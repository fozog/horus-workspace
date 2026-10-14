#!/usr/bin/python3
"""Build IPv4-only ASN + geography tables; see iplookup4.h for the C format.

Usage: python3 stage_ipv4.py INPUT.csv OUTPUT_DIR
       [--previous-asn ASN.csv] [--previous-geography geography.csv]

Outputs: asn.csv, geography.csv, ipv4.bin. Existing output files are replaced.
Country/continent fields are preserved verbatim and form the geography key.
Rows without an ASN are dropped, IPv6 rows are ignored, overlaps are rejected.
Uniformity is tested on BOTH indexes, including unknown addresses (0, 0).
Previous registries retain unused metadata slots; new keys append, never renumber.
For a single asn.csv/geography.csv shared with IPv6, use stage_ipinfo_lite.py, which
reuses write_table() from this module.
"""
import argparse
from array import array
import csv
import ipaddress
from pathlib import Path
import struct
import sys

ASN_FIELDS = ["asn", "as_name", "as_domain"]
GEO_FIELDS = ["country", "country_code", "continent", "continent_code"]
INPUT_FIELDS = ["network", *GEO_FIELDS, *ASN_FIELDS]
SUBNETS = 1 << 24
HEADER = struct.Struct("<4s5I5Q")
PARTITION_OFFSET = HEADER.size + SUBNETS * 8


def registry(path, fields):
    records = []
    if path:
        with open(path, newline="", encoding="utf-8") as source:
            reader = csv.reader(source, strict=True)
            if next(reader, None) != ["index", *fields]:
                raise ValueError(f"{path}: unexpected registry header")
            for line, row in enumerate(reader, 2):
                if len(row) != len(fields) + 1 or int(row[0]) != len(records) + 1:
                    raise ValueError(f"{path}:{line}: invalid registry row/index")
                records.append(tuple(row[1:]))
    return records


def make_indexes(current, previous, key, asn_tombstones=False):
    records = list(previous)
    indexes = {}
    for index, record in enumerate(records, 1):
        if asn_tombstones and not record[0]:
            continue
        value = key(record)
        if value in indexes:
            raise ValueError(f"duplicate registry key: {value}")
        indexes[value] = index
    for value in sorted(current):
        if value not in indexes:
            records.append(current[value])
            indexes[value] = len(records)
        else:
            records[indexes[value] - 1] = current[value]
    return records, indexes


def read_input(path):
    rows, asns, geographies = [], {}, {}
    dropped = ignored = 0
    with open(path, newline="", encoding="utf-8") as source:
        reader = csv.reader(source, strict=True)
        if next(reader, None) != INPUT_FIELDS:
            raise ValueError(f"{path}: unexpected input header")
        for line, row in enumerate(reader, 2):
            if len(row) != 8:
                raise ValueError(f"{path}:{line}: expected 8 fields")
            net = ipaddress.ip_network(row[0], strict=True)
            if net.version != 4:
                ignored += 1
                continue
            if not row[5]:
                dropped += 1
                continue
            asn = row[5]
            if not asn.startswith("AS") or not asn[2:].isdigit() or not 0 < int(asn[2:]) < 1 << 32:
                raise ValueError(f"{path}:{line}: invalid ASN {asn!r}")
            number = int(asn[2:])
            metadata = (f"AS{number}", row[6], row[7])
            if number in asns and asns[number] != metadata:
                raise ValueError(f"{path}:{line}: conflicting metadata for AS{number}")
            geo = tuple(row[1:5])
            asns[number] = metadata
            geographies[geo] = geo
            start = int(net.network_address)
            rows.append((start, start + net.num_addresses, number, geo))
    rows.sort()
    end = 0
    for start, stop, _, _ in rows:
        if start < end:
            raise ValueError(f"{path}: overlapping assigned networks at {ipaddress.IPv4Address(start)}")
        end = stop
    print(f"Read {len(rows)} assigned IPv4 rows; dropped {dropped} reservations; ignored {ignored} IPv6 rows")
    return rows, asns, geographies


def write_registry(path, fields, records):
    with open(path, "w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["index", *fields])
        writer.writerows((i, *record) for i, record in enumerate(records, 1))


def write_words(output, words):
    if sys.byteorder == "little":
        words.tofile(output)
    else:
        copy = array("Q", words)
        copy.byteswap()
        copy.tofile(output)


def build(source, output_dir, previous_asn=None, previous_geography=None):
    rows, current_asns, current_geo = read_input(source)
    asns, asn_index = make_indexes(
        current_asns, registry(previous_asn, ASN_FIELDS), lambda r: int(r[0][2:]),
        asn_tombstones=True)
    geos, geo_index = make_indexes(
        current_geo, registry(previous_geography, GEO_FIELDS), tuple)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_registry(output_dir / "asn.csv", ASN_FIELDS, asns)
    write_registry(output_dir / "geography.csv", GEO_FIELDS, geos)
    write_table(output_dir / "ipv4.bin", rows, asn_index, geo_index, len(asns), len(geos))


def write_table(path, rows, asn_index, geo_index, n_asn, n_geo):
    """Write an IP4G file. rows: sorted, non-overlapping (start, end_excl, asn_number, geo)."""
    if n_asn > 0xffffffff or n_geo > 0xffff:
        raise ValueError("metadata registry exceeds uint32 ASN or uint16 geography capacity")
    subnets = array("Q", [0]) * SUBNETS
    if subnets.itemsize != 8:
        raise RuntimeError("this Python platform does not provide 64-bit array('Q')")
    partial = {}
    for start, end, asn, geo in rows:
        leaf = (asn_index[asn] << 32) | (geo_index[geo] << 16)
        # No address expansion for complete /24s.
        first, last = (start + 255) >> 8, end >> 8
        if first < last:
            subnets[first:last] = array("Q", [leaf]) * (last - first)
        for block in {start >> 8, (end - 1) >> 8}:
            lo, hi = max(start, block << 8), min(end, (block + 1) << 8)
            if hi - lo < 256:
                partition = partial.setdefault(block, array("Q", [0]) * 256)
                partition[lo & 255:(hi - (block << 8))] = array("Q", [leaf]) * (hi - lo)
    partitions = []
    for block, partition in sorted(partial.items()):
        if all(word == partition[0] for word in partition):
            subnets[block] = partition[0]
        else:
            subnets[block] = (PARTITION_OFFSET + len(partitions) * 2048) | 1
            partitions.append(partition)
    size = PARTITION_OFFSET + len(partitions) * 2048
    with open(path, "wb") as output:
        output.write(HEADER.pack(b"IP4G", 1, HEADER.size, n_asn, n_geo,
                                 len(partitions), SUBNETS, HEADER.size,
                                 PARTITION_OFFSET, size, 0))
        write_words(output, subnets)
        for partition in partitions:
            write_words(output, partition)
    print(f"{n_asn} ASN slots, {n_geo} geography slots, {len(partitions)} partitions; "
          f"IPv4 table {size / 2**20:.2f} MiB -> {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("output_dir")
    parser.add_argument("--previous-asn")
    parser.add_argument("--previous-geography")
    args = parser.parse_args()
    try:
        build(args.input, args.output_dir, args.previous_asn, args.previous_geography)
    except (OSError, ValueError, csv.Error) as error:
        parser.exit(1, f"stage_ipv4: {error}\n")
