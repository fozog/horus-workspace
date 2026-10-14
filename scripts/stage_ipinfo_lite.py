#!/usr/bin/python3
"""Build lookup tables for IPv4 and IPv6 from ipinfo_lite.csv.

Usage: stage_ipinfo_lite.py <ipinfo_lite.csv> <asn.csv> <geography.csv> <ipv4.bin> <ipv6.bin>
                            [--previous-asn ASN.csv] [--previous-geography GEOGRAPHY.csv]

Outputs:
  asn.csv        ASN registry shared by ipv4.bin and ipv6.bin (format below)
  geography.csv  geography registry (index,country,country_code,continent,continent_code)
                 shared by ipv4.bin and ipv6.bin
  ipv4.bin       IP4G: ASN + geography, /24 array with 256-leaf partitions (iplookup4.h)
  ipv6.bin       IPA6 version 3: ASN + geography trie to /64, split /64s as range lists
                 (format below, iplookup.h)

Rows without an ASN are reservations and are dropped (lookup returns "not found").
Touching IPv6 networks with the same (ASN, geography) are merged before building.

asn.csv (shared by both families)
---------------------------------
    index,asn,as_name,as_domain
    1,AS3,Massachusetts Institute of Technology,mit.edu
    2,,,                                   <- free slot (ASN deleted by an update)
    ...
Data line i (1-based, after the header) has index i. Fields are RFC 4180 CSV: a field
containing ',' or '"' is double-quoted with '"' doubled. Index 0 means "not found".

Indexes are stable so that a running system can be updated in place (see diff.py):
  - without --previous-asn, indexes are assigned from 1 in increasing ASN order;
  - with --previous-asn, every ASN keeps its index (name/domain are refreshed),
    ASNs that disappeared leave a free slot (empty asn field) that is never reused, and
    new ASNs are appended in increasing ASN order. This is exactly the numbering a system
    gets by applying the diff.py actions, so a restart from rebuilt files is consistent.
Free slots are never referenced by the tables. A rebuild without --previous-asn
compacts the numbering (only possible when restarting the consumer from the new files).
geography.csv follows stage_ipv4.py: with --previous-geography every entry keeps its index
(unused ones are kept as is), new ones are appended in sorted order.

Binary table ipv6.bin (IPA6 version 3)
--------------------------------------
A multibit trie down to /64 whose leaves are indexes into a table of (ASN, geography)
locations; a /64 that is not uniform holds a sorted list of ranges searched by bisection.
All integers are little-endian. Every section starts on a 64-byte boundary (zero padding).

    header (64 bytes):
        char     magic[4]       "IPA6"
        uint32   version        3
        uint32   n_asn          number of data lines in asn.csv (free slots included)
        uint32   n_geo          number of data lines in geography.csv
        uint32   n_realms       number of distinct L0 blocks
        uint32   n_levels       number of 8-bit levels below L0 (0..4)
        uint32   n_locations    number of distinct (asn_index, geography_index) pairs
        uint32   n_split        number of split /64s
        uint32   n_keys         number of key/value slots (lists + alignment padding)
        uint32   n_blocks[4]    number of 256-entry blocks in L1..L4 (unused ones are 0)
        12 bytes zero
    uint16   realm[65536]       top 16 bits -> L0 block number (0 = not found, else 1..n_realms);
                                top-16 values with identical content share one block
    location[n_locations + 1]   8 bytes each, the C location_t layout:
                                uint16 geography_index, 2 bytes zero, uint32 asn_index.
                                location[0] = (0, 0) = not found; others reference used
                                slots of asn.csv / geography.csv. Sorted by (asn, geo).
    uint32   L0[n_realms << 16]                     slot = /32
    uint32   L1[n_blocks[0]][256] .. L4[n_blocks[3]][256]   L4 slot = /64
    split64[n_split]            {uint32 first, uint32 count}: list = key/value[first .. first+count)
    uint64   key[n_keys]        low 64 bits of each range start, ascending within a list;
                                key[first] == 0; first is a multiple of 8 (one cache line)
    uint32   value[n_keys]      location index of the range starting at key[i] (0 = gap)

Trie entry (uint32):
    bit 31 set        pointer: (entry & 0x3fffffff) is a block in the next level,
                      indexed by the next address byte (never in L4)
    bit 30 set        split: (entry & 0x3fffffff) is a split64 index (only in L4)
    otherwise         location index (0 = not found)

Lookup (b = address bytes, network order):
    r = realm[b0<<8 | b1]; if !r: not found
    e = L0[(r-1)<<16 | b2<<8 | b3];                                       k = 4
    for (lvl = 1; e & PTR; lvl++, k++) e = L<lvl>[(e & 0x3fffffff)*256 + b[k]];
    if e & SPLIT: s = split64[e & 0x3fffffff]; lo = b8..b15 as uint64;
                  i = last index in [s.first, s.first + s.count) with key[i] <= lo;
                  e = value[i]
    location[e] is the result.
At most: realm, L0, L1..L4, then for a split /64: split64, ~log2(count) keys, value; location.

Location indexes are internal to ipv6.bin (renumbered by every build); only the ASN and
geography indexes they contain are stable. ASN boundaries stop at /48; geography
boundaries go down to /128 but only inside a few thousand /64s.
"""
import sys
import argparse
import csv
import struct
import random
import bisect
import ipaddress
from array import array

import stage_ipv4

VERSION = 3
HEADER = struct.Struct("<4s8I4I12x")  # 64 bytes, see docstring
HEADER_SIZE = 64
MAX_LEVELS = 4                         # L1..L4: the trie stops at /64
LOCATION = struct.Struct("<H2xI")      # C location_t: geography_index, padding, asn_index
PTR = 0x80000000
SPLIT = 0x40000000
SPLIT_SHIFT = 64                       # slots of this size (/64) are split, not subdivided
KEYS_PER_LINE = 8                      # each key list starts on a 64-byte cache line


def pad64(n):
    return -n % 64


class Family:
    def __init__(self, version):
        self.version = version
        self.bits = 32 if version == 4 else 128
        self.magic = b"IPA4" if version == 4 else b"IPA6"
        self.realm_bits = 0 if version == 4 else 16
        self.l0_bits = 24 if version == 4 else 16
        self.rows = []      # (start, end_excl, value)


def read_csv(path):
    """Return (fams, meta, v4_rows, geographies).

    fams[6].rows: (start, end_excl, asn, geo) for the IPv6 trie.
    v4_rows: sorted, non-overlapping (start, end_excl, asn, geo) for the IP4G table.
    """
    fams = {4: Family(4), 6: Family(6)}
    meta = {}
    geographies = {}
    v4_rows = []
    skipped = 0
    with open(path, 'r', encoding='utf-8', newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or len(row) < 8 or row[0] == 'network':
                continue
            asn = row[5].strip()
            if not asn:
                skipped += 1
                continue
            net = ipaddress.ip_network(row[0].strip(), strict=False)
            start = int(net.network_address)
            end = start + net.num_addresses
            num = int(asn[2:])
            geo = tuple(row[1:5])
            meta.setdefault(num, (row[6].strip(), row[7].strip()))
            geographies[geo] = geo
            if net.version == 4:
                v4_rows.append((start, end, num, geo))
            else:
                fams[6].rows.append((start, end, num, geo))
    v4_rows.sort()
    for prev, cur in zip(v4_rows, v4_rows[1:]):
        if cur[0] < prev[1]:
            raise ValueError(f"IPv4: overlapping networks at {ipaddress.ip_address(cur[0])}")
    print(f"Dropped {skipped} rows without ASN; {len(meta)} distinct ASNs, "
          f"{len(geographies)} geographies")
    return fams, meta, v4_rows, geographies


def merge(fam):
    """Sort, check for overlaps and merge touching ranges with the same value."""
    fam.rows.sort()
    merged = []
    for a, e, v in fam.rows:
        if merged and a < merged[-1][1]:
            raise ValueError(f"IPv{fam.version}: overlapping networks at {ipaddress.ip_address(a)}")
        if merged and merged[-1][1] == a and merged[-1][2] == v:
            merged[-1][1] = e
        else:
            merged.append([a, e, v])
    fam.ranges = [tuple(r) for r in merged]
    fam.rows = None


class Builder:
    """Build the trie from fam.ranges, whose values are the leaf entries (location indexes)."""

    def __init__(self, fam):
        self.fam = fam
        self.levels = []        # levels[i] = list of 256-entry array blocks (level i+1)
        self.dedup = []
        self.splits = []        # (first, count) per split /64
        self.split_dedup = {}
        self.keys = array('Q')
        self.values = array('I')

    def split(self, base, ranges):
        """Register the range list of a non-uniform /64 starting at base; return its entry."""
        items = []              # (offset of the low 64 bits, location), first offset 0
        pos = base
        for a, e, v in ranges:
            if a > pos:
                items.append((pos - base, 0))
            if not items or items[-1][1] != v:
                items.append((a - base, v))
            pos = e
        if pos < base + (1 << SPLIT_SHIFT):
            items.append((pos - base, 0))
        if items[0][0] != 0:
            items.insert(0, (0, 0))
        key = tuple(items)
        if key not in self.split_dedup:
            while len(self.keys) % KEYS_PER_LINE:
                self.keys.append(0)
                self.values.append(0)
            self.split_dedup[key] = len(self.splits)
            self.splits.append((len(self.keys), len(items)))
            for k, v in items:
                self.keys.append(k)
                self.values.append(v)
        return SPLIT | self.split_dedup[key]

    def block(self, level, base, shift, nslots, ranges):
        """Build an array of nslots entries; slot i covers [base + i<<shift, base + (i+1)<<shift)."""
        slots = array('I', bytes(4 * nslots))
        unit = 1 << shift
        partial = {}
        for a, e, v in ranges:
            idx = v
            s = (a - base) >> shift
            t = (e - base) >> shift
            if (a - base) & (unit - 1):
                partial.setdefault(s, []).append((a, min(e, base + (s + 1) * unit), v))
                s += 1
            if t > s:
                slots[s:t] = array('I', [idx]) * (t - s)
            if (e - base) & (unit - 1) and t >= s:
                partial.setdefault(t, []).append((max(a, base + t * unit), e, v))

        for i, sub in sorted(partial.items()):
            if shift == SPLIT_SHIFT:
                slots[i] = self.split(base + i * unit, sub)
                continue
            child = self.block(level + 1, base + i * unit, shift - 8, 256, sub)
            while len(self.levels) <= level:
                self.levels.append([])
                self.dedup.append({})
            key = child.tobytes()
            store = self.dedup[level]
            if key not in store:
                store[key] = len(self.levels[level])
                self.levels[level].append(child)
            slots[i] = PTR | store[key]
        return slots

    def build(self):
        fam = self.fam
        top_shift = fam.bits - fam.realm_bits          # bits below the realm
        l0_shift = top_shift - fam.l0_bits             # bits below an L0 slot

        by_realm = {}
        for a, e, v in fam.ranges:
            while a < e:
                r = a >> top_shift
                cut = min(e, (r + 1) << top_shift)
                by_realm.setdefault(r, []).append((a, cut, v))
                a = cut
        self.realm_of = {}      # top bits -> 1-based L0 block number
        self.l0 = []
        seen = {}
        for r in sorted(by_realm):
            blk = self.block(0, r << top_shift, l0_shift, 1 << fam.l0_bits, by_realm[r])
            key = blk.tobytes()
            if key not in seen:
                self.l0.append(blk)
                seen[key] = len(self.l0)
            self.realm_of[r] = seen[key]
        if len(self.l0) > 0xffff:
            raise ValueError("too many L0 blocks")
        if len(self.levels) > MAX_LEVELS:
            raise ValueError("too many levels")
        for lvl in self.levels:
            if len(lvl) >= SPLIT:
                raise ValueError("too many blocks")
        if len(self.splits) >= SPLIT or len(self.keys) >= 1 << 32:
            raise ValueError("too many split /64s")

    def write(self, path, n_asn, n_geo, locations):
        """locations[i - 1] = (asn_index, geo_index) of location index i."""
        fam = self.fam
        counts = [len(lvl) for lvl in self.levels]
        if len(locations) >= SPLIT:
            raise ValueError("too many locations")
        header = HEADER.pack(fam.magic, VERSION, n_asn, n_geo, len(self.l0), len(counts),
                             len(locations), len(self.splits), len(self.keys),
                             *(counts + [0] * (MAX_LEVELS - len(counts))))
        assert len(header) == HEADER_SIZE

        def put(out, arr):
            if sys.byteorder != 'little':
                arr = array(arr.typecode, arr)
                arr.byteswap()
            arr.tofile(out)

        with open(path, 'wb') as out:
            out.write(header)
            realm_map = array('H', bytes(2 << fam.realm_bits))
            for r, n in self.realm_of.items():
                realm_map[r] = n
            put(out, realm_map)
            loc = LOCATION.pack(0, 0) + b"".join(LOCATION.pack(g, a) for a, g in locations)
            out.write(loc + bytes(pad64(len(loc))))
            for blocks in [self.l0] + self.levels:
                for b in blocks:
                    put(out, b)
            split = b"".join(struct.pack("<2I", f, c) for f, c in self.splits)
            out.write(split + bytes(pad64(len(split))))
            put(out, self.keys)
            put(out, self.values)
            size = out.tell()
        realms = f"top-16 values={len(self.realm_of)}, L0 blocks={len(self.l0)}, "
        print(f"IPv{fam.version}: {len(fam.ranges)} ranges, {len(locations)} locations, {realms}"
              f"blocks per level={counts}, {len(self.splits)} split /64s with "
              f"{len(self.keys)} key slots, {size / 2**20:.1f} MB -> {path}")


class Table:
    """Reference reader for the binary format (independent of the builder)."""

    def __init__(self, path):
        with open(path, 'rb') as f:
            data = f.read()
        magic, ver, self.n_asn, self.n_geo, nr, nl, nloc, nsplit, nkeys, *counts = \
            HEADER.unpack_from(data, 0)
        assert magic == b"IPA6" and ver == VERSION and nl <= MAX_LEVELS
        counts = counts[:nl]
        off = HEADER_SIZE

        def take(code, n, align=False):
            nonlocal off
            a = array(code)
            a.frombytes(data[off:off + a.itemsize * n])
            if sys.byteorder != 'little':
                a.byteswap()
            off += a.itemsize * n
            if align:
                off += pad64(off)
            return a
        self.realm = take('H', 65536)
        self.locations = [(asn, geo) for geo, asn in
                          LOCATION.iter_unpack(data[off:off + LOCATION.size * (nloc + 1)])]
        assert self.locations[0] == (0, 0)
        off += LOCATION.size * (nloc + 1)
        off += pad64(off)
        self.levels = [take('I', nr << 16)] + [take('I', c * 256) for c in counts]
        split = take('I', 2 * nsplit, align=True)
        self.splits = list(zip(split[0::2], split[1::2]))
        self.keys = take('Q', nkeys)
        self.values = take('I', nkeys)
        assert off == len(data)

    def lookup(self, addr):
        """Return (asn_index, geo_index) for an integer address ((0, 0) = not found)."""
        b = addr.to_bytes(16, 'big')
        r = self.realm[b[0] << 8 | b[1]]
        if not r:
            return 0, 0
        e = self.levels[0][(r - 1) << 16 | b[2] << 8 | b[3]]
        lvl, k = 1, 4
        while e & PTR:
            e = self.levels[lvl][(e & ~PTR) * 256 + b[k]]
            lvl += 1
            k += 1
        if e & SPLIT:
            assert lvl == MAX_LEVELS + 1       # only /64-level entries are split
            first, count = self.splits[e & ~SPLIT]
            i = bisect.bisect_right(self.keys, addr & (2**64 - 1), first, first + count) - 1
            e = self.values[i]
        return self.locations[e]


def verify(path, fam, locations, samples=200000):
    """Check ipv6.bin against fam.ranges (values = location indexes into locations)."""
    t = Table(path)
    ranges = fam.ranges
    starts = [a for a, _, _ in ranges]

    def expected(addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i >= 0 and addr < ranges[i][1]:
            return locations[ranges[i][2] - 1]
        return 0, 0

    errors = 0
    top = 1 << fam.bits
    for a, e, v in ranges:
        for addr in (a, e - 1, a + (e - a) // 2, a - 1, e):
            if 0 <= addr < top and t.lookup(addr) != expected(addr):
                errors += 1
    rnd = random.Random(1)
    for _ in range(samples if ranges else 0):
        a, e, _ = rnd.choice(ranges)
        for addr in (rnd.randrange(a, e), rnd.getrandbits(fam.bits)):
            if t.lookup(addr) != expected(addr):
                errors += 1
    print(f"IPv{fam.version} verification: " + ("OK" if not errors else f"FAILED, {errors} mismatches"))
    return errors == 0


def read_asn_slots(path):
    """Read an asn.csv; return a list where slot i-1 holds the ASN number of index i or None."""
    slots = []
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if int(row[0]) != len(slots) + 1:
                raise ValueError(f"{path}: index {row[0]} on data line {len(slots) + 1}")
            slots.append(int(row[1][2:]) if row[1] else None)
    present = [a for a in slots if a is not None]
    if len(present) != len(set(present)):
        raise ValueError(f"{path}: duplicate ASN")
    return slots


def assign_indexes(meta, base_path=None):
    """Return (slots, asn_index): slots[i-1] = ASN number of index i, or None for a free slot."""
    slots = read_asn_slots(base_path) if base_path else []
    slots = [a if a in meta else None for a in slots]
    known = {a for a in slots if a is not None}
    slots += sorted(a for a in meta if a not in known)
    asn_index = {a: i + 1 for i, a in enumerate(slots) if a is not None}
    return slots, asn_index


def verify4(path, rows, asn_index, geo_index, samples=200000):
    """Check ipv4.bin (IP4G) against the source rows, independently of the writer."""
    with open(path, 'rb') as f:
        data = f.read()
    magic, _, hsize, _, _, _, nsub, sub_off = stage_ipv4.HEADER.unpack_from(data)[:8]
    assert magic == b"IP4G" and nsub == stage_ipv4.SUBNETS
    words = array('Q', data[hsize:])
    if sys.byteorder != 'little':
        words.byteswap()
    base = (sub_off - hsize) // 8

    def lookup(addr):
        w = words[base + (addr >> 8)]
        if w & 1:
            w = words[((w & ~1) - hsize) // 8 + (addr & 255)]
        return w >> 32, (w >> 16) & 0xffff

    starts = [r[0] for r in rows]

    def expected(addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i >= 0 and addr < rows[i][1]:
            return asn_index[rows[i][2]], geo_index[rows[i][3]]
        return 0, 0

    errors = 0
    for a, e, _, _ in rows:
        for addr in (a, e - 1, a + (e - a) // 2, a - 1, e):
            if 0 <= addr < 1 << 32 and lookup(addr) != expected(addr):
                errors += 1
    rnd = random.Random(1)
    for _ in range(samples if rows else 0):
        a, e, _, _ = rnd.choice(rows)
        for addr in (rnd.randrange(a, e), rnd.getrandbits(32)):
            if lookup(addr) != expected(addr):
                errors += 1
    print("IPv4 verification: " + ("OK" if not errors else f"FAILED, {errors} mismatches"))
    return errors == 0


def main(src, asn_csv, geo_csv, v4_bin, v6_bin, base_asn_csv=None, base_geo_csv=None):
    print(f"Reading {src}...")
    fams, meta, v4_rows, geographies = read_csv(src)
    slots, asn_index = assign_indexes(meta, base_asn_csv)
    n_asn = len(slots)

    with open(asn_csv, 'w', encoding='utf-8', newline='') as out:
        w = csv.writer(out, lineterminator='\n')
        w.writerow(['index', 'asn', 'as_name', 'as_domain'])
        for i, a in enumerate(slots, 1):
            w.writerow([i, f"AS{a}", meta[a][0], meta[a][1]] if a is not None else [i, '', '', ''])
    free = n_asn - len(meta)
    print(f"{len(meta)} ASNs in {n_asn} slots ({free} free) -> {asn_csv}")

    geos, geo_index = stage_ipv4.make_indexes(
        geographies, stage_ipv4.registry(base_geo_csv, stage_ipv4.GEO_FIELDS), tuple)
    stage_ipv4.write_registry(geo_csv, stage_ipv4.GEO_FIELDS, geos)
    print(f"{len(geos)} geography slots -> {geo_csv}")

    stage_ipv4.write_table(v4_bin, v4_rows, asn_index, geo_index, n_asn, len(geos))
    ok = verify4(v4_bin, v4_rows, asn_index, geo_index)

    fam = fams[6]
    locations = sorted({(asn_index[a], geo_index[g]) for _, _, a, g in fam.rows})
    location_index = {loc: i for i, loc in enumerate(locations, 1)}
    fam.rows = [(s, e, location_index[(asn_index[a], geo_index[g])]) for s, e, a, g in fam.rows]
    merge(fam)
    b = Builder(fam)
    b.build()
    b.write(v6_bin, n_asn, len(geos), locations)
    ok &= verify(v6_bin, fam, locations)
    return ok


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Build asn.csv, geography.csv, ipv4.bin (IP4G) "
                                     "and ipv6.bin (IPA6 v3) from ipinfo_lite.csv")
    for name in ("ipinfo_lite_csv", "asn_csv", "geography_csv", "ipv4_bin", "ipv6_bin"):
        parser.add_argument(name)
    parser.add_argument("--previous-asn")
    parser.add_argument("--previous-geography")
    args = parser.parse_args()
    sys.exit(0 if main(args.ipinfo_lite_csv, args.asn_csv, args.geography_csv, args.ipv4_bin,
                       args.ipv6_bin, args.previous_asn, args.previous_geography) else 1)
