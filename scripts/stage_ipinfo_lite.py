#!/usr/bin/python3
"""Build ASN lookup tables for IPv4 and IPv6 from ipinfo_lite.csv.

Usage: stage_ipinfo_lite.py <ipinfo_lite.csv> <asn.csv> <ipv4.bin> <ipv6.bin> [<previous asn.csv>]

Rows without an ASN are reservations and are dropped (lookup returns "not found").
The ASN depends on nothing but the address, so networks of the same ASN that touch are
merged before building (countries are ignored).

asn.csv (shared by both families)
---------------------------------
    index,asn,as_name,as_domain
    1,AS3,Massachusetts Institute of Technology,mit.edu
    2,,,                                   <- free slot (ASN deleted by an update)
    ...
Data line i (1-based, after the header) has index i. Fields are RFC 4180 CSV: a field
containing ',' or '"' is double-quoted with '"' doubled. Index 0 means "not found".

Indexes are stable so that a running system can be updated in place (see diff.py):
  - without <previous asn.csv>, indexes are assigned from 1 in increasing ASN order;
  - with <previous asn.csv>, every ASN keeps its index (name/domain are refreshed),
    ASNs that disappeared leave a free slot (empty asn field) that is never reused, and
    new ASNs are appended in increasing ASN order. This is exactly the numbering a system
    gets by applying the diff.py actions, so a restart from rebuilt files is consistent.
Free slots are never referenced by the tables. A rebuild without <previous asn.csv>
compacts the numbering (only possible when restarting the consumer from the new files).

Binary tables (ipv4.bin, ipv6.bin)
----------------------------------
Both are a multibit trie; all integers are little-endian uint32.

    header (128 bytes):
        char     magic[4]       "IPA4" or "IPA6"
        uint32   version        1
        uint32   n_asn          number of data lines in asn.csv (free slots included)
        uint32   l0_bits        24 (IPv4) or 16 (IPv6)
        uint32   n_realms       IPv4: 1, IPv6: number of distinct L0 blocks
        uint32   n_levels       number of 8-bit levels below L0 (may be 0)
        uint32   n_blocks[26]   number of 256-entry blocks in each level (unused ones are 0)
    IPv6 only:
        uint16   realm[65536]   top 16 bits -> L0 block number (0 = not found, else 1..n_realms);
                                top-16 values with identical content share one block
    uint32   L0[n_realms << l0_bits]
    uint32   L1[n_blocks[0]][256]
    uint32   L2[n_blocks[1]][256]
    ...

Each entry is either an ASN index into asn.csv (0 = not found), or, if bit 31 is set,
a pointer: (entry & 0x7fffffff) is a block number in the next level, indexed by the
next address byte.

Lookup (b = address bytes, network order):
    IPv4: e = L0[b0<<16 | b1<<8 | b2];                                    k = 3
    IPv6: r = realm[b0<<8 | b1]; if !r: not found
          e = L0[(r-1)<<16 | b2<<8 | b3];                                 k = 4
    for (lvl = 1; e & 0x80000000; lvl++, k++) e = L<lvl>[(e & 0x7fffffff)*256 + b[k]];
    e is the ASN index.

With the current data IPv4 has no level below L0 (no /24 holds more than one ASN) and
IPv6 has two (no ASN boundary is finer than /48).
"""
import sys
import csv
import struct
import random
import bisect
import ipaddress
from array import array

VERSION = 1
HEADER_SIZE = 128
MAX_LEVELS = 26
PTR = 0x80000000


class Family:
    def __init__(self, version):
        self.version = version
        self.bits = 32 if version == 4 else 128
        self.magic = b"IPA4" if version == 4 else b"IPA6"
        self.realm_bits = 0 if version == 4 else 16
        self.l0_bits = 24 if version == 4 else 16
        self.rows = []      # (start, end_excl, asn_number)


def read_csv(path):
    fams = {4: Family(4), 6: Family(6)}
    meta = {}
    skipped = 0
    with open(path, 'r', encoding='utf-8') as f:
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
            num = int(asn[2:])
            meta.setdefault(num, (row[6].strip(), row[7].strip()))
            fams[net.version].rows.append((start, start + net.num_addresses, num))
    print(f"Dropped {skipped} rows without ASN; {len(meta)} distinct ASNs")
    return fams, meta


def merge(fam):
    """Sort, check for overlaps and merge touching ranges of the same ASN."""
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
    def __init__(self, fam, asn_index):
        self.fam = fam
        self.asn_index = asn_index
        self.levels = []        # levels[i] = list of 256-entry array blocks (level i+1)
        self.dedup = []

    def block(self, level, base, shift, nslots, ranges):
        """Build an array of nslots entries; slot i covers [base + i<<shift, base + (i+1)<<shift)."""
        slots = array('I', bytes(4 * nslots))
        unit = 1 << shift
        partial = {}
        for a, e, v in ranges:
            idx = self.asn_index[v]
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
            if len(lvl) >= PTR:
                raise ValueError("too many blocks")

    def write(self, path, n_asn):
        fam = self.fam
        counts = [len(lvl) for lvl in self.levels]
        header = struct.pack("<4s5I", fam.magic, VERSION, n_asn, fam.l0_bits,
                             len(self.l0), len(counts))
        header += struct.pack(f"<{MAX_LEVELS}I", *(counts + [0] * (MAX_LEVELS - len(counts))))
        assert len(header) == HEADER_SIZE
        with open(path, 'wb') as out:
            out.write(header)
            if fam.realm_bits:
                realm_map = array('H', bytes(2 << fam.realm_bits))
                for r, n in self.realm_of.items():
                    realm_map[r] = n
                if sys.byteorder != 'little':
                    realm_map.byteswap()
                realm_map.tofile(out)
            for blocks in [self.l0] + self.levels:
                for b in blocks:
                    if sys.byteorder != 'little':
                        b = array('I', b)
                        b.byteswap()
                    b.tofile(out)
        size = HEADER_SIZE + (2 << fam.realm_bits if fam.realm_bits else 0) \
            + 4 * (len(self.l0) << fam.l0_bits) + 4 * 256 * sum(counts)
        realms = f"top-16 values={len(self.realm_of)}, L0 blocks={len(self.l0)}, " if fam.realm_bits else ""
        print(f"IPv{fam.version}: {len(fam.ranges)} ranges, {realms}"
              f"blocks per level={counts}, {size / 2**20:.1f} MB -> {path}")


class Table:
    """Reference reader for the binary format (independent of the builder)."""

    def __init__(self, path):
        with open(path, 'rb') as f:
            data = f.read()
        magic, ver, self.n_asn, self.l0_bits, nr, nl = struct.unpack_from("<4s5I", data, 0)
        counts = struct.unpack_from(f"<{MAX_LEVELS}I", data, 24)[:nl]
        assert magic in (b"IPA4", b"IPA6") and ver == VERSION
        self.v6 = magic == b"IPA6"
        off = HEADER_SIZE
        if self.v6:
            self.realm = array('H', data[off:off + 131072])
            if sys.byteorder != 'little':
                self.realm.byteswap()
            off += 131072

        def take(n):
            nonlocal off
            a = array('I', data[off:off + 4 * n])
            if sys.byteorder != 'little':
                a.byteswap()
            off += 4 * n
            return a
        self.levels = [take(nr << self.l0_bits)] + [take(c * 256) for c in counts]
        assert off == len(data)

    def lookup(self, addr):
        """Return the ASN index for an integer address (0 = not found)."""
        if self.v6:
            b = addr.to_bytes(16, 'big')
            r = self.realm[b[0] << 8 | b[1]]
            if not r:
                return 0
            e = self.levels[0][(r - 1) << 16 | b[2] << 8 | b[3]]
            k = 4
        else:
            b = addr.to_bytes(4, 'big')
            e = self.levels[0][b[0] << 16 | b[1] << 8 | b[2]]
            k = 3
        lvl = 1
        while e & PTR:
            e = self.levels[lvl][(e & ~PTR) * 256 + b[k]]
            lvl += 1
            k += 1
        return e


def verify(path, fam, asn_index, samples=200000):
    t = Table(path)
    ranges = fam.ranges
    starts = [a for a, _, _ in ranges]

    def expected(addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i >= 0 and addr < ranges[i][1]:
            return asn_index[ranges[i][2]]
        return 0

    errors = 0
    top = 1 << fam.bits
    for a, e, v in ranges:
        for addr in (a, e - 1, a + (e - a) // 2, a - 1, e):
            if 0 <= addr < top and t.lookup(addr) != expected(addr):
                errors += 1
    rnd = random.Random(1)
    for _ in range(samples):
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


def main(src, asn_csv, v4_bin, v6_bin, base_asn_csv=None):
    print(f"Reading {src}...")
    fams, meta = read_csv(src)
    slots, asn_index = assign_indexes(meta, base_asn_csv)
    n_asn = len(slots)

    with open(asn_csv, 'w', encoding='utf-8', newline='') as out:
        w = csv.writer(out, lineterminator='\n')
        w.writerow(['index', 'asn', 'as_name', 'as_domain'])
        for i, a in enumerate(slots, 1):
            w.writerow([i, f"AS{a}", meta[a][0], meta[a][1]] if a is not None else [i, '', '', ''])
    free = n_asn - len(meta)
    print(f"{len(meta)} ASNs in {n_asn} slots ({free} free) -> {asn_csv}")

    ok = True
    for fam, path in ((fams[4], v4_bin), (fams[6], v6_bin)):
        merge(fam)
        b = Builder(fam, asn_index)
        b.build()
        b.write(path, n_asn)
        ok &= verify(path, fam, asn_index)
    return ok


if __name__ == '__main__':
    if len(sys.argv) not in (5, 6):
        print(f"Usage: python3 {sys.argv[0]} <ipinfo_lite.csv> <asn.csv> <ipv4.bin> <ipv6.bin> "
              f"[<previous asn.csv>]")
        sys.exit(1)
    sys.exit(0 if main(*sys.argv[1:]) else 1)
