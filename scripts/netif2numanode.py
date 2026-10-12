#!/usr/bin/env python3
"""Find a network interface's NUMA node, PCI ancestry, CPUs and sockets."""

import argparse
import json
import re
from pathlib import Path


SYS_NET = Path("/sys/class/net")
SYS_CPU = Path("/sys/devices/system/cpu")
SYS_NODE = Path("/sys/devices/system/node")

PCI_RE = re.compile(
    r"^(?:[0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}:"
    r"[0-9a-fA-F]{2}\.[0-7]$"
)


def read(path):
    try:
        return path.read_text().strip()
    except (OSError, PermissionError):
        return None


def parse_cpu_list(value):
    """Parse Linux cpulist syntax, e.g. '0-3,8,10-11'."""
    cpus = set()
    if not value:
        return cpus

    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = map(int, part.split("-", 1))
            cpus.update(range(lo, hi + 1))
        else:
            cpus.add(int(part))
    return cpus


def format_cpu_list(cpus):
    """Compress a set of CPU IDs to Linux cpulist syntax."""
    cpus = sorted(cpus)
    if not cpus:
        return ""

    ranges = []
    start = prev = cpus[0]

    for cpu in cpus[1:]:
        if cpu == prev + 1:
            prev = cpu
            continue
        ranges.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = cpu

    ranges.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(ranges)


def cpu_topology(cpus):
    """Map CPUs to socket/package and core IDs."""
    result = []
    for cpu in sorted(cpus):
        base = SYS_CPU / f"cpu{cpu}"
        if not base.exists():
            continue

        package = read(base / "topology/physical_package_id")
        core = read(base / "topology/core_id")
        online = read(base / "online")

        result.append({
            "cpu": cpu,
            "socket": int(package) if package is not None else None,
            "core": int(core) if core is not None else None,
            "online": online != "0" if online is not None else True,
        })
    return result


def node_cpus(node):
    return parse_cpu_list(read(SYS_NODE / f"node{node}/cpulist"))


def inspect_interface(ifname):
    net = SYS_NET / ifname
    if not net.exists():
        raise ValueError(f"Interface {ifname!r} does not exist")

    device_link = net / "device"
    if not device_link.exists():
        return {
            "interface": ifname,
            "device_path": None,
            "bus_type": "virtual/no device link",
            "numa_node": None,
            "numa_source": None,
            "pci_ancestry": [],
            "local_cpus": [],
            "sockets": [],
            "status": "No device symlink; interface may be virtual.",
        }

    device = device_link.resolve()
    info = {
        "interface": ifname,
        "device_path": str(device),
        "bus_type": "unknown",
        "numa_node": None,
        "numa_source": None,
        "pci_ancestry": [],
        "local_cpus": [],
        "sockets": [],
        "status": None,
    }

    # Walk from the network device toward /sys/devices.
    # Keep the closest valid NUMA node and the first useful CPU list.
    current = device
    first_cpu_list = None
    cpu_list_source = None
    numa_candidates = []

    while current != current.parent:
        name = current.name

        if PCI_RE.match(name):
            bdf = name if name.count(":") == 2 else None
            if bdf is None:
                # Normalize domain-less BDF if encountered.
                bdf = "0000:" + name

            entry = {
                "bdf": bdf,
                "sysfs_path": str(current),
                "vendor": read(current / "vendor"),
                "device": read(current / "device"),
                "class": read(current / "class"),
                "numa_node": None,
                "local_cpus": None,
            }

            raw_node = read(current / "numa_node")
            if raw_node is not None:
                try:
                    node = int(raw_node)
                    if node >= 0:
                        entry["numa_node"] = node
                        numa_candidates.append(
                            (node, str(current / "numa_node"))
                        )
                except ValueError:
                    pass

            raw_cpus = read(current / "local_cpulist")
            if raw_cpus:
                cpus = parse_cpu_list(raw_cpus)
                entry["local_cpus"] = format_cpu_list(cpus)
                if cpus and first_cpu_list is None:
                    first_cpu_list = cpus
                    cpu_list_source = str(current / "local_cpulist")

            info["pci_ancestry"].append(entry)

        # Some platforms expose NUMA data on non-PCI ancestors too.
        raw_node = read(current / "numa_node")
        if raw_node is not None:
            try:
                node = int(raw_node)
                if node >= 0:
                    numa_candidates.append(
                        (node, str(current / "numa_node"))
                    )
            except ValueError:
                pass

        raw_cpus = read(current / "local_cpulist")
        if raw_cpus and first_cpu_list is None:
            cpus = parse_cpu_list(raw_cpus)
            if cpus:
                first_cpu_list = cpus
                cpu_list_source = str(current / "local_cpulist")

        current = current.parent

    if info["pci_ancestry"]:
        info["bus_type"] = "PCI"
    else:
        info["bus_type"] = "non-PCI or no PCI ancestor"

    # Prefer the nearest valid NUMA association found during traversal.
    if numa_candidates:
        info["numa_node"] = numa_candidates[0][0]
        info["numa_source"] = numa_candidates[0][1]
    elif first_cpu_list:
        # Infer NUMA only if all CPUs in the local list belong to one node.
        memberships = {}
        for node_path in SYS_NODE.glob("node[0-9]*"):
            try:
                node_id = int(node_path.name[4:])
            except ValueError:
                continue
            for cpu in node_cpus(node_id):
                memberships.setdefault(cpu, set()).add(node_id)

        inferred_nodes = {
            node
            for cpu in first_cpu_list
            for node in memberships.get(cpu, set())
        }
        if len(inferred_nodes) == 1:
            info["numa_node"] = next(iter(inferred_nodes))
            info["numa_source"] = (
                f"inferred from local CPU list at {cpu_list_source}"
            )

    # Resolve CPUs using the selected NUMA node, otherwise a local CPU list.
    if info["numa_node"] is not None:
        cpus = node_cpus(info["numa_node"])
        info["cpu_source"] = (
            f"{SYS_NODE}/node{info['numa_node']}/cpulist"
        )
    elif first_cpu_list:
        cpus = first_cpu_list
        info["cpu_source"] = cpu_list_source
    else:
        cpus = set()
        info["cpu_source"] = None

    topology = cpu_topology(cpus)
    info["local_cpus"] = topology
    info["sockets"] = sorted({
        item["socket"] for item in topology
        if item["socket"] is not None
    })

    if info["numa_node"] is not None:
        info["status"] = "NUMA node found"
    elif topology:
        info["status"] = (
            "NUMA node unknown; CPUs/sockets found from locality information"
        )
    else:
        info["status"] = (
            "NUMA association unavailable in sysfs; no reliable fallback found"
        )

    return info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("interface", help="e.g. enp3s0 or eth0")
    parser.add_argument("--json", action="store_true",
                        help="print machine-readable JSON")
    args = parser.parse_args()

    try:
        result = inspect_interface(args.interface)
    except ValueError as exc:
        parser.error(str(exc))

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"Interface   : {result['interface']}")
    print(f"Device path : {result['device_path']}")
    print(f"Bus type    : {result['bus_type']}")
    print(f"NUMA node   : {result['numa_node']}")
    print(f"NUMA source : {result['numa_source']}")
    print(f"CPU source  : {result.get('cpu_source')}")
    print(f"Sockets     : {result['sockets']}")
    print(f"Status      : {result['status']}")

    if result["pci_ancestry"]:
        print("\nPCI ancestry (interface toward root):")
        for dev in result["pci_ancestry"]:
            print(
                f"  {dev['bdf']} "
                f"vendor={dev['vendor']} device={dev['device']} "
                f"NUMA={dev['numa_node']} CPUs={dev['local_cpus']}"
            )

    if result["local_cpus"]:
        print("\nCPUs on selected NUMA node/locality:")
        print("  CPU  SOCKET  CORE  ONLINE")
        for cpu in result["local_cpus"]:
            print(
                f"  {cpu['cpu']:>3}  "
                f"{str(cpu['socket']):>6}  "
                f"{str(cpu['core']):>4}  "
                f"{cpu['online']}"
            )


if __name__ == "__main__":
    main()
