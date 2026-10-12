#!/usr/bin/env python3
"""Identify the Linux driver and matching DPDK PMDs for a network interface."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def read_text(path):
    try:
        return Path(path).read_text().strip()
    except (OSError, ValueError):
        return None


def get_interface_info(ifname):
    net = Path("/sys/class/net") / ifname
    if not net.exists():
        raise ValueError(f"Network interface {ifname!r} does not exist")

    device = (net / "device").resolve()
    driver_link = net / "device/driver"

    linux_driver = (
        Path(os.path.realpath(driver_link)).name
        if driver_link.exists() else None
    )

    # PCI devices have a vendor/device pair in sysfs.
    vendor = read_text(device / "vendor")
    device_id = read_text(device / "device")

    info = {
        "interface": ifname,
        "device_path": str(device),
        "linux_driver": linux_driver or "unknown",
        "bus_type": "PCI" if vendor and device_id else "non-PCI",
        "pci_bdf": device.name if vendor and device_id else None,
        "vendor": vendor.removeprefix("0x").lower() if vendor else None,
        "device": device_id.removeprefix("0x").lower()
        if device_id else None,
        "subsystem_vendor": None,
        "subsystem_device": None,
    }

    if vendor and device_id:
        for key, filename in (
            ("subsystem_vendor", "subsystem_vendor"),
            ("subsystem_device", "subsystem_device"),
        ):
            value = read_text(device / filename)
            info[key] = value.removeprefix("0x").lower() if value else None

    return info


def get_pmd_info(tool, binary):
    result = subprocess.run(
        [tool, "-p", binary],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"dpdk-pmdinfo.py failed (exit {result.returncode}):\n"
            f"{result.stderr.strip()}"
        )

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "dpdk-pmdinfo.py did not produce JSON. "
            "This script expects a modern DPDK version (22.11 or later). "
            "Check the tool version and its output format."
        ) from exc

    if not isinstance(data, list):
        raise RuntimeError("Unexpected PMD metadata format: expected a JSON list")

    return data


def id_matches(pmd_id, interface_id):
    if interface_id is None or pmd_id is None:
        return False
    return str(pmd_id).lower().removeprefix("0x") == interface_id.lower()


def find_matching_pmds(pmds, info):
    matches = []

    for pmd in pmds:
        for pci_id in pmd.get("pci_ids", []):
            if not (
                id_matches(pci_id.get("vendor"), info["vendor"])
                and id_matches(pci_id.get("device"), info["device"])
            ):
                continue

            # If the PMD specifies a real subsystem ID, require it to match.
            # "ffff" is commonly used as a wildcard.
            subsystem_ok = True
            for key in ("subsystem_vendor", "subsystem_device"):
                supported = pci_id.get(key)
                actual = info.get(key)
                if (
                    supported is not None
                    and str(supported).lower().removeprefix("0x") != "ffff"
                    and not id_matches(supported, actual)
                ):
                    subsystem_ok = False
                    break

            if subsystem_ok:
                matches.append({
                    "name": pmd.get("name", "unknown"),
                    "kmod": pmd.get("kmod"),
                    "pci_id": pci_id,
                })
                break

    return sorted(matches, key=lambda item: item["name"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("interface", help="Linux interface, e.g. enp3s0")
    parser.add_argument(
        "--pmdinfo",
        default="dpdk-pmdinfo.py",
        help="Path to dpdk-pmdinfo.py",
    )
    parser.add_argument(
        "--binary",
        default="/usr/bin/dpdk-testpmd",
        help="DPDK executable whose linked PMDs should be inspected",
    )
    args = parser.parse_args()

    try:
        info = get_interface_info(args.interface)

        print(f"Interface       : {info['interface']}")
        print(f"Linux driver    : {info['linux_driver']}")
        print(f"Bus type        : {info['bus_type']}")
        print(f"Device path     : {info['device_path']}")

        if info["bus_type"] != "PCI":
            print("PMD match       : PCI matching is not applicable.")
            print("                 A bus-specific check is needed.")
            return 2

        print(f"PCI address     : {info['pci_bdf']}")
        print(f"Vendor:Device   : {info['vendor']}:{info['device']}")
        print(
            "Subsystem IDs   : "
            f"{info['subsystem_vendor'] or '?'}:"
            f"{info['subsystem_device'] or '?'}"
        )

        pmds = get_pmd_info(args.pmdinfo, args.binary)
        matches = find_matching_pmds(pmds, info)

        print("\nMatching DPDK PMDs:")
        if not matches:
            print("  None found in the inspected DPDK binary/plugins.")
            # the following line is used by a enable_dpdk script
            print("  You may want to use PMD name: af_xdp")
            print(f"  --vdev=net_af_xdp0,iface={info['interface']},queue_count=$QUEUES")
            return 1

        for match in matches:
            print(f"  PMD name       : {match['name']}")
            print(f"  Required kmod   : {match['kmod'] or 'unspecified'}")

        return 0

    except (ValueError, RuntimeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
