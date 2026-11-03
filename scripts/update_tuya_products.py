#!/usr/bin/python3
"""Builds the Tuya product identification table from the tuya-local project.

Downloads https://github.com/make-all/tuya-local (one tarball request) and scans
custom_components/tuya_local/devices/*.yaml. Every `products[].id` is a Tuya
productKey as broadcast in discovery PDUs (see apps/tuya.c); each one yields a row

    product_id|vendor|model

with vendor = products[].manufacturer and model = "<top-level name> <products[].model>".
The same product id may legitimately appear in several rows (same or different
vendor/model). Output: run/data/tuya_products.csv ('|' separated, header line),
later loaded into a hashtable keyed by product id.
"""

import io
import re
import sys
import tarfile
import urllib.request
from pathlib import Path

TARBALL_URL = "https://codeload.github.com/make-all/tuya-local/tar.gz/refs/heads/main"
DEVICES_DIR = "custom_components/tuya_local/devices/"
OUTPUT_CSV = Path(__file__).resolve().parent.parent / "run" / "data" / "tuya_products.csv"

try:
  import yaml
except ImportError:
  sys.exit("PyYAML is required (apt install python3-yaml)")


def sanitize(text):
  """One CSV field: no separator, no newlines, collapsed whitespace."""
  return re.sub(r"\s+", " ", str(text).replace("|", "/")).strip()


def download_tarball(url):
  print(f"Downloading {url}...")
  request = urllib.request.Request(url, headers={"User-Agent": "horus-tuya-products/1.0"})
  with urllib.request.urlopen(request) as response:
    return response.read()


def iter_device_yamls(tarball):
  with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
    for member in archive:
      if DEVICES_DIR not in member.name or not member.name.endswith(".yaml"):
        continue
      handle = archive.extractfile(member)
      if handle is None:
        continue
      yield member.name.rsplit("/", 1)[-1], handle.read()


def device_rows(file_name, content):
  try:
    device = yaml.safe_load(content)
  except yaml.YAMLError as error:
    print(f"WARNING: cannot parse {file_name}: {error}", file=sys.stderr)
    return
  if not isinstance(device, dict):
    return
  name = device.get("name", "")
  products = device.get("products")
  if not isinstance(products, list):
    return
  for product in products:
    if not isinstance(product, dict):
      continue
    product_id = product.get("id")
    if not product_id:
      continue
    vendor = sanitize(product.get("manufacturer", ""))
    model = sanitize(" ".join(part for part in (str(name), str(product.get("model", ""))) if part))
    yield f"{sanitize(product_id)}|{vendor}|{model}"


def main():
  output = Path(sys.argv[1]) if len(sys.argv) > 1 else OUTPUT_CSV
  rows = set()
  files = 0
  for file_name, content in iter_device_yamls(download_tarball(TARBALL_URL)):
    files += 1
    rows.update(device_rows(file_name, content))
  if not rows:
    sys.exit("No product entries found: tuya-local layout may have changed")
  output.parent.mkdir(parents=True, exist_ok=True)
  with open(output, "w", encoding="utf-8") as csv:
    csv.write("product_id|vendor|model\n")
    csv.write("\n".join(sorted(rows)))
    csv.write("\n")
  print(f"Wrote {len(rows)} products from {files} device files to {output}")


if __name__ == "__main__":
  main()
