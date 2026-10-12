#!/usr/bin/python3
import csv
import re
import urllib.request

ETH_URL = "https://standards-oui.ieee.org/ethertype/eth.txt"
OUTPUT_CSV = "ethertypes.csv"


def download_registry(url):
  print(f"Downloading registry from {url}...")
  headers = {
      "User-Agent": (
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML,"
          " like Gecko) Chrome/120.0.0.0 Safari/537.36"
      )
  }
  req = urllib.request.Request(url, headers=headers)
  with urllib.request.urlopen(req) as response:
    return response.read().decode("utf-8", errors="ignore").replace("\r", "")


def parse_eth_file(content):
  lines = content.splitlines()

  # Step 1: Parse the header line to find exact column boundaries
  org_col_idx = 35  # Default fallbacks
  proto_col_idx = 138

  for line in lines:
    if "EtherType" in line and "PROTOCOL" in line:
      if "ORGANIZATION" in line:
        org_col_idx = line.find("ORGANIZATION")
      elif "Organization" in line:
        org_col_idx = line.find("Organization")
      proto_col_idx = line.find("PROTOCOL")
      break

  records = []
  i = 0
  n = len(lines)
  entry_pattern = re.compile(r"^([0-9A-Fa-f]{4})\b")

  while i < n:
    line = lines[i]

    # Look for the start of a new entry (4 hex digits at the beginning)
    match = entry_pattern.match(line)
    if match:
      eth_code = match.group(1).upper()
      entry_lines = [line]

      # Aggregate subsequent lines until the next entry is reached. Blank/
      # whitespace-only lines are kept since address blocks can contain them
      # in the middle of a single record.
      i += 1
      while i < n:
        next_line = lines[i]
        if entry_pattern.match(next_line):
          break
        entry_lines.append(next_line)
        i += 1

      # Process the gathered block using the column boundaries
      records.append(build_record(eth_code, entry_lines, org_col_idx, proto_col_idx))
    else:
      i += 1

  return records


def build_record(eth_code, lines, org_col, proto_col):
  vendor_block_lines = []
  protocol_block_lines = []

  for line in lines:
    # Slice Vendor/Organization column, stopping before the Protocol column
    if len(line) > org_col:
      end_idx = proto_col if len(line) >= proto_col else len(line)
      vendor_text = line[org_col:end_idx].strip()
      if vendor_text:
        vendor_block_lines.append(vendor_text)

    # Slice Protocol column
    if len(line) > proto_col:
      proto_text = line[proto_col:].strip()
      if proto_text:
        protocol_block_lines.append(proto_text)

  return {
      "ethertype": f"0x{eth_code}",
      "vendor": "\\n".join(vendor_block_lines),
      "protocol": "\\n".join(protocol_block_lines),
  }


def save_csv(records, filename):
  print(f"Writing {len(records)} entries to {filename}...")
  with open(filename, mode="w", newline="", encoding="utf-8") as f:
    writer = csv.writer(
        f, delimiter="|", quoting=csv.QUOTE_MINIMAL, lineterminator="\n"
    )
    writer.writerow(
        ["ethertype", "multi-line vendor", "multi-line protocol information"]
    )

    for r in records:
      writer.writerow([r["ethertype"], r["vendor"], r["protocol"]])
  print("Export complete!")


if __name__ == "__main__":
  raw_data = download_registry(ETH_URL)
  parsed_records = parse_eth_file(raw_data)
  save_csv(parsed_records, OUTPUT_CSV)
