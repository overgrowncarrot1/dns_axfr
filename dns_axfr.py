#!/usr/bin/env python3
import argparse
import subprocess
import json
import re
import sys
import textwrap

def parse_args():
    parser = argparse.ArgumentParser(
        prog="dns_axfr.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
        DNS Zone Transfer & Recon Utility
        ---------------------------------
        Performs DNS zone transfers (AXFR), automatically detects nameservers if needed,
        extracts CNAME records, and optionally screenshots discovered domains using gowitness.

        Examples:
          # Simple AXFR attempt
          python3 dns_axfr.py -d example.com

          # Automatically find NS records and try each
          python3 dns_axfr.py -d example.com --try-ns

          # Save results to JSON
          python3 dns_axfr.py -d example.com -o full.json --cnames-only cnames.json

          # Screenshot discovered domains (HTTP/HTTPS)
          python3 dns_axfr.py -d example.com --try-ns \\
              --gowitness --schemes "http,https" \\
              --gowitness-args "--timeout 20 --write-screenshots screenshots"

          # Screenshot discovered domains (HTTPS) and change User-Agent
          python3 dns_axfr.py -d zonetransfer.me --try-ns \
              -o zonetransfer_full.json \
              --cnames-only zonetransfer_cnames.json \
              --gowitness \
              --schemes "https" \
              --gowitness-args "--timeout 20 --write-screenshots --write-jsonl-file --chrome-user-agent 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36' --write-none"

        Notes:
          - If AXFR fails for the given domain, the tool can auto-fetch NS records and retry.
          - Works great for automation pipelines or OSINT.
        """)
    )

    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Domain to attempt zone transfer against (e.g., zonetransfer.me)"
    )
    parser.add_argument(
        "--try-ns",
        action="store_true",
        help="Automatically find nameservers and try AXFR for each"
    )
    parser.add_argument(
        "-o", "--output",
        metavar="OUTPUT_FILE",
        default="axfr_full.json",
        help="Save all AXFR records to JSON file (default: axfr_full.json)"
    )
    parser.add_argument(
        "--cnames-only",
        metavar="CNAME_OUTPUT_FILE",
        help="Save only CNAME records to a separate JSON file"
    )
    parser.add_argument(
        "--gowitness",
        action="store_true",
        help="Run gowitness screenshots for discovered CNAME targets"
    )
    parser.add_argument(
        "--schemes",
        default="http,https",
        help="Comma-separated URL schemes for gowitness (default: http,https)"
    )
    parser.add_argument(
        "--gowitness-args",
        metavar="ARGS",
        help="Additional arguments to pass to gowitness (e.g., '--timeout 20 --write-screenshots outdir')"
    )

    return parser.parse_args()

def run_cmd(cmd):
    """Run a shell command and return stdout as text."""
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        return result.stdout.strip()
    except Exception as e:
        print(f"[-] Error running command: {' '.join(cmd)} -> {e}")
        return ""

def resolve_ns(domain):
    """Resolve name servers for the domain."""
    print(f"[+] Resolving NS records for {domain}...")
    output = run_cmd(["dig", domain, "NS", "+short"])
    ns_records = [line.strip(".") for line in output.splitlines() if line.strip()]
    if ns_records:
        print(f"[+] Found NS: {', '.join(ns_records)}")
    else:
        print("[-] No NS records found.")
    return ns_records

def axfr_zone(domain, ns_server):
    """Attempt a zone transfer using dig."""
    print(f"[+] Trying AXFR against {ns_server} for zone {domain}...")
    cmd = ["dig", f"@{ns_server}", domain, "AXFR"]
    return run_cmd(cmd)

def parse_records(dig_output):
    """Parse dig AXFR output into structured records."""
    records = []
    for line in dig_output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        record = {
            "name": parts[0],
            "ttl": parts[1],
            "class": parts[2],
            "type": parts[3],
            "value": " ".join(parts[4:])
        }
        records.append(record)
    return records

def save_json(filename, data):
    """Save dictionary or list to JSON file."""
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Saved {len(data)} records to {filename}")

def run_gowitness(cname_records, schemes, gowitness_args):
    """Run gowitness for each CNAME target."""
    for cname_record in cname_records:
        target = cname_record["value"].rstrip(".")
        for scheme in schemes.split(","):
            url = f"{scheme}://{target}"
            cmd = ["gowitness", "scan", "single", "-u", url]
            if gowitness_args:
                cmd.extend(gowitness_args.split())
            print(f"[+] Running Gowitness: {' '.join(cmd)}")
            subprocess.run(cmd)

def main():
    args = parse_args()

    ns_servers = []
    if args.try_ns:
        ns_servers = resolve_ns(args.domain)
    else:
        ns_servers = [args.domain]

    all_records = []
    for ns in ns_servers:
        result = axfr_zone(args.domain, ns)
        if "Transfer failed" in result or not result:
            print(f"[-] AXFR failed against {ns}")
            continue
        all_records = parse_records(result)
        break  # stop after first successful AXFR

    if not all_records:
        print("[-] No AXFR succeeded against any of the tried servers.")
        sys.exit(1)

    save_json(args.output, all_records)

    if args.cnames_only:
        cname_records = [r for r in all_records if r["type"].upper() == "CNAME"]
        save_json(args.cnames_only, cname_records)
        if args.gowitness and cname_records:
            run_gowitness(cname_records, args.schemes, args.gowitness_args)

if __name__ == "__main__":
    main()
