#!/usr/bin/env python3
"""
refresh-cloud-ranges.py -- regenerate kmap-cloud-ranges.csv from the live
published cloud-provider IP-range feeds.

This is an OUT-OF-BAND maintenance tool.  The kmap scanner never runs it; it
only reads the bundled CSV at scan time.  Run it periodically to refresh the
bundled snapshot:

    python tools/refresh-cloud-ranges.py -o kmap-cloud-ranges.csv

Output format (one IPv4 CIDR per line, sorted by network address ascending):

    cidr,provider,region,service

Each provider is fetched independently with a timeout; a feed that fails to
download is reported on stderr and skipped (the others still produce output).
IPv6 prefixes are dropped (the matcher is IPv4-only for now).
"""

import argparse
import csv
import ipaddress
import json
import sys
import urllib.request

DEFAULT_TIMEOUT = 30  # seconds, per the project's "bound every network call" rule


def fetch(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "kmap-cloud-refresh"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_json(url, timeout):
    return json.loads(fetch(url, timeout).decode("utf-8", "replace"))


# Each provider function yields (cidr, provider, region, service) tuples.
def aws(timeout):
    data = fetch_json("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout)
    for p in data.get("prefixes", []):
        cidr = p.get("ip_prefix")
        if cidr:
            yield cidr, "aws", p.get("region", "") or "", p.get("service", "") or ""


def gcp(timeout):
    data = fetch_json("https://www.gstatic.com/ipranges/cloud.json", timeout)
    for p in data.get("prefixes", []):
        cidr = p.get("ipv4Prefix")
        if cidr:
            yield cidr, "gcp", p.get("scope", "") or "", p.get("service", "") or ""


def azure(timeout):
    # Azure publishes a weekly JSON whose download URL rotates; the operator can
    # pass --azure-url to point at the current ServiceTags file. Skipped if unset.
    return iter(())


def azure_from(url, timeout):
    data = fetch_json(url, timeout)
    for v in data.get("values", []):
        props = v.get("properties", {})
        region = props.get("region", "") or ""
        service = props.get("systemService", "") or ""
        for cidr in props.get("addressPrefixes", []):
            yield cidr, "azure", region, service


def cloudflare(timeout):
    text = fetch("https://www.cloudflare.com/ips-v4", timeout).decode("utf-8", "replace")
    for line in text.splitlines():
        line = line.strip()
        if line:
            yield line, "cloudflare", "", ""


def digitalocean(timeout):
    text = fetch("https://www.digitalocean.com/geo/google.csv", timeout).decode("utf-8", "replace")
    for row in csv.reader(text.splitlines()):
        # columns: range,country,region,city,postal
        if row and "/" in row[0]:
            region = row[2] if len(row) > 2 else ""
            yield row[0], "digitalocean", region, ""


def oracle(timeout):
    data = fetch_json("https://docs.oracle.com/iaas/tools/public_ip_ranges.json", timeout)
    for region in data.get("regions", []):
        rname = region.get("region", "") or ""
        for c in region.get("cidrs", []):
            cidr = c.get("cidr")
            if cidr:
                # '|' not ',': the bundled CSV must stay strictly comma-free so
                # cloud_map.cc's fast naive comma-split (no RFC-4180 de-quoting)
                # parses region/service correctly.
                yield cidr, "oracle", rname, "|".join(c.get("tags", []))


PROVIDERS = {
    "aws": aws,
    "gcp": gcp,
    "cloudflare": cloudflare,
    "digitalocean": digitalocean,
    "oracle": oracle,
}


def is_ipv4_cidr(cidr):
    try:
        return isinstance(ipaddress.ip_network(cidr, strict=False),
                          ipaddress.IPv4Network)
    except ValueError:
        return False


def sort_key(row):
    return int(ipaddress.ip_network(row[0], strict=False).network_address)


def clean_field(s):
    # The bundled CSV is parsed by cloud_map.cc with a naive comma split (no
    # RFC-4180 quote handling), so no emitted field may contain a comma, double
    # quote, or newline -- otherwise csv.writer would quote it and the C++ side
    # would mis-parse.  region/service are free-form from the feeds; sanitize.
    return (s or "").replace(",", " ").replace('"', " ") \
                    .replace("\n", " ").replace("\r", " ").strip()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-o", "--output", default="kmap-cloud-ranges.csv")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--azure-url", default="",
                    help="current Azure ServiceTags JSON URL (rotates weekly)")
    ap.add_argument("--only", default="",
                    help="comma-separated subset of providers to fetch")
    args = ap.parse_args()

    wanted = set(p.strip() for p in args.only.split(",") if p.strip()) or set(PROVIDERS)
    rows, seen = [], set()

    def collect(name, gen):
        n = 0
        try:
            for cidr, prov, region, service in gen:
                if not is_ipv4_cidr(cidr):
                    continue
                key = (cidr, prov)
                if key in seen:
                    continue
                seen.add(key)
                rows.append([cidr, prov, clean_field(region), clean_field(service)])
                n += 1
        except Exception as e:  # one provider failing must not abort the rest
            sys.stderr.write(f"WARN: {name} feed failed: {e}\n")
        sys.stderr.write(f"  {name}: {n} ranges\n")

    for name in sorted(wanted):
        if name in PROVIDERS:
            collect(name, PROVIDERS[name](args.timeout))
    if args.azure_url and ("azure" in wanted or not args.only):
        collect("azure", azure_from(args.azure_url, args.timeout))
    elif not args.only:
        sys.stderr.write("  azure: skipped (pass --azure-url <ServiceTags JSON>)\n")

    rows.sort(key=sort_key)

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        f.write("# kmap-cloud-ranges.csv -- generated by tools/refresh-cloud-ranges.py\n")
        f.write("# cidr,provider,region,service\n")
        w = csv.writer(f, lineterminator="\n")
        for r in rows:
            w.writerow(r)

    sys.stderr.write(f"wrote {len(rows)} ranges -> {args.output}\n")


if __name__ == "__main__":
    main()
