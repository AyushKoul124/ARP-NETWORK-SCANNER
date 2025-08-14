#!/usr/bin/env python3
"""Simple ARP network scanner"""
import argparse
import sys
try:
    from scapy.all import ARP, Ether, srp, conf
except Exception as e:
    print("Scapy is required. Install with: pip install scapy", file=sys.stderr)
    raise

def scan(target, timeout=2, iface=None):
    conf.verb = 0
    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    answered, _ = srp(packet, timeout=timeout, iface=iface, inter=0.1)
    hosts = []
    for _, received in answered:
        hosts.append({"ip": received.psrc, "mac": received.hwsrc})
    hosts.sort(key=lambda h: tuple(int(x) for x in h["ip"].split(".")))
    return hosts

def print_table(rows):
    if not rows:
        print("No hosts found.")
        return
    headers = ["IP Address", "MAC Address"]
    widths = [len(h) for h in headers]
    for r in rows:
        widths[0] = max(widths[0], len(r["ip"]))
        widths[1] = max(widths[1], len(r["mac"]))
    fmt = f"{{:<{widths[0]}}}  {{:<{widths[1]}}}"
    print(fmt.format(*headers))
    print("-" * (sum(widths) + 2))
    for r in rows:
        print(fmt.format(r["ip"], r["mac"]))

def main():
    parser = argparse.ArgumentParser(description="Simple ARP network scanner (Layer-2).")
    parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR, e.g., 192.168.1.0/24")
    parser.add_argument("--iface", help="Network interface to use (optional)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout per probe in seconds")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of table")
    args = parser.parse_args()

    try:
        hosts = scan(args.target, timeout=args.timeout, iface=args.iface)
    except PermissionError:
        print("Permission error. Try running as root or with sudo.", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"OS/network error: {e}", file=sys.stderr)
        sys.exit(2)

    if args.json:
        import json
        print(json.dumps(hosts, indent=2))
    else:
        print_table(hosts)

if __name__ == "__main__":
    sys.exit(main())
