#!/usr/bin/env python3

# Description: Find subnet gateways using ICMP.

import sys
import signal
import argparse
import scapy.all as scapy

def interrupt_handler(signal, frame):
    print("\n[!] Ctrl+C Detected!")
    sys.exit(0)

def icmp_scan(ip):
    ans = scapy.sr1(scapy.IP(dst=ip)/scapy.ICMP(), timeout=1, verbose=0)

    if ans:
        return True
    else:
        return False

def validate_range(range_part):
    return 0 <= range_part <= 255

def generate_ips(ip_range):
    ip_ranges = ip_range.split(".")
    if len(ip_ranges) != 4:
        return []

    ranges = []
    for part in ip_ranges:
        if "-" in part:
            range_part = part.split("-")
            if len(range_part) != 2:
                return []

            min_range = int(range_part[0])
            max_range = int(range_part[1])

            if not validate_range(min_range) or not validate_range(max_range):
                return []

            ranges.append(range(min_range, max_range + 1))
        else:
            ranges.append([int(part)])

    ips = []
    for range1 in ranges[0]:
        for range2 in ranges[1]:
            for range3 in ranges[2]:
                for range4 in ranges[3]:
                    ips.append(f"{range1}.{range2}.{range3}.{range4}")

    return ips, max_range

def save_to_file(output, filename):
    with open(filename, "w") as file:
        file.write(output)

def main():
    parser = argparse.ArgumentParser(description="ICMP Scanner")
    parser.add_argument("subnets_and_ranges", nargs="+", help="List of subnets or ranges to scan")
    parser.add_argument("-o", "--output", help="Name of the TXT file output")
    parser.add_argument("-v","--verbose", action="store_true", help="Print the current IPs that are being scanned")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, interrupt_handler)

    if args.output and not args.output.endswith(".txt"):
        args.output += ".txt"

    txt_output = ""

    try:
        for subnet_or_range in args.subnets_and_ranges:
            if "-" in subnet_or_range:
                ips_to_scan, last_number_to_compare = generate_ips(subnet_or_range)
                if not ips_to_scan:
                    print(f"Invalid IP range: {subnet_or_range}")
                    continue
                else:
                    try:
                        for ip in ips_to_scan:
                            ip_parts = ip.split(".")
                            last_octet_range = range(int(ip_parts[3]), 256)
                            for last_octet in last_octet_range:
                                current_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{last_octet}"
                                devices_found = icmp_scan(current_ip)
                                if args.verbose:
                                    print(f"Currently scanning: {current_ip}")
                                if devices_found is True:
                                    print(f"Found a subnet: {current_ip}\n")
                                    if args.output:
                                        txt_output += f"{current_ip}\n"
                                    if last_number_to_compare <= 255:
                                        break
                                    else:
                                        last_number_to_compare = int(ip_parts[2]) + 1
                                        ip_parts[3] = "1"
                                        if last_number_to_compare <= 255:
                                            ip_parts[2] = str(last_number_to_compare)
                                        else:
                                            last_number_to_compare = int(ip_parts[1]) + 1
                                            ip_parts[2] = "1"
                                            if last_number_to_compare <= 255:
                                                ip_parts[1] = str(last_number_to_compare)
                                            else:
                                                ip_parts[1] = "1"
                                                ip_parts[0] = str(int(ip_parts[0]) + 1)
                                    continue
                                break
                    except KeyboardInterrupt:
                        print("\n[!] Exiting")
                        raise
    except SystemExit:
        pass
    finally:
        print("[+] Saving the file")
        if args.output:
            save_to_file(txt_output, args.output)

if __name__ == "__main__":
    main()