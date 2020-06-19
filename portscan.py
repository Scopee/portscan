#!/usr/bin/env python3
import argparse
from arch.scanner import Scanner


def main():
    parser = argparse.ArgumentParser(description="PortScan")
    parser.add_argument('host', action='store', help="target host")
    parser.add_argument('-t', '--tcp', action='store_true',
                        help='Scan TCP ports')
    parser.add_argument('-u', '--udp', action='store_true',
                        help='Scan UDP ports')
    parser.add_argument('-p', '--ports', nargs=2, type=int,
                        default=[1, 65535], help='scanning ports range')
    parser.add_argument('-w', '--workers', type=int, default=10,
                        help='Number of threads')
    args = parser.parse_args()
    host = args.host
    ports = args.ports
    tcp = args.tcp
    udp = args.udp
    scanner = Scanner(host, range(ports[0], ports[1] + 1), tcp, udp,
                      workers=args.workers)
    try:
        scanner.start()
    except KeyboardInterrupt:
        exit(-1)


if __name__ == '__main__':
    main()
