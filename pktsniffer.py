
import argparse

import utils


def main() -> None:
    parser = argparse.ArgumentParser(prog="Packet Sniffer")

    parser.add_argument('-r', '--filename')
    parser.add_argument('-c', '--count')
    parser.add_argument('-t', '--packettype')
    parser.add_argument('-host', '--host')
    parser.add_argument('-p', '--port')
    parser.add_argument('-ip', '--ip')
    parser.add_argument('-n', '--net')

    args = parser.parse_args()
    print(args.filename,args.count)
    utils.filter_and_display_packet(args)


if __name__ == '__main__':
    main()