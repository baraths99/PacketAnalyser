import argparse
import utils
from typing import Optional


def main() -> None:
    """
    Main entry point of the packet sniffer application.

    Parses command-line arguments, including the filename, count, packet type,
    host, port, IP, and net. Calls the `filter_and_display_packet` function
    from the utils module to process the arguments and display filtered packets.

    :return: None
    """
    parser = argparse.ArgumentParser(prog="Packet Sniffer")

    parser.add_argument('-r', '--filename', type=str, help="The name of the pcap file to analyze.")
    parser.add_argument('-c', '--count', type=int, help="Number of packets to capture or display.")
    parser.add_argument('-t', '--packettype', type=str, help="Filter based on packet type (e.g., 'TCP', 'UDP').")
    parser.add_argument('-host', '--host', type=str, help="Filter packets by host address.")
    parser.add_argument('-p', '--port', type=str, help="Filter packets by port (e.g., '80').")
    parser.add_argument('-ip', '--ip', type=str, help="Filter packets by specific IP address.")
    parser.add_argument('-n', '--net', type=str, help="Filter packets by network range (e.g., '192.168.1.0/24').")

    args = parser.parse_args()

    utils.filter_and_display_packet(args)


if __name__ == '__main__':
    main()
