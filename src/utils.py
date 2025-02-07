import argparse
import pyshark


def print_ethernet_header(packet) -> None:
    """
    Print the Ethernet header of a packet.

    :param packet: A PyShark packet object containing Ethernet layer data.
    :type packet: pyshark.packet.Packet
    :return: None
    """
    print("ETHERNET HEADER")
    eth = packet.eth
    destination_mac_address = eth.dst
    source_mac_address = eth.src
    ether_type = eth.type
    print("Destination MAC address: ".rjust(30) + destination_mac_address)
    print("Source MAC address: ".rjust(30) + source_mac_address)
    print("Ethertype: ".rjust(30) + ether_type)


def print_IP_header(packet) -> None:
    """
    Print the IP header of a packet.

    :param packet: A PyShark packet object containing IP layer data.
    :type packet: pyshark.packet.Packet
    :return: None
    """
    print("IP HEADER")
    ip = packet.ip
    version = ip.version
    type_of_service = ip.dsfield
    header_length = ip.hdr_len
    total_length = ip.len
    identification = ip.id
    flags = ip.flags
    fragment_offset = ip.frag_offset
    ttl = ip.ttl
    protocol = ip.proto
    header_checksum = ip.checksum
    source_ip_address = ip.src
    destination_ip_address = ip.dst
    print("Version: ".rjust(30) + version)
    print("Type of Service: ".rjust(30) + type_of_service)
    print("Header Length: ".rjust(30) + header_length)
    print("Total Length: ".rjust(30) + total_length)
    print("Identification: ".rjust(30) + identification)
    print("Flags: ".rjust(30) + flags)
    print("Fragment Offset: ".rjust(30) + fragment_offset)
    print("Time to Live: ".rjust(30) + ttl)
    print("Protocol: ".rjust(30) + protocol)
    print("Header Checksum: ".rjust(30) + header_checksum)
    print("Source IP Address: ".rjust(30) + source_ip_address)
    print("Destination IP Address: ".rjust(30) + destination_ip_address)


def print_encapsulated_packets(packet) -> None:
    """
    Print encapsulated packet information (e.g., UDP, TCP, ICMP).

    :param packet: A PyShark packet object that may contain UDP, TCP, or ICMP data.
    :type packet: pyshark.packet.Packet
    :return: None
    """
    if hasattr(packet, 'udp'):
        print(packet.udp)
    if hasattr(packet, 'tcp'):
        print(packet.tcp)
    if hasattr(packet, 'icmp'):
        print(packet.icmp)


def print_IPV6_header(packet) -> None:
    """
    Print the IPv6 header of a packet.

    :param packet: A PyShark packet object containing IPv6 layer data.
    :type packet: pyshark.packet.Packet
    :return: None
    """
    print("IPV6 HEADER")
    print(packet.ipv6)

def display_packets(pcap, count: str) -> None:
    """
    Display packets from a capture file up to the specified count.

    :param pcap: A PyShark FileCapture object representing the capture file.
    :type pcap: pyshark.packet.capture.FileCapture
    :param count: The number of packets to display.
    :type count: str
    :return: None
    """
    packet_counter = 0
    for packet in pcap:
        if packet_counter >= int(count):
            break
        if hasattr(packet, 'eth'):
            print_ethernet_header(packet)
        if hasattr(packet, 'ip'):
            print_IP_header(packet)
        if hasattr(packet, 'ipv6') :
            print_IPV6_header(packet)
        print_encapsulated_packets(packet)
        packet_counter += 1
    print(str(packet_counter)+ " packets displayed" )


def filter_and_display_packet(args: argparse.Namespace) -> None:
    """
    Filter and display packets based on command-line arguments.

    :param args: The parsed command-line arguments.
    :type args: argparse.Namespace
    :return: None
    """
    filename = args.filename
    count = 1000
    if args.count:
        count = args.count
    filters = []
    if args.count:
        count = args.count
    if args.packettype:
        filters.append(args.packettype)
    if args.host:
        filters.append(f"ip.addr == {args.host}")
    if args.port:
        filters.append(f"tcp.port == {args.port} || udp.port == {args.port}")
    if args.net:
        filters.append(f"ip.addr == {args.net}")
    if args.ip:
        if int(args.ip) == 4:
            filters.append("ip")
        elif int(args.ip) == 6:
            filters.append("ipv6")
    filter_str = " and ".join(filters)
    pcap = pyshark.FileCapture(filename, display_filter=filter_str)
    display_packets(pcap, count)
