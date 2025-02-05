import pyshark

def print_ethernet_header(packet):
    print("ETHERNET HEADER")
    eth = packet.eth
    destination_mac_address = eth.dst
    source_mac_address = eth.src
    ether_type = eth.type
    print("Destination MAC address: ".rjust(30) + destination_mac_address)
    print("Source MAC address: ".rjust(30)+source_mac_address)
    print("Ethertype: ".rjust(30)+ ether_type)


def print_IP_header(packet):
    print("IP HEADER")
    ip = packet.ip
    version = ip.version
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
    print("Header Length: ".rjust(30) + header_length)
    print("Total Length: ".rjust(30) + total_length)
    print("Identification: ".rjust(30) +identification)
    print("Flags: ".rjust(30) + flags)
    print("Fragment Offset: ".rjust(30) +fragment_offset)
    print("Time to Live: ".rjust(30) +ttl)
    print("Protocol: ".rjust(30) +protocol)
    print("Header Checksum: ".rjust(30) +header_checksum)
    print("Source IP Address: ".rjust(30) +source_ip_address)
    print("Destination IP Address: ".rjust(30) +destination_ip_address)


def print_encapsulated_packets(packet):
   if hasattr(packet, 'udp'):
       print(packet.udp)
   if hasattr(packet, 'tcp'):
       print(packet.tcp)
   if hasattr(packet, 'icmp'):
       print(packet.icmp)

def display_packets(filename, count):
    pcap = pyshark.FileCapture(filename)
    packet_counter = 0
    for packet in pcap:
       if packet_counter >= int(count):
           break
       if hasattr(packet,'eth'):
        print_ethernet_header(packet)
       if hasattr(packet,'ip'):
        print_IP_header(packet)
       print_encapsulated_packets(packet)
       packet_counter+=1

