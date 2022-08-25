##### FICHERO CON FUNCIONES PARA IMPRIMIR LA INFORMACIÓN #####

import textwrap # Para formatear la información en multilinea

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '



def print_Ethernet(ethernet_packet, i):
    print('Packet number: ' + str(i))
    print('Ethernet Frame:')
    print('Destination: {}, Source: {}, Protocol: {}\n'.format(ethernet_packet.dest_mac, ethernet_packet.src_mac, ethernet_packet.type))


def print_IPv4(ipv4_packet):
    print(TAB_1 + 'IPv4 Packet:')
    print(TAB_2 + 'Version {}, Header Length: {}, TTL: {}'.format(ipv4_packet.version, ipv4_packet.header_length, ipv4_packet.ttl))
    print(TAB_2 + 'Protocol {}, Source: {}, Destination: {}'.format(ipv4_packet.protocol, ipv4_packet.src, ipv4_packet.dest))


def print_ICMP(icmp_packet):
    print(TAB_1 + 'ICMP Packet:')
    print(TAB_2 + 'Type {}, Code: {}, Checksum: {}'.format(icmp_packet.icmp_type, icmp_packet.code, icmp_packet.checksum))
    print(TAB_2 + 'Data:')
    print(format_multi_line(DATA_TAB_3, icmp_packet.data))


def print_TCP(tcp_segment):
    print(TAB_1 + 'TCP Segment:')
    print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp_segment.src_port, tcp_segment.dest_port))
    print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp_segment.sequence, tcp_segment.acknowledgment))
    print(TAB_2 + 'Flags:')
    print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(tcp_segment.flag_urg, tcp_segment.flag_ack, tcp_segment.flag_psh, tcp_segment.flag_rst, tcp_segment.flag_syn, tcp_segment.flag_fin))
    print(TAB_2 + 'Actived flags: {}'.format(tcp_segment.actived_flags))
    print(TAB_2 + 'Data:')
    print(format_multi_line(DATA_TAB_3, tcp_segment.data))


def print_UDP(udp_segment):
    print(TAB_1 + 'UDP Segment:')
    print(TAB_2 + 'Source Port: {}, Destination port: {}, Length: {}'. format(udp_segment.src_port, udp_segment.dest_port, udp_segment.size))
    print(TAB_2 + 'Data:')
    print(format_multi_line(DATA_TAB_3, udp_segment.data))


def print_else_IPv4(ipv4_packet):
    print(TAB_1 + 'Other Type:')
    print(TAB_2 + 'Proto Type: ' + str(ipv4_packet.protocol))
    print(TAB_2 + 'Data:')
    print(format_multi_line(DATA_TAB_3, ipv4_packet.data))


def print_ARP(arp_packet):
    print(TAB_1 + 'ARP Packet:')
    print(TAB_2 + 'Hardware type: {}, Protocol type: {}, Hardware size: {}, Protocol size: {}'.format(arp_packet.hardware, arp_packet.protocol, arp_packet.hardware_size, arp_packet.protocol_size))
    print(TAB_2 + 'Opcode: {}'.format(arp_packet.opcode))
    print(TAB_2 + 'Sender MAC: {}, Sender IP: {}'.format(arp_packet.src_mac, arp_packet.src_ip))
    print(TAB_2 + 'Target MAC: {}, Target IP: {}'.format(arp_packet.dest_mac, arp_packet.dest_ip))
    print(TAB_2 + 'Data:')
    print(format_multi_line(DATA_TAB_3, arp_packet.data))


def print_DHCP(dhcp_packet):
    print(TAB_1 + 'DHCP Packet:')
    print(TAB_2 + 'message_type: {}, hardware_type: {}, hardware_address_length: {}, hops: {}'.format(dhcp_packet.message_type, dhcp_packet.hardware_type, dhcp_packet.hardware_address_length, dhcp_packet.hops))
    print(TAB_2 + 'transaction_id: {}, seconds_elapsed: {}, bootp_flags: {}'.format(dhcp_packet.transaction_id, dhcp_packet.seconds_elapsed, dhcp_packet.bootp_flags))

    print(TAB_2 + 'client_ip: {}'.format(dhcp_packet.client_ip))
    print(TAB_2 + 'your_ip: {}'.format(dhcp_packet.your_ip))
    print(TAB_2 + 'next_server_ip: {}'.format(dhcp_packet.next_server_ip))
    print(TAB_2 + 'relay_agent_ip: {}'.format(dhcp_packet.relay_agent_ip))
    print(TAB_2 + 'client_mac: {}'.format(dhcp_packet.client_mac))
    print(TAB_2 + 'client_hardware_padding: {}'.format(dhcp_packet.client_hardware_padding))
    print(TAB_2 + 'server_host_name: {}'.format(dhcp_packet.server_host_name))
    print(TAB_2 + 'boot_file_name: {}'.format(dhcp_packet.boot_file_name))
    print(TAB_2 + 'magic_cookie: {}'.format(dhcp_packet.magic_cookie))

    # Imprimo todas las opciones del paquete, menos las 255 que indica el final
    print(TAB_2 + 'Options:')
    for opcion in dhcp_packet.options:
        print(TAB_3 + '{}'.format(opcion))


def print_else_Ethernet(ethernet_packet):
    print(TAB_1 + 'Other Ethernet Protocol:')
    print(TAB_2 + 'Ethernet Protocol: ' + str(ethernet_packet.type))
    print(TAB_2 + 'Data:')
    print(format_multi_line(DATA_TAB_3, ethernet_packet.data))


# Formatear información en multilinea
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])