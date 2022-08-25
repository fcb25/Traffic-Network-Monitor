##### FICHERO CON FUNCIONES PARA ALMACENAR LA INFORMACIÓN #####

import settings # Clase con las variables globales

from datetime import datetime # Para obtener la fecha y hora actual

import textwrap # Para formatear la información en multilinea


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '



def log_Ethernet(ethernet_packet, i):
    # Obtengo la fecha y hora actual
    date = datetime.now()
    date_formated = date.strftime("%d/%m/%Y %H:%M:%S.%f")[:-3]

    settings.all_traffic.write(date_formated + "\n")
    settings.all_traffic.write('Packet number: ' + str(i) + "\n")
    settings.all_traffic.write('Ethernet Frame:\n')
    settings.all_traffic.write('Destination: {}, Source: {}, Protocol: {}\n'.format(ethernet_packet.dest_mac, ethernet_packet.src_mac, ethernet_packet.type))


def log_IPv4(ipv4_packet):
    settings.all_traffic.write(TAB_1 + 'IPv4 Packet:\n')
    settings.all_traffic.write(TAB_2 + 'Version {}, Header Length: {}, TTL: {}\n'.format(ipv4_packet.version, ipv4_packet.header_length, ipv4_packet.ttl))
    settings.all_traffic.write(TAB_2 + 'Protocol {}, Source: {}, Destination: {}\n'.format(ipv4_packet.protocol, ipv4_packet.src, ipv4_packet.dest))


def log_ICMP(icmp_packet):
    settings.all_traffic.write(TAB_1 + 'ICMP Packet:\n')
    settings.all_traffic.write(TAB_2 + 'Type {}, Code: {}, Checksum: {}\n'.format(icmp_packet.icmp_type, icmp_packet.code, icmp_packet.checksum))
    settings.all_traffic.write(TAB_2 + 'Data:\n')
    settings.all_traffic.write(format_multi_line(DATA_TAB_3, icmp_packet.data) + "\n")


def log_TCP(tcp_segment):
    settings.all_traffic.write(TAB_1 + 'TCP Segment:\n')
    settings.all_traffic.write(TAB_2 + 'Source Port: {}, Destination Port: {}\n'.format(tcp_segment.src_port, tcp_segment.dest_port))
    settings.all_traffic.write(TAB_2 + 'Sequence: {}, Acknowledgment: {}\n'.format(tcp_segment.sequence, tcp_segment.acknowledgment))
    settings.all_traffic.write(TAB_2 + 'Flags:')
    settings.all_traffic.write(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}\n'.format(tcp_segment.flag_urg, tcp_segment.flag_ack, tcp_segment.flag_psh, tcp_segment.flag_rst, tcp_segment.flag_syn, tcp_segment.flag_fin))
    settings.all_traffic.write(TAB_2 + 'Actived flags: {}\n'.format(tcp_segment.actived_flags))
    settings.all_traffic.write(TAB_2 + 'Data:\n')
    settings.all_traffic.write(format_multi_line(DATA_TAB_3, tcp_segment.data) + "\n")


def log_UDP(udp_segment):
    settings.all_traffic.write(TAB_1 + 'UDP Segment:\n')
    settings.all_traffic.write(TAB_2 + 'Source Port: {}, Destination port: {}, Length: {}\n'. format(udp_segment.src_port, udp_segment.dest_port, udp_segment.size))
    settings.all_traffic.write(TAB_2 + 'Data:\n')
    settings.all_traffic.write(format_multi_line(DATA_TAB_3, udp_segment.data) + "\n")


def log_else_IPv4(ipv4_packet):
    settings.all_traffic.write(TAB_1 + 'Other Type:')
    settings.all_traffic.write(TAB_2 + 'Proto Type: ' + str(ipv4_packet.protocol))
    settings.all_traffic.write(TAB_2 + 'Data:')
    settings.all_traffic.write(format_multi_line(DATA_TAB_3, ipv4_packet.data) + "\n")


def log_ARP(arp_packet):
    settings.all_traffic.write(TAB_1 + 'ARP Packet:\n')
    settings.all_traffic.write(TAB_2 + 'Hardware type: {}, Protocol type: {}, Hardware size: {}, Protocol size: {}\n'.format(arp_packet.hardware, arp_packet.protocol, arp_packet.hardware_size, arp_packet.protocol_size))
    settings.all_traffic.write(TAB_2 + 'Opcode: {}\n'.format(arp_packet.opcode))
    settings.all_traffic.write(TAB_2 + 'Sender MAC: {}, Sender IP: {}\n'.format(arp_packet.src_mac, arp_packet.src_ip))
    settings.all_traffic.write(TAB_2 + 'Target MAC: {}, Target IP: {}\n'.format(arp_packet.dest_mac, arp_packet.dest_ip))
    settings.all_traffic.write(TAB_2 + 'Data:\n')
    settings.all_traffic.write(format_multi_line(DATA_TAB_3, arp_packet.data) +"\n")


def log_DHCP(dhcp_packet):
    settings.all_traffic.write(TAB_1 + 'DHCP Packet:\n')
    settings.all_traffic.write(TAB_2 + 'message_type: {}, hardware_type: {}, hardware_address_length: {}, hops: {}\n'.format(dhcp_packet.message_type, dhcp_packet.hardware_type, dhcp_packet.hardware_address_length, dhcp_packet.hops))
    settings.all_traffic.write(TAB_2 + 'transaction_id: {}, seconds_elapsed: {}, bootp_flags: {}'.format(dhcp_packet.transaction_id, dhcp_packet.seconds_elapsed, dhcp_packet.bootp_flags))

    settings.all_traffic.write(TAB_2 + 'client_ip: {}\n'.format(dhcp_packet.client_ip))
    settings.all_traffic.write(TAB_2 + 'your_ip: {}\n'.format(dhcp_packet.your_ip))
    settings.all_traffic.write(TAB_2 + 'next_server_ip: {}\n'.format(dhcp_packet.next_server_ip))
    settings.all_traffic.write(TAB_2 + 'relay_agent_ip: {}\n'.format(dhcp_packet.relay_agent_ip))
    settings.all_traffic.write(TAB_2 + 'client_mac: {}\n'.format(dhcp_packet.client_mac))
    settings.all_traffic.write(TAB_2 + 'client_hardware_padding: {}\n'.format(dhcp_packet.client_hardware_padding))
    settings.all_traffic.write(TAB_2 + 'server_host_name: {}\n'.format(dhcp_packet.server_host_name))
    settings.all_traffic.write(TAB_2 + 'boot_file_name: {}\n'.format(dhcp_packet.boot_file_name))
    settings.all_traffic.write(TAB_2 + 'magic_cookie: {}\n'.format(dhcp_packet.magic_cookie))

    # Imprimo todas las opciones del paquete, menos las 255 que indica el final
    settings.all_traffic.write(TAB_2 + 'Options:\n')
    for opcion in dhcp_packet.options:
        settings.all_traffic.write(TAB_3 + '{}\n'.format(opcion))


def log_else_Ethernet(ethernet_packet):
    settings.all_traffic.write(TAB_1 + 'Other Ethernet Protocol:\n')
    settings.all_traffic.write(TAB_2 + 'Ethernet Protocol: ' + str(ethernet_packet.type) + "\n")
    settings.all_traffic.write(TAB_2 + 'Data:\n')
    settings.all_traffic.write(format_multi_line(DATA_TAB_3, ethernet_packet.data) + "\n")


# Formatear información en multilinea
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])






def log_add_routing_table(mac, ip):
    # Obtengo la fecha y hora actual
    date = datetime.now()
    date_formated = date.strftime("%d/%m/%Y %H:%M:%S.%f")[:-3]

    settings.all_traffic.write("********************************************************************")
    settings.all_traffic.write(date_formated + "\n")
    settings.all_traffic.write(" + Add to routing table: " + mac + " - " + ip)
    settings.all_traffic.write("********************************************************************")




def log_enrutamiento_incorrecto(m, i, mac, ip, problem):
    # Obtengo la fecha y hora actual
    date = datetime.now()
    date_formated = date.strftime("%d/%m/%Y %H:%M:%S.%f")[:-3]

    if problem == "ip":
        settings.incorrect_routing.write("*********************** IP Problem ***********************\n")
        settings.incorrect_routing.write(date_formated + "\n")
        settings.incorrect_routing.write("Original MAC: " + m + " - Original IP: " + i + "\n")
        settings.incorrect_routing.write("Original MAC: " + mac + " - Problem IP: " + ip + "\n")

    if problem == "mac":
        settings.incorrect_routing.write('*********************** MAC Problem ***********************\n')
        settings.incorrect_routing.write(date_formated + "\n")
        settings.incorrect_routing.write("Original MAC: " + m + " - Original IP: " + i + "\n")
        settings.incorrect_routing.write("Problem MAC: " + mac + " - Original IP: " + ip + "\n")




def log_arp_poisoning(src_mac, src_ip, dest_mac, dest_ip, opcode):
    # Obtengo la fecha y hora actual
    date = datetime.now()
    date_formated = date.strftime("%d/%m/%Y %H:%M:%S.%f")[:-3]

    settings.mitm_attacks.write("*********************** ARP attack --> Changed MAC ***********************\n")
    settings.mitm_attacks.write(date_formated + "\n")
    settings.mitm_attacks.write("Attacker MAC: " + src_mac + " - Supplanted IP: " + src_ip + "\n")
    settings.mitm_attacks.write("Attacked device: MAC: " + dest_mac + " - IP: " + dest_ip + "\n")




def log_dhcp_spoofing(src_mac, dest_mac, dhcp_server_ip, your_ip, message_type):
    # Obtengo la fecha y hora actual
    date = datetime.now()
    date_formated = date.strftime("%d/%m/%Y %H:%M:%S.%f")[:-3]

    settings.mitm_attacks.write("*********************** DHCP attack --> Different DHCP Server IP ***********************\n")
    settings.mitm_attacks.write(date_formated + "\n")
    settings.mitm_attacks.write("src_MAC: " + src_mac + " - dest_MAC:" + dest_mac + " - Fake DHCP Server IP: " + dhcp_server_ip + " - IP offered: " + your_ip + " - Message_type: " + str(message_type) + "\n")




def log_posible_dos(fecha, src_ip, dest_ip, paquetes, pais, pais_codigo, region, region_codigo, ciudad, latitut, longitud):
    # Obtengo la fecha y hora actual
    date = datetime.now()
    date_formated = date.strftime("%d/%m/%Y %H:%M:%S.%f")[:-3]

    settings.dos_attacks.write("*********************** Possible DoS attack --> Checked at: " + date_formated + " ***********************\n")
    settings.dos_attacks.write("Attack date: " + str(fecha) + " Source IP: " + src_ip + " Destination IP: " + dest_ip + "\n")
    settings.dos_attacks.write("Number of packets recibed in 1 minute: " + str(paquetes) + "\n")
    settings.dos_attacks.write("Source IP Information - Country: " + pais + " (" + pais_codigo + ") - Region: " + region + " (" + region_codigo + ") - City: " + ciudad + " - Latitude: " + str(latitut) + " - Longitude: " + str(longitud) + "\n")