import struct
import socket
import codecs # Para codificar los bytes a UTF-8

from clases_functions import get_mac_addr, get_ipv4_flags, process_dhcp_option_data

class Packet_recived:

    def __init__(self, raw_data):
        
        self.dataLink = None
        self.network = None
        self.transport = None


# Class Ethernet
# Capa 2 --> Data Link
class Ethernet:

    def __init__(self, raw_data):

        dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s 2s', raw_data[:14]) # ! indica que es network data (big/little endian), 6s indica que son 6 caracteres y H small unsigned int
        
        self.dest_mac = get_mac_addr(dest_mac)
        self.src_mac = get_mac_addr(src_mac)
        self.type = eth_proto.hex()
        self.data = raw_data[14:]



# Class IPv4
# Capa 3 --> Network
class IPv4:

    def __init__(self, raw_data):

        version_header_lenght = raw_data[0]
        
        self.version = version_header_lenght >> 4 # Obtengo el byte entero
        self.header_length = (version_header_lenght & 15) * 4 # Obtengo el header length. Me sirve para saber lo que ocupa el header y donde empiezan los datos
        self.ttl, self.protocol, src, dest = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src = socket.inet_ntoa(src)
        self.dest = socket.inet_ntoa(dest)
        self.data = raw_data[self.header_length:]


# Class ARP
# Capa 3 --> Network
class ARP:

    def __init__(self, raw_data):

        arp_header = raw_data[:28]
        hardware, protocol, hardware_size, protocol_size, opcode, src_mac, src_ip, dest_mac, dest_ip = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
        
        self.hardware = int.from_bytes(hardware, "big")
        self.protocol = protocol.hex()
        self.hardware_size = int.from_bytes(hardware_size, "big")
        self.protocol_size = int.from_bytes(protocol_size, "big")
        self.opcode = int.from_bytes(opcode, "big")
        self.src_mac = get_mac_addr(src_mac)
        self.src_ip = socket.inet_ntoa(src_ip)
        self.dest_mac = get_mac_addr(dest_mac)
        self.dest_ip = socket.inet_ntoa(dest_ip)
        self.data = raw_data[28:]
 


# Class ICMP
# Capa 3 --> Network
class ICMP:

    def __init__(self, raw_data):

        self.icmp_type, self.code, self.checksum = struct.unpack('! B B H', raw_data[:4])
        self.data = raw_data[4:]


# Class TCP
# Capa 4 --> Transport
class TCP_segment:

    def __init__(self, raw_data):

        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, self.offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
        
        self.offset = (self.offset_reserved_flags >> 12) * 4
        
        self.flag_urg = (self.offset_reserved_flags & 32) >> 5
        self.flag_ack = (self.offset_reserved_flags & 16) >> 4
        self.flag_psh = (self.offset_reserved_flags & 8) >> 3
        self.flag_rst = (self.offset_reserved_flags & 4) >> 2
        self.flag_syn = (self.offset_reserved_flags & 2) >> 1
        self.flag_fin = self.offset_reserved_flags & 1

        self.actived_flags = get_ipv4_flags(self.flag_urg, self.flag_ack, self.flag_psh, self.flag_rst, self.flag_syn, self.flag_fin)

        self.data = raw_data[self.offset:]
        


# Class UDP
# Capa 4 --> Transport
class UDP_segment:

    def __init__(self, raw_data):

        (self.src_port, self.dest_port, self.size, self.check_sum) = struct.unpack('! H H H H', raw_data[:8])
        self.data = raw_data[8:]



# Class DHCP
# Capa 7 --> Application
class DHCP_Segment:

    def __init__(self, raw_data):

        message_type, hardware_type, hardware_address_length, hops, transaction_id, seconds_elapsed = struct.unpack("1s1s1s1s4s2s", raw_data[:10])
        bootp_flags, client_ip, your_ip, next_server_ip, relay_agent_ip, client_mac, client_hardware_padding, server_host_name, boot_file_name, magic_cookie = struct.unpack("2s4s4s4s4s6s10s64s128s4s", raw_data[10:240])
        
        self.message_type = int.from_bytes(message_type, "big")
        self.hardware_type = hardware_type.hex()
        self.hardware_address_length = int.from_bytes(hardware_address_length, "big")
        self.hops = int.from_bytes(hops, "big")
        self.transaction_id = transaction_id.hex()
        self.seconds_elapsed = int.from_bytes(seconds_elapsed, "big")

        self.bootp_flags = bootp_flags.hex()
        self.client_ip = socket.inet_ntoa(client_ip)
        self.your_ip = socket.inet_ntoa(your_ip)
        self.next_server_ip = socket.inet_ntoa(next_server_ip)
        self.relay_agent_ip = socket.inet_ntoa(relay_agent_ip)
        self.client_mac = get_mac_addr(client_mac)
        self.client_hardware_padding = codecs.decode(client_hardware_padding, 'UTF-8')
        self.server_host_name = codecs.decode(server_host_name, 'UTF-8')
        self.boot_file_name = codecs.decode(boot_file_name, 'UTF-8')
        self.magic_cookie = magic_cookie.hex()

        options = []
        x = 0
        flag = True
        while(flag):

            option = int.from_bytes(raw_data[240+x:240+x+1], "big")
            x += 1

            # Compruebo si es el final de las opciones para terminar de recorrer raw_data
            if(option == 255):
                flag = False
                continue

            length = int.from_bytes(raw_data[240+x:240+x+1], "big")
            x += 1

            dato = raw_data[240+x:240+x+length]
            #print(dato.hex())
            x += length

            # Proceso todos los campos de cada opcion
            option = process_dhcp_option_data(option, length, dato)
            options.append(option)
        

        self.options = options        