# Ejecutable para hacer el decode con binsascii.hexlify y comprobar los resultados con main.py

import socket

import argparse
import sys
import threading

import settings # Clase con las variables globales
from clases import *
from print_functions import print_Ethernet, print_IPv4, print_ICMP, print_TCP, print_UDP, print_DHCP, print_else_IPv4, print_ARP, print_else_Ethernet
from log_functions import log_Ethernet, log_IPv4, log_ICMP, log_TCP, log_UDP, log_DHCP, log_else_IPv4, log_ARP, log_else_Ethernet
from functions import barrido_de_red, comprobar_tabla_enrutamiento, comprobar_ataque_DHCP, comprobar_ataque_ARP, comprobar_ataque_dos
from almacenamiento import almacenar_en_bbdd, connection


# Captura trafico
def traffic_capture():
    # Creo un socket(AF_PACKET: Low-level packet interface, SOCK_RAW: RAW socket, ntohs: network to host short)
    # socket(AF_PACKET,RAW_SOCKET,...) means L2 socket , Data-link Layer Protocol = Ethernet
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # Con esto puedo vincular el socket a una inferfaz concreta
    conn.setsockopt(socket.SOL_SOCKET, 25, str("enp0s3" + '\0').encode('utf-8'))

    i = 0

    print('Entro al main')

    while True:
        raw_data, addr = conn.recvfrom(65536) # El socket recibe informacion con tamaño maximo de buffer 65536
        ethernet_packet = Ethernet(raw_data)

        # Compruebo que el paquete no sea de loopback, ya que no me interesa procesar dicho tráfico
        # Por tanto, solo proceso el tráfico cuya MAC origen y destino no sean 00:00:00:00:00:00
        if(ethernet_packet.src_mac != "00:00:00:00:00:00" and ethernet_packet.dest_mac != "00:00:00:00:00:00"):
            
            log_Ethernet(ethernet_packet, i)
            if(settings.verbose == True):print_Ethernet(ethernet_packet, i)

            i += 1

            # Proceso el tipo de paquete en funcion del protocolo
            # 0800 = IPv4
            if ethernet_packet.type == "0800":
                ipv4_packet = IPv4(ethernet_packet.data)
                # Compruebo si las conexiones están en la red
                comprobar_tabla_enrutamiento(ethernet_packet.src_mac, ipv4_packet.src, ethernet_packet.dest_mac, ipv4_packet.dest)
                
                # Compruebo que el paquete no sea de loopback, ya que no me interesa almacenar dicho tráfico
                log_IPv4(ipv4_packet)
                if(settings.verbose == True):print_IPv4(ipv4_packet)
                
                # Almaceno el paquete en le BBDD
                almacenar_en_bbdd(ethernet_packet.src_mac, ethernet_packet.dest_mac, ipv4_packet.src, ipv4_packet.dest, ipv4_packet.protocol, ipv4_packet.data)


                # 1 = ICMP
                if ipv4_packet.protocol == 1:
                    icmp_packet = ICMP(ipv4_packet.data)
                    log_ICMP(icmp_packet)
                    if(settings.verbose == True):print_ICMP(icmp_packet)


                # 6 = TCP
                elif ipv4_packet.protocol == 6:
                    tcp_segment = TCP_segment(ipv4_packet.data)
                    log_TCP(tcp_segment)
                    if(settings.verbose == True):print_TCP(tcp_segment)


                # 17 = UDP
                elif ipv4_packet.protocol == 17:
                    udp_segment = UDP_segment(ipv4_packet.data)
                    log_UDP(udp_segment)
                    if(settings.verbose == True):print_UDP(udp_segment)
                    
                    if (udp_segment.src_port == 67 and udp_segment.dest_port == 68) or (udp_segment.src_port == 68 and udp_segment.dest_port == 67):
                        dhcp_segment = DHCP_Segment(udp_segment.data)
                        log_DHCP(dhcp_segment)
                        if(settings.verbose == True):print_DHCP(dhcp_segment)
                        comprobar_ataque_DHCP(ethernet_packet.src_mac, ethernet_packet.dest_mac, dhcp_segment)

                
                # Otro tipo
                else:
                    log_else_IPv4(ipv4_packet)
                    if(settings.verbose == True):print_else_IPv4(ipv4_packet)

            
            # 0806 = ARP
            elif ethernet_packet.type == "0806":
                arp_packet = ARP(ethernet_packet.data)
                # Compruebo si existe un ataque Man in the Middle mediante ARP
                # Lo compruebo sobre las MAC e IP del paquete ARP, ya que es con las que se realiza el ataque (no con las MAC de la cabecera ethernet)
                comprobar_ataque_ARP(arp_packet.src_mac, arp_packet.src_ip, arp_packet.dest_mac, arp_packet.dest_ip, arp_packet.opcode) 
                log_ARP(arp_packet)           
                if(settings.verbose == True):print_ARP(arp_packet)


            else:
                log_else_Ethernet(ethernet_packet)
                if(settings.verbose == True):print_else_Ethernet(ethernet_packet)
            


            # Cada 10000 paquetes recibidos compruebo si hay posibles ataques de DoS
            if i % 10000 == 0:

                # Creo un hilo de ejecución para que el monitor continue analizando el trafico
                th = threading.Thread(target=comprobar_ataque_dos)
                th.start()
                #comprobar_ataque_dos()




if __name__ == '__main__':
    
    # Obtengo los argumentos del programa
    parser = argparse.ArgumentParser(description='Network Traffic Monitor')
    parser.add_argument('-n', '--network_range', default=['192.168.0.1','192.168.0.255'], nargs=2, metavar=('start_ip','end_ip'), type=str, help='Network IP range (start and end IP) | -n 192.168.0.1 192.168.0.255')
    parser.add_argument('-d', '--dhcp_server_ip', default='192.168.0.1', type=str, help='DHCP Server IP | -d 192.168.0.1')
    parser.add_argument('-v', '--verbose', default='False', action='store_true', help='Show traffic info | -v')
    parser.add_argument('-t', '--time_scan_devices', default=10, type=int, help='Time in seconds scanning devices on network range before start the traffic monitor | -t 10')
    

    try:
        # Proceso los argumentos y creo las variables globales
        settings.proces_args(parser)

        print("****************************************")
        print("********** Program Parameters **********")
        print("****************************************")
        print("Start IP: " + str(settings.start_ip))
        print("End IP: " + str(settings.end_ip))
        print("DHCP IP: " + str(settings.dhcp_ip))
        print("Verbose: " + str(settings.verbose))
        print("Time in seconds Scanning Devices: " + str(settings.time_scan_devices))
        print("****************************************")


        # Realizo un barrido de ARP a todas las direcciones IP del rango de la red para crear la tabla de enrutamiento
        barrido_de_red()

        traffic_capture()
    
    except KeyboardInterrupt:
        print("\nClosing the traffic monitor")
        settings.all_traffic.close()
        settings.incorrect_routing.close()
        settings.mitm_attacks.close()
        settings.dos_attacks.close()