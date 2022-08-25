##### FICHERO CON FUNCIONES GENERALES #####

from datetime import datetime
import socket
import sys
from requests import get
from clases import ARP, Ethernet
import struct
from log_functions import log_enrutamiento_incorrecto, log_add_routing_table, log_arp_poisoning, log_dhcp_spoofing, log_posible_dos

import settings
from almacenamiento import almacenar_arp_poisoning, almacenar_dhcp_spoofing, almacenar_enrutamiento_incorrecto, almacenar_posible_dos, select_dos_traffic, select_dos_traffic_from_date, select_last_dos_attack_date

# Para comprobar si la ip está dentro del rango de la red
# Esta libreria puede comparar si una IP es < o > que otra, mientras que si comparas solo string puede dar problemas
# ej. 192.168.0.1 < 2.0.0.0 --> Si comparas string esto daria True, cuando en verdad es falso
from ipaddress import IPv4Address

def comprobar_tabla_enrutamiento(src_mac, src_ip, dest_mac, dest_ip):
    
    # Compruebo si la src_ip está en el rango de mi red
    if IPv4Address(src_ip) >= IPv4Address(settings.start_ip) and IPv4Address(src_ip) <= IPv4Address(settings.end_ip):
        comprobar_coincide_enrutamiento(src_mac, src_ip)

    # Compruebo si la dest_ip está en el rango de mi red
    if IPv4Address(dest_ip) >= IPv4Address(settings.start_ip) and IPv4Address(dest_ip) <= IPv4Address(settings.end_ip):
        comprobar_coincide_enrutamiento(dest_mac, dest_ip)





def comprobar_coincide_enrutamiento(mac, ip):
    
    existe = False

    # Compruebo si es una difusión de red / broadcast (la mac es FF:FF:FF:FF:FF:FF)
    # Compruebo si es la respuesta de una peticion ICMP type 3 (Destination unreachable message) (la mac es 00:00:00:00:00:00)
    if mac != "FF:FF:FF:FF:FF:FF" and mac != "00:00:00:00:00:00":

        # Recorro todas las direcciones almacenadas en la tabla de enrutamiento
        for m, i in settings.tabla_enrutamiento:

            # Compruebo si existe en la tabla
            if mac == m and ip == i:
                existe = True

            # Si coincide la MAC pero la IP no --> Problema
            if mac == m and ip != i:
                print("*********************** IP Problem ***********************")
                print("Original MAC: " + m + " - Original IP: " + i)
                print("Original MAC: " + mac + " - Problem IP: " + ip)
                log_enrutamiento_incorrecto(m, i, mac, ip, "ip")
                almacenar_enrutamiento_incorrecto(mac, ip, m, i)
                existe = True
                
            # Si coincide la IP pero la MAC no --> Problema
            if ip == i and mac != m:
                print("*********************** MAC problem ***********************")
                print("Original MAC: " + m + " - Original IP: " + i)
                print("Problem MAC: " + mac + " - Original IP: " + ip)
                log_enrutamiento_incorrecto(m, i, mac, ip, "mac")
                almacenar_enrutamiento_incorrecto(mac, ip, m, i)
                existe = True
                
        # Si no está en la tabla, lo añado
        if existe == False:
            settings.tabla_enrutamiento.append((mac, ip))
            print("********************************************************************")
            print(" + Add to routing table: " + mac + " - " + ip)
            print("********************************************************************")
            log_add_routing_table(mac, ip)
    
    
    # Imprimo la tabla de enrutamiento
    #print("*** Tabla enrutamiento ***")
    #for m, i in settings.tabla_enrutamiento:
    #    print("MAC: " + m + " - IP: " + i)




def comprobar_ataque_ARP(src_mac, src_ip, dest_mac, dest_ip, opcode):

    # Compruebo si el opcode = 2 (reply)
    if opcode == 2:

        # Compruebo si la dest_ip está en el rango de mi red
        if IPv4Address(dest_ip) >= IPv4Address(settings.start_ip) and IPv4Address(dest_ip) <= IPv4Address(settings.end_ip):

            for m, i in settings.tabla_enrutamiento:

                # Si coincide la IP pero la MAC no --> Ataque --> El atacante esta haciendo creer a la victima que la IP de un equipo tiene la MAC del atacante asociada
                if src_ip == i and src_mac != m:
                    print("*********************** ARP attack --> Changed MAC - IP  ***********************")
                    print("Attacker MAC: " + src_mac + " - Supplanted IP: " + src_ip)
                    print("Attacked device: MAC: " + dest_mac + " - IP: " + dest_ip)
                    log_arp_poisoning(src_mac, src_ip, dest_mac, dest_ip, opcode)
                    almacenar_arp_poisoning(src_mac, src_ip, dest_mac, dest_ip, opcode)



def comprobar_ataque_DHCP(src_mac, dest_mac, dhcp_segment):
    
    # Compruebo que el mensaje sea de tipo 2 (que lo envía el servidor DHCP), que sea de tipo Offer o ACK
    if (dhcp_segment.message_type == 2):

        # Comrpuebo si el paquete DHCP contiene la opción 54, que es la DHCP Server Identifier
        for opcion in dhcp_segment.options:
            if opcion['option'] == 54:
                # Compruebo si el Servidor DHCP NO es el correcto
                if IPv4Address(opcion['DHCP Server Identifier']) != settings.dhcp_ip:
                    print("*********************** DHCP attack --> Different DHCP Server IP ***********************")
                    print("src_MAC: " + src_mac + " - dest_MAC:" + dest_mac + " - Fake DHCP Server IP: " + opcion['DHCP Server Identifier'] + " - IP offered: " + dhcp_segment.your_ip + " - Message_type: " + str(dhcp_segment.message_type))
                    log_dhcp_spoofing(src_mac, dest_mac, opcion['DHCP Server Identifier'], dhcp_segment.your_ip, dhcp_segment.message_type)
                    almacenar_dhcp_spoofing(src_mac, dest_mac, opcion['DHCP Server Identifier'], dhcp_segment.your_ip, dhcp_segment.message_type)



# Obtengo los posibles ataques de DoS e información de sus IP
def comprobar_ataque_dos():

    # Obtengo la fecha del ultimo ataque DoS almacenado
    select, count = select_last_dos_attack_date()
    print(select)
    print(count)

    # Si no hay ningun ataque almacenado --> realizo la busqueda sobre todo el trafico
    if count == 0:
        select = select_dos_traffic(settings.start_ip, settings.end_ip) # Obtengo los posibles ataques de DoS

    # Si hay algun ataque almacenado --> realizo la busqueda sobre el trafico a partir de una fecha
    else:
        fecha = (select[0][0])
        #fecha = "2022-02-20 17:50:12"
        select = select_dos_traffic_from_date(settings.start_ip, settings.end_ip, fecha) # Obtengo los posibles ataques de DoS
    

    #i = 0
    for x in select:
        #i += 1
        #print(str(i) + str(x))
        print(str(x[0]) + " - " + x[1] + " - " + x[2] + " - " + str(x[3]))

        # Realizo una llamada a ipapi para obtener informacion de la IP atacante (src_ip)
        url = "https://ipapi.co/" + x[1] + "/json/"
        response = get(url)
        data = response.json()
        
        # Almaceno los valores del select y la información de la IP en los logs y en la tabla de posibles ataques de la BBDD
        log_posible_dos(x[0], x[1], x[2], str(x[3]), data['country_name'], data['country'], data['region'], data['region_code'], data['city'], data['latitude'], data['longitude'])        
        
        # (fecha, src_ip, dest_ip, paquetes, pais, pais_codigo, region, region_codigo, ciudad, latitut, longitud)
        almacenar_posible_dos(x[0], x[1], x[2], str(x[3]), data['country_name'], data['country'], data['region'], data['region_code'], data['city'], data['latitude'], data['longitude'])




def barrido_de_red():

    print("***** Start Devices Scanner *****")

    # Creo el socket para enviar los ARP
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    sock.bind(('enp0s3', 6)) # 6 its protocol number

    # Creo el socket para recibir los ARP
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    conn.setsockopt(socket.SOL_SOCKET, 25, str("enp0s3" + '\0').encode('utf-8'))


    # Obtengo la primera IP del rango y el tiempo actual
    actual_ip = settings.start_ip
    t1 = datetime.now()

    # Realizo un bucle que este escuchando paquetes ARP y vaya haciendo las peticiones ARP
    # El tiempo de escucha dura lo que se especifique en los argmuentos (default: 10s)
    while((datetime.now()-t1).seconds <= settings.time_scan_devices):
        if(actual_ip <= settings.end_ip):
            send_ARP(sock, actual_ip)
            actual_ip += 1
        
        raw_data, addr = conn.recvfrom(65536) # El socket recibe informacion con tamaño maximo de buffer 65536
        ethernet_packet = Ethernet(raw_data)

        if ethernet_packet.type == "0806":
            arp_packet = ARP(ethernet_packet.data)
            # Proceso solo los paquetes que son de respuesta opcode = 2 (reply)
            if arp_packet.opcode == 2:
                comprobar_tabla_enrutamiento(arp_packet.src_mac, arp_packet.src_ip, arp_packet.dest_mac, arp_packet.dest_ip)
        

    print("***** Finish Devices Scanner *****")
    conn.close()
    sock.close()



# Send ARP message
def send_ARP(sock, actual_ip):
    a, b, c, d = map(int, str(actual_ip).split('.'))

    ETHERNET_PACKET = [
        struct.pack('!6B', 0xff,0xff,0xff,0xff,0xff,0xff), # Destination MAC --> MAC Broadcast
        struct.pack('!6B', 0x08,0x00,0x27,0x7d,0x11,0x4d), # Source MAC --> MAC del monitor de tráfico
        struct.pack('!H', 0x0806) # Type
    ]

    ARP_PACKET = [
        struct.pack('!H', 0x0001), # Hardware type
        struct.pack('!H', 0x0800), # Protocol type = IPv4
        struct.pack('!B', 0x06), # Hardware size
        struct.pack('!B', 0x04), # Protocol size
        struct.pack('!H', 0x0001), # Opcode = request(1)
        struct.pack('!6B', 0x08,0x00,0x27,0x7d,0x11,0x4d), # Sender MAC address --> MAC del monitor de tráfico
        struct.pack('!4B', 0xc0,0xa8,0x00,0x1e), # Sender IP address --> IP del monitor de tráfico
        struct.pack('!6B', 0x00,0x00,0x00,0x00,0x00,0x00), # Targe MAC address --> MAC Broadcast
        struct.pack('!4B', a,b,c,d) # Target IP address --> IP del equipo a descubrir
    ]


    grouped_packets = ETHERNET_PACKET + ARP_PACKET
    packet = (b''.join(grouped_packets))

    sock.send(packet)