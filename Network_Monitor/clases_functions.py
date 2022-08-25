##### FICHERO CON FUNCIONES PARA LAS DISTINTAS CLASES #####

import socket
import codecs # Para codificar los bytes a UTF-8


def get_mac_addr(bytes_addr):
    # Mapea bytes_addr con tamaño 2 (\x08\x00'N\x18\xbe --> list --> ['08' '00' '27' '4E' '18' 'BE'])
    # Actua como una lista que contiene valores hexadecimales de dos digitos para cada byte
    bytes_str = map('{:02x}'.format, bytes_addr)  
 
    mac_addr = ':'.join(bytes_str).upper() # convierte los valores de dos digitos a mayuscula y los une con :
    return mac_addr


def get_ipv4_flags(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin):
    actived_flags = []
    
    if flag_urg == 1:
        actived_flags.append("flag_urg")
    if flag_ack == 1:
        actived_flags.append("flag_ack")
    if flag_psh == 1:
        actived_flags.append("flag_psh")
    if flag_rst == 1:
        actived_flags.append("flag_rst")
    if flag_syn == 1:
        actived_flags.append("flag_syn")
    if flag_fin == 1:
        actived_flags.append("flag_fin")
    
    return actived_flags



def process_dhcp_option_data(option, length, dato):
    
    if option == 1:
        subnet_mask = socket.inet_ntoa(dato)
        return {"option":1, "length":length, "Subnet Mask":subnet_mask}

    elif option == 2:
        return {"option":2, "length":length, "Time Offset":int.from_bytes(dato, "big")}

    elif option == 3:
        ip_router = socket.inet_ntoa(dato)
        return {"option":3, "length":length, "Router":ip_router}

    elif option == 6:
        # Recorro los distintos DNS si hay varios
        list_dns = []
        x = 0
        while(x < length):
            dns = socket.inet_ntoa(dato[x:x+4])
            list_dns.append(dns)
            x += 4
        
        return {"option":6, "length":length, "Domain Name Server":list_dns}

    elif option == 12:
        return {"option":12, "length":length, "Host name":codecs.decode(dato, 'UTF-8')}

    elif option == 23:
        return {"option":23, "length":length, "Default IP Time-to-Live":int.from_bytes(dato, "big")}

    elif option == 50:
        ip_address = socket.inet_ntoa(dato)
        return {"option":50, "length":length, "Requested IP Address":ip_address}

    elif option == 51:
        return {"option":51, "length":length, "IP Address Lease Time (seconds)":int.from_bytes(dato, "big")}

    elif option == 53:
        return {"option":53, "length":length, "DHCP":int.from_bytes(dato, "big")}

    elif option == 54:
        ip_DHCP = socket.inet_ntoa(dato)
        return {"option":54, "length":length, "DHCP Server Identifier":ip_DHCP}

    elif option == 55:
        # Recorro la lista de parametros requeridos
        param_request_list = []
        x = 0
        while(x < length):
            param_request = int.from_bytes(dato[x:x+1], "big")
            param_request_list.append(param_request)
            x += 1
        
        return {"option":55, "length":length, "Parameter Request List":param_request_list}

    elif option == 58:
        return {"option":58, "length":length, "Renewal Time Value (seconds)":int.from_bytes(dato, "big")}

    elif option == 59:
        return {"option":59, "length":length, "Rebinding Time Value (seconds)":int.from_bytes(dato, "big")}

    elif option == 60:
        return {"option":60, "length":length, "Vendor Class identifier name":codecs.decode(dato, 'UTF-8')}

    elif option == 61:
        client_identifier = {"Hardware Type":dato[0], "Client MAC Address":get_mac_addr(dato[1:])}
        return {"option":61, "length":length, "Client Identifier":client_identifier}

    elif option == 81:
        client_fully_qualified__domain_name = {"Flags":dato[0], "A-RR Result":dato[1], "PTR-RR result":dato[2], "Client Name":codecs.decode(dato[3:], 'UTF-8')}
        return {"option":81, "length":length, "Client Fully Qualified Domain Name":client_fully_qualified__domain_name}

    #elif option == 255:
    #    True