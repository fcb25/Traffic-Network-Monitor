# Conexión y almacenamiento BBDD

import mysql.connector

connection = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="prueba"
)



def almacenar_en_bbdd(src_mac, dest_mac, src_ip, dest_ip, type, data):

    sql = "INSERT INTO conexiones_4 (src_mac, dest_mac, src_ip, dest_ip, tipo, datos) VALUES (%s, %s, %s, %s, %s, %s)"
    val = (src_mac, dest_mac, src_ip, dest_ip, type, str(len(data)))

    # Realizo la conexión con un cursor
    cursor = connection.cursor()
    cursor.execute(sql, val)
    connection.commit()
    cursor.close()

    return True



def almacenar_enrutamiento_incorrecto(src_mac, src_ip, dest_mac, dest_ip):

    sql = "INSERT INTO enrutamiento_incorrecto (src_mac, src_ip, dest_mac, dest_ip) VALUES (%s, %s, %s, %s)"
    val = (src_mac, src_ip, dest_mac, dest_ip)

    # Realizo la conexión con un cursor
    cursor = connection.cursor()
    cursor.execute(sql, val)
    connection.commit()
    cursor.close()

    return True



def almacenar_arp_poisoning(src_mac, src_ip, dest_mac, dest_ip, opcode):

    sql = "INSERT INTO arp_poisoning (src_mac, src_ip, dest_mac, dest_ip, opcode) VALUES (%s, %s, %s, %s, %s)"
    val = (src_mac, src_ip, dest_mac, dest_ip, opcode)

    # Realizo la conexión con un cursor
    cursor = connection.cursor()
    cursor.execute(sql, val)
    connection.commit()
    cursor.close()

    return True



def almacenar_dhcp_spoofing(src_mac, dest_mac, dhcp_ip, your_ip, message_type):

    sql = "INSERT INTO dhcp_spoofing (src_mac, dest_mac, dhcp_ip, your_ip, message_type) VALUES (%s, %s, %s, %s, %s)"
    val = (src_mac, dest_mac, dhcp_ip, your_ip, message_type)

    # Realizo la conexión con un cursor
    cursor = connection.cursor()
    cursor.execute(sql, val)
    connection.commit()
    cursor.close()

    return True



# Método para obtener el tráfico y ver si hay posibles ataques DoS
def select_dos_traffic(start_ip, end_ip):

    #sql = "select from_unixtime(unix_timestamp(x.fecha) - unix_timestamp(x.fecha) mod 60) as ts, count(*), x.src_ip, x.dest_ip \
    #    from (select fecha, src_ip, dest_ip from conexiones_4 where dest_ip like \"%192.168.0.%\") x \
    #    group by ts, src_ip, dest_ip having count(*) > 100 order by ts"
    
    #sql = "select from_unixtime(unix_timestamp(x.fecha) - unix_timestamp(x.fecha) mod 60) as ts, count(*), x.src_ip, x.dest_ip \
    #    from (select fecha, src_ip, dest_ip from conexiones_4 where dest_ip betweeen " + str(start_ip) + " and " + str(end_ip) + ") x \
    #    group by ts, src_ip, dest_ip having count(*) > 100 order by ts"

    sql = "select from_unixtime(unix_timestamp(x.fecha) - unix_timestamp(x.fecha) mod 60) as ts, x.src_ip, x.dest_ip, count(*) \
        from (select fecha, src_ip, dest_ip from conexiones_4 where INET_ATON(dest_ip) >= INET_ATON(\"" + str(start_ip) + "\") and INET_ATON(dest_ip) <= INET_ATON(\"" + str(end_ip) + "\")) x \
        group by ts, src_ip, dest_ip having count(*) > 100 order by ts"
    
    cursor = connection.cursor()
    cursor.execute(sql)
    select_result = cursor.fetchall()

    return select_result



# Método para obtener el tráfico a partir de una fecha y ver si hay posibles ataques DoS
def select_dos_traffic_from_date(start_ip, end_ip, date):

    sql = "select from_unixtime(unix_timestamp(x.fecha) - unix_timestamp(x.fecha) mod 60) as ts, x.src_ip, x.dest_ip, count(*) \
        from (select fecha, src_ip, dest_ip from conexiones_4 where fecha > \"" + date + "\" and INET_ATON(dest_ip) >= INET_ATON(\"" + str(start_ip) + "\") and INET_ATON(dest_ip) <= INET_ATON(\"" + str(end_ip) + "\")) x \
        group by ts, src_ip, dest_ip having count(*) > 100 order by ts"
        
    
    cursor = connection.cursor()
    cursor.execute(sql)
    select_result = cursor.fetchall()

    return select_result



# Método para obtener la fecha del ultimo posible ataque DoS almacenado
def select_last_dos_attack_date():

    # Incremento la fecha en 1 minuto ya que las consultas las realizo por periodos de 1 minuto
    # y el trafico generado dentro de ese minuto ya esta analizado y no me interesa volver a analizarlo
    sql = "SELECT DATE_FORMAT(DATE_ADD(fecha, INTERVAL 1 MINUTE), '%Y-%m-%d %H:%i:%s') FROM posible_dos ORDER BY fecha DESC LIMIT 1"
    
    cursor = connection.cursor()
    cursor.execute(sql)
    select_result = cursor.fetchall()
    select_result_count = cursor.rowcount

    return select_result, select_result_count



def almacenar_posible_dos(fecha, src_ip, dest_ip, paquetes, pais, pais_codigo, region, region_codigo, ciudad, latitut, longitud):

    sql = "INSERT INTO posible_dos (fecha, src_ip, dest_ip, paquetes, pais, pais_codigo, region, region_codigo, ciudad, latitud, longitud) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    val = (fecha, src_ip, dest_ip, paquetes, pais, pais_codigo, region, region_codigo, ciudad, latitut, longitud)

    # Realizo la conexión con un cursor
    cursor = connection.cursor()
    cursor.execute(sql, val)
    connection.commit()
    cursor.close()

    return True