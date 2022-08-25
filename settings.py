import ipaddress

def proces_args(parser):

    # Variables globales (argumentos del programa)
    global start_ip
    global end_ip
    global dhcp_ip
    global verbose
    global time_scan_devices

    # Tabla donde se almacena cada MAC con su IP
    global tabla_enrutamiento
    tabla_enrutamiento = []

    # Ficheros de escritura (logs)
    global all_traffic
    global incorrect_routing
    global mitm_attacks
    global dos_attacks
    
    all_traffic = open("logs/all_traffic.txt", "a")
    incorrect_routing = open("logs/incorrect_routing.txt", "a")
    mitm_attacks = open("logs/mitm_attacks.txt", "a")
    dos_attacks = open("logs/dos_attacks.txt", "a")
    


    args = parser.parse_args()

    verbose = args.verbose

    # Compruebo que el tiempo especificado sea mayor que 0
    time_scan_devices = args.time_scan_devices
    if(args.time_scan_devices < 0):
        raise parser.error('Device scan time must be greater than 0')
    
    # Compruebo que las IP tengan formato correcto
    try:
        start_ip = ipaddress.IPv4Address(args.network_range[0])
    except:
        raise parser.error('Start range IP has a bad syntax ' + args.network_range[0])

    try:
        end_ip = ipaddress.IPv4Address(args.network_range[1])
    except:
        raise parser.error('End range IP has a bad syntax ' + args.network_range[1])
    
    try:
        dhcp_ip = ipaddress.IPv4Address(args.dhcp_server_ip)
    except:
        raise parser.error('DHCP server IP has a bad syntax ' + args.dhcp_server_ip)
        
    
    if(end_ip < start_ip):
        raise parser.error('Start range IP must be smaller than End range IP')