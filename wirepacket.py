from scapy.all import sniff, Raw, IP, TCP

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):  # Filtra pacotes TCP com payload
        ip_src = packet[IP].src  # IP de origem
        ip_dst = packet[IP].dst  # IP de destino
        payload = packet[Raw].load  # Dados do pacote
        print(f"[+] Pacote Capturado: {ip_src} -> {ip_dst}")
        print(f"Mensagem: {payload.decode(errors='ignore')}")  # Tenta decodificar como string

print("Iniciando captura de pacotes...")
def sniff_per_port():
    sniff(filter="tcp port 5432", prn=packet_callback, store=0)

def sniff_per_ip(src, ip):
    sniff(filter=f"ip {src} {ip}", prn=packet_callback, store=0)

#sniff_per_port()
#sniff_per_ip('src', '172.24.48.1')
sniff_per_ip('dst', '172.24.53.84')
