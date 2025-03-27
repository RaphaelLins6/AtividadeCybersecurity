from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    """
    Função de callback para processar pacotes capturados.
    """
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Pacote IP capturado: {src_ip} -> {dst_ip}")
        
        # Verifica se é um pacote TCP
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"Porta de origem: {src_port}, Porta de destino: {dst_port}")
            
            # Exemplo de análise: detectar pacotes para portas suspeitas
            if dst_port in [22, 23, 3389]:  # SSH, Telnet, RDP
                print(f"Alerta: Tráfego suspeito detectado para a porta {dst_port}!")

def main():
    """
    Função principal para capturar pacotes.
    """
    print("Iniciando captura de pacotes...")
    sniff(prn=packet_callback, count=10)  # Captura 10 pacotes e chama o callback

if __name__ == "__main__":
    main()