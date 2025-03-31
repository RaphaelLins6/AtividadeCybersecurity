import re
from collections import defaultdict

# Simula IPs trafegando na rede
logs = [
    '192.168.1.1 - - [10/Mar/2025:10:10:10] "PORT_SCAN 22 80 443 8080 3306 21"',
    '192.168.1.2 - - [10/Mar/2025:10:11:00] "FAILED_LOGIN admin 3x"',
    '192.168.1.3 - - [10/Mar/2025:10:12:00] "FAILED_LOGIN root 5x"',
    '192.168.1.2 - - [10/Mar/2025:10:12:30] "FAILED_LOGIN guest 4x"',
    '192.168.1.1 - - [10/Mar/2025:10:13:00] "PORT_SCAN 25 110 143 993 995"'
]

# Dicionário para armazenar a lista de logs para um acesso mais direto na identificação
ataques_detectados = defaultdict(list)

def analisar_logs(logs):
    for log in logs:
        ip = re.search(r'\d+\.\d+\.\d+\.\d+', log).group()
        
        # Detectando varredura de portas
        if "PORT_SCAN" in log:
            portas = re.findall(r'\d+', log.split('PORT_SCAN')[1])
            # Nesse caso escolhmeos um critério de 4 portas para ser considerado uma varredura
            if len(portas) >= 4:
                ataques_detectados[ip].append(f"Varredura de portas detectada: {portas}")
        
        # Detectando tentativas de login invalidas
        if "FAILED_LOGIN" in log:
            tentativa = re.search(r'FAILED_LOGIN (\w+) (\d+)x', log)
            # Nesse caso utilizamos um critério de 3 tentativas de logins
            if tentativa and int(tentativa.group(2)) >= 3:
                ataques_detectados[ip].append(f"Múltiplas falhas de login ({tentativa.group(2)}x) para usuário {tentativa.group(1)}")

# Analisando os logs
analisar_logs(logs)

# Exibindo IPs dos atacantes
for ip, ataques in ataques_detectados.items():
    print(f"Alerta! Possível ataque detectado do IP {ip}:")
    for ataque in ataques:
        print(f" - {ataque}")
