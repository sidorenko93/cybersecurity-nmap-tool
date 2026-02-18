import nmap
import sys

class CyberSecurityTool:
    def __init__(self):
        try:
            self.scanner = nmap.PortScanner()
        except nmap.PortScannerError:
            print("ERROR: Nmap no está instalado o no está en el PATH.")
            sys.exit(1)

    # ===============================
    # 1. ESCANEO DE PUERTOS ABIERTOS
    # ===============================
    def scan_ports(self, target, ports="1-1024"):
        print("\n[+] Iniciando escaneo de puertos...\n")
        self.scanner.scan(hosts=target, arguments=f"-sS -p {ports}")

        for host in self.scanner.all_hosts():
            print(f"Host detectado: {host}")
            print(f"Estado: {self.scanner[host].state()}")

            for proto in self.scanner[host].all_protocols():
                print(f"Protocolo: {proto}")
                ports_list = self.scanner[host][proto].keys()

                for port in sorted(ports_list):
                    state = self.scanner[host][proto][port]['state']
                    service = self.scanner[host][proto][port]['name']
                    if state == "open":
                        print(f"  [+] Puerto {port}/tcp ABIERTO - Servicio: {service}")

    # ======================================
    # 2. DETECCIÓN DE SERVICIOS Y VERSIONES
    # ======================================
    def detect_services(self, target):
        print("\n[+] Detectando servicios y versiones...\n")
        self.scanner.scan(target, arguments="-sV")

        for host in self.scanner.all_hosts():
            for proto in self.scanner[host].all_protocols():
                for port in self.scanner[host][proto]:
                    service = self.scanner[host][proto][port]
                    print(
                        f"Puerto {port}/tcp | "
                        f"Servicio: {service['name']} | "
                        f"Versión: {service.get('version', 'N/A')}"
                    )

    # ======================================
    # 3. ESCANEO DE VULNERABILIDADES (NSE)
    # ======================================
    def scan_vulnerabilities(self, target):
        print("\n[+] Ejecutando scripts NSE de vulnerabilidades...\n")
        self.scanner.scan(target, arguments="--script vuln")

        for host in self.scanner.all_hosts():
            if 'script' in self.scanner[host]:
                for script, output in self.scanner[host]['script'].items():
                    print(f"\n[!] Vulnerabilidad detectada: {script}")
                    print(output)
            else:
                print("[+] No se detectaron vulnerabilidades conocidas.")

    # ======================================
    # 4. CONFIGURACIONES DÉBILES
    # ======================================
    def weak_config_check(self, target):
        print("\n[+] Buscando configuraciones débiles...\n")
        self.scanner.scan(target, arguments="--script auth,default")

        for host in self.scanner.all_hosts():
            if 'script' in self.scanner[host]:
                for script, output in self.scanner[host]['script'].items():
                    print(f"\n[!] Script ejecutado: {script}")
                    print(output)
            else:
                print("[+] No se encontraron configuraciones débiles evidentes.")

# ===============================
# MENÚ PRINCIPAL
# ===============================
def show_menu():
    print("""
========================================
   HERRAMIENTA BÁSICA DE CIBERSEGURIDAD
========================================
1. Escanear puertos abiertos
2. Detección de servicios y versiones
3. Escaneo de vulnerabilidades (NSE)
4. Comprobación de configuraciones débiles
0. Salir
""")

def main():
    tool = CyberSecurityTool()
    target = input("Introduce la IP o rango (ej: 192.168.1.0/24): ")

    while True:
        show_menu()
        option = input("Selecciona una opción: ")

        if option == "1":
            tool.scan_ports(target)
        elif option == "2":
            tool.detect_services(target)
        elif option == "3":
            tool.scan_vulnerabilities(target)
        elif option == "4":
            tool.weak_config_check(target)
        elif option == "0":
            print("Saliendo de la herramienta.")
            break
        else:
            print("Opción no válida.")

if __name__ == "__main__":
    main()
