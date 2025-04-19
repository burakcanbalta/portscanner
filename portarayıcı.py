#!/usr/bin/env python3
import socket
import concurrent.futures
import argparse
from datetime import datetime
import ipaddress
import nmap
import requests
from colorama import Fore, init, Style
import asyncio
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox
import os
import json
from urllib.parse import urlparse

# Renkleri başlat
init(autoreset=True)

# Özel servis veritabanı
CUSTOM_SERVICES = {
    3000: "Node.js",
    8080: "HTTP-Alt",
    9000: "Hadoop",
    9200: "Elasticsearch",
    27017: "MongoDB",
    5601: "Kibana"
}

# Güvenlik açığı veritabanı
VULN_DB = {
    "Apache 2.4.49": "CVE-2021-41773",
    "OpenSSH 8.2p1": "CVE-2020-15778",
    "ProFTPd 1.3.5": "CVE-2015-3306",
    "WordPress 5.0": "CVE-2019-9978",
    "MySQL 5.7": "CVE-2019-2631"
}

class AdvancedPortScanner:
    def __init__(self):
        self.open_ports = []
        self.scan_results = []
        self.nm = nmap.PortScanner()
        self.db_conn = sqlite3.connect('scan_results.db')
        self.init_db()
        
    def init_db(self):
        cursor = self.db_conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS scans
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          target TEXT,
                          port INTEGER,
                          service TEXT,
                          version TEXT,
                          vulnerabilities TEXT,
                          timestamp DATETIME)''')
        self.db_conn.commit()

    def print_banner(self):
        banner = f"""
{Fore.RED}╔═╗╔═╗╔╦╗  ╔╦╗╔═╗╦═╗╔╦╗  ╔═╗╔═╗╔╦╗╔═╗╦═╗╔╦╗
{Fore.RED}║ ╦╠═╣║║║  ║║║║ ║╠╦╝║║║  ╠═╣╠═╝║║║║╣ ╠╦╝║║║
{Fore.RED}╚═╝╩ ╩╩ ╩  ╩ ╩╚═╝╩╚═╩ ╩  ╩ ╩╩  ╩ ╩╚═╝╩╚═╩ ╩
{Fore.CYAN}Gelişmiş Port Tarayıcı ve Güvenlik Analiz Aracı
{Fore.YELLOW}Versiyon: 3.0 | Yazar: DeepSeek Chat
        """
        print(banner)

    def validate_target(self, target):
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            try:
                socket.gethostbyname(target)
                return True
            except socket.gaierror:
                return False

    def adaptive_timeout(self, port):
        common_ports = [21, 22, 80, 443, 3389, 3306]
        return 0.3 if port in common_ports else 1.2

    def get_service_info(self, port):
        try:
            return CUSTOM_SERVICES.get(port, socket.getservbyport(port, "tcp"))
        except:
            return "unknown"

    async def async_scan_port(self, target, port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.adaptive_timeout(port)
            )
            writer.close()
            await writer.wait_closed()
            return port, True
        except:
            return port, False

    def scan_tcp_port(self, target, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.adaptive_timeout(port))
                result = s.connect_ex((target, port))
                if result == 0:
                    service = self.get_service_info(port)
                    return port, True, service
        except Exception as e:
            pass
        return port, False, None

    def scan_udp_port(self, target, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.sendto(b'\x00', (target, port))
                s.recvfrom(1024)
                return port, True, "UDP"
        except:
            return port, False, None

    def nmap_service_scan(self, target, ports):
        try:
            port_str = ','.join(map(str, ports))
            self.nm.scan(hosts=target, ports=port_str, arguments='-sV -T4')
            
            results = []
            for proto in self.nm[target].all_protocols():
                for port in self.nm[target][proto].keys():
                    service = self.nm[target][proto][port]['name']
                    product = self.nm[target][proto][port].get('product', '')
                    version = self.nm[target][proto][port].get('version', '')
                    info = f"{service} {product} {version}".strip()
                    results.append((port, True, info))
            return results
        except Exception as e:
            print(f"{Fore.RED}[!] Nmap taraması başarısız: {str(e)}")
            return []

    def check_web(self, ip, port):
        protocols = ['http', 'https']
        for protocol in protocols:
            url = f"{protocol}://{ip}:{port}"
            try:
                response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
                if response.status_code < 500:
                    server = response.headers.get('Server', '')
                    title = ""
                    if '<title>' in response.text:
                        title = response.text.split('<title>')[1].split('</title>')[0][:50]
                    return {
                        'protocol': protocol,
                        'status': response.status_code,
                        'server': server,
                        'title': title,
                        'url': url
                    }
            except:
                continue
        return None

    def check_vulnerabilities(self, service_info):
        for pattern, vuln in VULN_DB.items():
            if pattern in service_info:
                return vuln
        return None

    def scan_through_proxy(self, target, port, proxy_config):
        proxies = {
            'http': f'http://{proxy_config["ip"]}:{proxy_config["port"]}',
            'https': f'http://{proxy_config["ip"]}:{proxy_config["port"]}'
        }
        try:
            requests.get(f'http://{target}:{port}', proxies=proxies, timeout=3)
            return True
        except:
            return False

    def save_to_db(self, target, port, service, version, vulnerabilities):
        cursor = self.db_conn.cursor()
        cursor.execute(
            "INSERT INTO scans (target, port, service, version, vulnerabilities, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (target, port, service, version, vulnerabilities, datetime.now())
        )
        self.db_conn.commit()

    def generate_html_report(self, target, results, filename='report.html'):
        rows = ""
        for result in results:
            port = result['port']
            service = result['service']
            version = result.get('version', '')
            vuln = result.get('vulnerability', '')
            web = result.get('web', '')
            
            row_class = "vulnerable" if vuln else ""
            
            web_info = ""
            if web:
                web_info = f"""<br>
                    <strong>Web:</strong> {web['url']}<br>
                    <strong>Server:</strong> {web['server']}<br>
                    <strong>Title:</strong> {web['title']}
                """
            
            rows += f"""
            <tr class="{row_class}">
                <td>{port}</td>
                <td>{service}</td>
                <td>{version}</td>
                <td>{vuln if vuln else 'None'}</td>
                <td>{web_info}</td>
            </tr>
            """
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Tarama Raporu - {target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr.vulnerable {{ background-color: #ffdddd; }}
                .summary {{ margin-top: 20px; padding: 10px; background-color: #f9f9f9; }}
            </style>
        </head>
        <body>
            <h1>{target} Tarama Sonuçları</h1>
            <p>Tarama Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <table>
                <tr>
                    <th>Port</th>
                    <th>Servis</th>
                    <th>Versiyon</th>
                    <th>Güvenlik Açığı</th>
                    <th>Ek Bilgiler</th>
                </tr>
                {rows}
            </table>
            
            <div class="summary">
                <h3>Özet</h3>
                <p>Toplam Açık Port: {len(results)}</p>
                <p>Güvenlik Açıkları: {sum(1 for r in results if r.get('vulnerability'))}</p>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html)
        return filename

    async def async_port_scan(self, target, ports, scan_type='tcp', threads=100):
        open_ports = []
        
        if scan_type == 'tcp':
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(self.scan_tcp_port, target, port): port for port in ports}
                for future in concurrent.futures.as_completed(futures):
                    port, is_open, service = future.result()
                    if is_open:
                        open_ports.append(port)
                        print(f"{Fore.GREEN}[+] TCP Port {port} ({service}) açık")
        
        elif scan_type == 'udp':
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(self.scan_udp_port, target, port): port for port in ports}
                for future in concurrent.futures.as_completed(futures):
                    port, is_open, service = future.result()
                    if is_open:
                        open_ports.append(port)
                        print(f"{Fore.GREEN}[+] UDP Port {port} ({service}) açık")
        
        elif scan_type == 'both':
            await self.async_port_scan(target, ports, 'tcp', threads)
            await self.async_port_scan(target, ports, 'udp', threads)
        
        return open_ports

    def run_scan(self, target, ports, scan_type='tcp', threads=100, service_scan=False, 
                 web_scan=False, vuln_scan=False, proxy=None, output=None):
        
        if not self.validate_target(target):
            print(f"{Fore.RED}[!] Geçersiz hedef: {target}")
            return
        
        try:
            if '-' in ports:
                start_port, end_port = map(int, ports.split('-'))
                ports = list(range(start_port, end_port + 1))
            else:
                ports = [int(p) for p in ports.split(',')]
        except:
            print(f"{Fore.RED}[!] Geçersiz port aralığı. Örnek: 1-1000 veya 80,443,8080")
            return
        
        print(f"{Fore.CYAN}[*] {target} hedefi için {scan_type.upper()} taraması başlatılıyor...\n")
        
        start_time = datetime.now()
        open_ports = asyncio.run(self.async_port_scan(target, ports, scan_type, threads))
        
        results = []
        if open_ports and (service_scan or web_scan or vuln_scan):
            print(f"\n{Fore.CYAN}[*] Detaylı analiz yapılıyor...")
            
            service_results = self.nmap_service_scan(target, open_ports) if service_scan else []
            
            for port in open_ports:
                result = {'port': port, 'service': self.get_service_info(port)}
                
                # Servis versiyon bilgisi
                if service_scan:
                    for sr_port, _, sr_info in service_results:
                        if sr_port == port:
                            result['service'] = sr_info.split()[0]
                            result['version'] = ' '.join(sr_info.split()[1:])
                            break
                
                # Web servis kontrolü
                if web_scan and (result['service'].lower() in ['http', 'https', 'ssl'] or port in [80, 443, 8080, 8443]):
                    web_info = self.check_web(target, port)
                    if web_info:
                        result['web'] = web_info
                
                # Güvenlik açığı kontrolü
                if vuln_scan and 'version' in result:
                    vuln = self.check_vulnerabilities(result['version'])
                    if vuln:
                        result['vulnerability'] = vuln
                
                # Veritabanına kaydet
                self.save_to_db(
                    target, port, 
                    result.get('service', ''), 
                    result.get('version', ''), 
                    result.get('vulnerability', '')
                )
                
                results.append(result)
                
                # Sonuçları ekrana yazdır
                output_str = f"{Fore.BLUE}[*] Port {port}: {result['service']}"
                if 'version' in result:
                    output_str += f" | Versiyon: {result['version']}"
                if 'vulnerability' in result:
                    output_str += f" | {Fore.RED}Güvenlik Açığı: {result['vulnerability']}"
                if 'web' in result:
                    output_str += f"\n{Fore.MAGENTA}    Web: {result['web']['url']} ({result['web']['server']})"
                print(output_str)
        
        # Rapor oluştur
        if output:
            if output.endswith('.html'):
                report_file = self.generate_html_report(target, results, output)
                print(f"\n{Fore.CYAN}[*] HTML rapor oluşturuldu: {report_file}")
            else:
                with open(output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"\n{Fore.CYAN}[*] Sonuçlar {output} dosyasına kaydedildi")
        
        duration = datetime.now() - start_time
        print(f"\n{Fore.YELLOW}[*] Tarama tamamlandı! Süre: {duration.total_seconds():.2f} saniye")
        print(f"{Fore.YELLOW}[*] Toplam {len(open_ports)} açık port bulundu")
        
        return results

class ScannerGUI:
    def __init__(self, scanner):
        self.scanner = scanner
        self.window = tk.Tk()
        self.window.title("Gelişmiş Port Tarayıcı")
        self.window.geometry("800x600")
        
        self.create_widgets()
    
    def create_widgets(self):
        # Hedef Girişi
        tk.Label(self.window, text="Hedef:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.target_entry = tk.Entry(self.window, width=40)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        
        # Port Aralığı
        tk.Label(self.window, text="Portlar:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.ports_entry = tk.Entry(self.window, width=40)
        self.ports_entry.insert(0, "1-1024")
        self.ports_entry.grid(row=1, column=1, padx=5, pady=5, sticky='w')
        
        # Tarama Türü
        tk.Label(self.window, text="Tarama Türü:").grid(row=2, column=0, padx=5, pady=5, sticky='e')
        self.scan_type = tk.StringVar(value="tcp")
        tk.Radiobutton(self.window, text="TCP", variable=self.scan_type, value="tcp").grid(row=2, column=1, sticky='w')
        tk.Radiobutton(self.window, text="UDP", variable=self.scan_type, value="udp").grid(row=2, column=2, sticky='w')
        tk.Radiobutton(self.window, text="Her İkisi", variable=self.scan_type, value="both").grid(row=2, column=3, sticky='w')
        
        # Thread Sayısı
        tk.Label(self.window, text="Thread Sayısı:").grid(row=3, column=0, padx=5, pady=5, sticky='e')
        self.threads_entry = tk.Entry(self.window, width=10)
        self.threads_entry.insert(0, "100")
        self.threads_entry.grid(row=3, column=1, padx=5, pady=5, sticky='w')
        
        # Ek Özellikler
        self.service_scan = tk.BooleanVar()
        tk.Checkbutton(self.window, text="Servis Versiyon Tespiti", variable=self.service_scan).grid(row=4, column=1, sticky='w')
        
        self.web_scan = tk.BooleanVar()
        tk.Checkbutton(self.window, text="Web Servis Analizi", variable=self.web_scan).grid(row=4, column=2, sticky='w')
        
        self.vuln_scan = tk.BooleanVar()
        tk.Checkbutton(self.window, text="Güvenlik Açığı Taraması", variable=self.vuln_scan).grid(row=4, column=3, sticky='w')
        
        # Proxy Ayarları
        tk.Label(self.window, text="Proxy (ip:port):").grid(row=5, column=0, padx=5, pady=5, sticky='e')
        self.proxy_entry = tk.Entry(self.window, width=40)
        self.proxy_entry.grid(row=5, column=1, padx=5, pady=5, sticky='w')
        
        # Çıktı Dosyası
        tk.Label(self.window, text="Çıktı Dosyası:").grid(row=6, column=0, padx=5, pady=5, sticky='e')
        self.output_entry = tk.Entry(self.window, width=40)
        self.output_entry.grid(row=6, column=1, padx=5, pady=5, sticky='w')
        
        # Tarama Butonu
        self.scan_button = tk.Button(self.window, text="Taramayı Başlat", command=self.start_scan)
        self.scan_button.grid(row=7, column=1, pady=10)
        
        # Sonuçlar
        self.results_text = tk.Text(self.window, wrap=tk.WORD, height=20, width=90)
        self.results_text.grid(row=8, column=0, columnspan=4, padx=10, pady=10)
        
        # Scrollbar
        scrollbar = tk.Scrollbar(self.window, command=self.results_text.yview)
        scrollbar.grid(row=8, column=4, sticky='ns')
        self.results_text.config(yscrollcommand=scrollbar.set)
    
    def start_scan(self):
        target = self.target_entry.get()
        if not target:
            messagebox.showerror("Hata", "Hedef belirtilmelidir!")
            return
        
        # Proxy ayarları
        proxy = None
        proxy_text = self.proxy_entry.get()
        if proxy_text:
            try:
                proxy_ip, proxy_port = proxy_text.split(':')
                proxy = {'ip': proxy_ip, 'port': int(proxy_port)}
            except:
                messagebox.showerror("Hata", "Geçersiz proxy formatı! Örnek: 127.0.0.1:8080")
                return
        
        # Taramayı başlat
        self.scan_button.config(state=tk.DISABLED)
        self.results_text.delete(1.0, tk.END)
        
        try:
            results = self.scanner.run_scan(
                target=target,
                ports=self.ports_entry.get(),
                scan_type=self.scan_type.get(),
                threads=int(self.threads_entry.get()),
                service_scan=self.service_scan.get(),
                web_scan=self.web_scan.get(),
                vuln_scan=self.vuln_scan.get(),
                proxy=proxy,
                output=self.output_entry.get() or None
            )
            
            # Sonuçları göster
            self.show_results(results)
            
        except Exception as e:
            messagebox.showerror("Hata", f"Tarama sırasında hata oluştu:\n{str(e)}")
        finally:
            self.scan_button.config(state=tk.NORMAL)
    
    def show_results(self, results):
        self.results_text.insert(tk.END, "TARAMA SONUÇLARI\n")
        self.results_text.insert(tk.END, "="*50 + "\n\n")
        
        for result in results:
            line = f"Port: {result['port']} | Servis: {result['service']}"
            
            if 'version' in result:
                line += f" | Versiyon: {result['version']}"
            
            if 'vulnerability' in result:
                line += f" | GÜVENLİK AÇIĞI: {result['vulnerability']}"
            
            self.results_text.insert(tk.END, line + "\n")
            
            if 'web' in result:
                web_info = result['web']
                self.results_text.insert(tk.END, f"    Web: {web_info['url']} (Status: {web_info['status']})\n")
                self.results_text.insert(tk.END, f"    Server: {web_info['server']}\n")
                self.results_text.insert(tk.END, f"    Title: {web_info['title']}\n")
            
            self.results_text.insert(tk.END, "-"*50 + "\n")
    
    def run(self):
        self.window.mainloop()

def main():
    parser = argparse.ArgumentParser(description='Gelişmiş Port Tarayıcı ve Güvenlik Analiz Aracı')
    parser.add_argument('target', nargs='?', help='Hedef IP veya domain')
    parser.add_argument('-p', '--ports', help='Port aralığı (örn: 1-1000) veya liste (örn: 80,443,8080)', default='1-1024')
    parser.add_argument('-t', '--threads', type=int, help='Thread sayısı', default=100)
    parser.add_argument('-T', '--scan-type', choices=['tcp', 'udp', 'both'], help='Tarama türü', default='tcp')
    parser.add_argument('-sV', '--service-version', action='store_true', help='Servis versiyon tespiti yap')
    parser.add_argument('-w', '--web-scan', action='store_true', help='Web servis analizi yap')
    parser.add_argument('-v', '--vuln-scan', action='store_true', help='Güvenlik açığı taraması yap')
    parser.add_argument('-x', '--proxy', help='Proxy sunucusu (örn: 127.0.0.1:8080)')
    parser.add_argument('-o', '--output', help='Sonuçları dosyaya kaydet (JSON veya HTML)')
    parser.add_argument('-g', '--gui', action='store_true', help='Grafiksel arayüzü başlat')
    
    args = parser.parse_args()
    
    scanner = AdvancedPortScanner()
    scanner.print_banner()
    
    if args.gui or not args.target:
        gui = ScannerGUI(scanner)
        gui.run()
    else:
        proxy_config = None
        if args.proxy:
            try:
                proxy_ip, proxy_port = args.proxy.split(':')
                proxy_config = {'ip': proxy_ip, 'port': int(proxy_port)}
            except:
                print(f"{Fore.RED}[!] Geçersiz proxy formatı. Örnek: 127.0.0.1:8080")
                return
        
        scanner.run_scan(
            target=args.target,
            ports=args.ports,
            scan_type=args.scan_type,
            threads=args.threads,
            service_scan=args.service_version,
            web_scan=args.web_scan,
            vuln_scan=args.vuln_scan,
            proxy=proxy_config,
            output=args.output
        )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Tarama kullanıcı tarafından durduruldu")
        exit(0)
##Kullanım
Kurulum
bash
pip install python-nmap requests colorama tkinter
bash
python3 port_scanner.py hedef.com -p 1-1000 -t 200 -sV -o sonuclar.txt
Gereksinimler
bash
pip install python-nmap requests colorama##
