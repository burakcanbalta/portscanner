#!/usr/bin/env python3
import socket
import concurrent.futures
import argparse
from datetime import datetime
import ipaddress
import sys
import threading
import time
import json
import sqlite3
from urllib.parse import urlparse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

class AdvancedPortScanner:
    def __init__(self):
        self.open_ports = []
        self.scan_results = []
        self.db_conn = sqlite3.connect('scan_results.db', check_same_thread=False)
        self.init_db()
        
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
        
    def init_db(self):
        cursor = self.db_conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS scans
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          target TEXT,
                          port INTEGER,
                          service TEXT,
                          version TEXT,
                          status TEXT,
                          timestamp DATETIME)''')
        self.db_conn.commit()

    def print_banner(self):
        banner = """
╔═╗╔═╗╔╦╗  ╔╦╗╔═╗╦═╗╔╦╗  ╔═╗╔═╗╔╦╗╔═╗╦═╗╔╦╗
║ ╦╠═╣║║║  ║║║║ ║╠╦╝║║║  ╠═╣╠═╝║║║║╣ ╠╦╝║║║
╚═╝╩ ╩╩ ╩  ╩ ╩╚═╝╩╚═╩ ╩  ╩ ╩╩  ╩ ╩╚═╝╩╚═╩ ╩
Gelişmiş Port Tarayıcı ve Güvenlik Analiz Aracı
Versiyon: 3.0 | Thread Safe Edition
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

    def get_service_info(self, port):
        service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
            27017: "MongoDB", 9200: "Elasticsearch", 5601: "Kibana"
        }
        return service_map.get(port, "Unknown")

    def scan_tcp_port(self, target, port, timeout=1.0):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                service = self.get_service_info(port)
                return port, True, service
        except Exception:
            pass
        return port, False, None

    def scan_udp_port(self, target, port, timeout=2.0):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b'\x00', (target, port))
            sock.recvfrom(1024)
            sock.close()
            return port, True, "UDP"
        except socket.timeout:
            return port, False, None
        except Exception:
            return port, False, None

    def port_scan(self, target, ports, scan_type='tcp', threads=100, timeout=1.0):
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            if scan_type == 'tcp':
                futures = [executor.submit(self.scan_tcp_port, target, port, timeout) for port in ports]
            elif scan_type == 'udp':
                futures = [executor.submit(self.scan_udp_port, target, port, timeout) for port in ports]
            else:
                return open_ports
            
            for future in concurrent.futures.as_completed(futures):
                port, is_open, service = future.result()
                if is_open:
                    open_ports.append((port, service))
                    print(f"[+] {scan_type.upper()} Port {port} ({service}) açık")
        
        return open_ports

    def nmap_service_scan(self, target, ports):
        if not NMAP_AVAILABLE:
            print("[!] Nmap modülü yüklü değil. Servis tespiti yapılamıyor.")
            return []
        
        try:
            port_str = ','.join(map(str, [port for port, _ in ports]))
            scan_result = self.nm.scan(hosts=target, ports=port_str, arguments='-sV -T4')
            
            results = []
            if target in scan_result['scan']:
                for proto in scan_result['scan'][target].all_protocols():
                    for port in scan_result['scan'][target][proto].keys():
                        service_info = scan_result['scan'][target][proto][port]
                        service_name = service_info['name']
                        product = service_info.get('product', '')
                        version = service_info.get('version', '')
                        full_info = f"{service_name} {product} {version}".strip()
                        results.append((port, full_info))
            return results
        except Exception as e:
            print(f"[!] Nmap taraması başarısız: {str(e)}")
            return []

    def check_web_service(self, target, port):
        if not REQUESTS_AVAILABLE:
            return None
            
        protocols = ['http', 'https']
        for protocol in protocols:
            url = f"{protocol}://{target}:{port}"
            try:
                response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
                if response.status_code < 500:
                    server = response.headers.get('Server', 'Unknown')
                    title = "Unknown"
                    if '<title>' in response.text:
                        title_start = response.text.find('<title>') + 7
                        title_end = response.text.find('</title>')
                        if title_end > title_start:
                            title = response.text[title_start:title_end][:50]
                    
                    return {
                        'protocol': protocol,
                        'status': response.status_code,
                        'server': server,
                        'title': title,
                        'url': url
                    }
            except Exception:
                continue
        return None

    def save_to_db(self, target, port, service, version, status):
        cursor = self.db_conn.cursor()
        cursor.execute(
            "INSERT INTO scans (target, port, service, version, status, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (target, port, service, version, status, datetime.now())
        )
        self.db_conn.commit()

    def generate_report(self, target, results, filename='report.txt'):
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Tarama Raporu - {target}\n")
            f.write(f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n\n")
            
            for result in results:
                f.write(f"Port: {result['port']}\n")
                f.write(f"Servis: {result['service']}\n")
                if 'version' in result and result['version']:
                    f.write(f"Versiyon: {result['version']}\n")
                if 'web' in result and result['web']:
                    web = result['web']
                    f.write(f"Web: {web['url']} (Status: {web['status']})\n")
                    f.write(f"Server: {web['server']}\n")
                    f.write(f"Title: {web['title']}\n")
                f.write("-" * 30 + "\n")
        
        return filename

    def run_scan(self, target, ports, scan_type='tcp', threads=100, 
                 service_scan=False, web_scan=False, timeout=1.0, output=None):
        
        if not self.validate_target(target):
            print(f"[!] Geçersiz hedef: {target}")
            return []
        
        try:
            if '-' in ports:
                start_port, end_port = map(int, ports.split('-'))
                port_list = list(range(start_port, end_port + 1))
            else:
                port_list = [int(p.strip()) for p in ports.split(',')]
        except Exception as e:
            print(f"[!] Geçersiz port aralığı: {e}")
            return []
        
        print(f"[*] {target} hedefi için {scan_type.upper()} taraması başlatılıyor...")
        print(f"[*] Port aralığı: {port_list[0]}-{port_list[-1]}")
        print(f"[*] Thread sayısı: {threads}\n")
        
        start_time = time.time()
        open_ports = self.port_scan(target, port_list, scan_type, threads, timeout)
        
        results = []
        if open_ports:
            print(f"\n[*] Detaylı analiz yapılıyor...")
            
            service_results = []
            if service_scan and NMAP_AVAILABLE:
                service_results = self.nmap_service_scan(target, open_ports)
            
            service_dict = dict(service_results)
            
            for port, service in open_ports:
                result = {
                    'port': port, 
                    'service': service,
                    'scan_type': scan_type
                }
                
                if port in service_dict:
                    result['version'] = service_dict[port]
                
                if web_scan and service.lower() in ['http', 'https', 'unknown']:
                    web_info = self.check_web_service(target, port)
                    if web_info:
                        result['web'] = web_info
                
                self.save_to_db(
                    target, port, 
                    result.get('service', ''), 
                    result.get('version', ''), 
                    'open'
                )
                
                results.append(result)
                
                output_str = f"[*] Port {port}: {result['service']}"
                if 'version' in result:
                    output_str += f" | Versiyon: {result['version']}"
                if 'web' in result:
                    output_str += f" | Web: {result['web']['url']}"
                print(output_str)
        
        duration = time.time() - start_time
        print(f"\n[*] Tarama tamamlandı! Süre: {duration:.2f} saniye")
        print(f"[*] Toplam {len(open_ports)} açık port bulundu")
        
        if output:
            report_file = self.generate_report(target, results, output)
            print(f"[*] Rapor oluşturuldu: {report_file}")
        
        return results

if TKINTER_AVAILABLE:
    class ScannerGUI:
        def __init__(self, scanner):
            self.scanner = scanner
            self.window = tk.Tk()
            self.window.title("Gelişmiş Port Tarayıcı")
            self.window.geometry("900x700")
            self.is_scanning = False
            self.scan_thread = None
            
            self.create_widgets()
        
        def create_widgets(self):
            main_frame = ttk.Frame(self.window, padding="10")
            main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            
            ttk.Label(main_frame, text="Hedef IP/Host:").grid(row=0, column=0, sticky=tk.W, pady=5)
            self.target_entry = ttk.Entry(main_frame, width=30)
            self.target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
            self.target_entry.insert(0, "127.0.0.1")
            
            ttk.Label(main_frame, text="Portlar:").grid(row=1, column=0, sticky=tk.W, pady=5)
            self.ports_entry = ttk.Entry(main_frame, width=30)
            self.ports_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
            self.ports_entry.insert(0, "1-1000")
            
            ttk.Label(main_frame, text="Thread Sayısı:").grid(row=2, column=0, sticky=tk.W, pady=5)
            self.threads_entry = ttk.Entry(main_frame, width=30)
            self.threads_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)
            self.threads_entry.insert(0, "100")
            
            ttk.Label(main_frame, text="Timeout (s):").grid(row=3, column=0, sticky=tk.W, pady=5)
            self.timeout_entry = ttk.Entry(main_frame, width=30)
            self.timeout_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5)
            self.timeout_entry.insert(0, "1.0")
            
            scan_type_frame = ttk.LabelFrame(main_frame, text="Tarama Türü", padding="5")
            scan_type_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
            
            self.scan_type = tk.StringVar(value="tcp")
            ttk.Radiobutton(scan_type_frame, text="TCP", variable=self.scan_type, value="tcp").grid(row=0, column=0, sticky=tk.W)
            ttk.Radiobutton(scan_type_frame, text="UDP", variable=self.scan_type, value="udp").grid(row=0, column=1, sticky=tk.W)
            
            options_frame = ttk.LabelFrame(main_frame, text="Seçenekler", padding="5")
            options_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
            
            self.service_scan = tk.BooleanVar()
            ttk.Checkbutton(options_frame, text="Servis Versiyon Tespiti", variable=self.service_scan).grid(row=0, column=0, sticky=tk.W)
            
            self.web_scan = tk.BooleanVar()
            ttk.Checkbutton(options_frame, text="Web Servis Analizi", variable=self.web_scan).grid(row=0, column=1, sticky=tk.W)
            
            ttk.Label(main_frame, text="Çıktı Dosyası:").grid(row=6, column=0, sticky=tk.W, pady=5)
            self.output_entry = ttk.Entry(main_frame, width=30)
            self.output_entry.grid(row=6, column=1, sticky=(tk.W, tk.E), pady=5)
            
            button_frame = ttk.Frame(main_frame)
            button_frame.grid(row=7, column=0, columnspan=2, pady=10)
            
            self.scan_button = ttk.Button(button_frame, text="Taramayı Başlat", command=self.start_scan)
            self.scan_button.grid(row=0, column=0, padx=5)
            
            self.stop_button = ttk.Button(button_frame, text="Durdur", command=self.stop_scan, state=tk.DISABLED)
            self.stop_button.grid(row=0, column=1, padx=5)
            
            ttk.Separator(main_frame, orient=tk.HORIZONTAL).grid(row=8, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
            
            ttk.Label(main_frame, text="Sonuçlar:").grid(row=9, column=0, sticky=tk.W, pady=5)
            
            results_frame = ttk.Frame(main_frame)
            results_frame.grid(row=10, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
            
            self.results_text = tk.Text(results_frame, wrap=tk.WORD, width=80, height=20)
            scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_text.yview)
            self.results_text.configure(yscrollcommand=scrollbar.set)
            
            self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
            
            main_frame.columnconfigure(1, weight=1)
            main_frame.rowconfigure(10, weight=1)
            results_frame.columnconfigure(0, weight=1)
            results_frame.rowconfigure(0, weight=1)
            self.window.columnconfigure(0, weight=1)
            self.window.rowconfigure(0, weight=1)
        
        def start_scan(self):
            if self.is_scanning:
                return
                
            target = self.target_entry.get().strip()
            if not target:
                messagebox.showerror("Hata", "Hedef belirtilmelidir!")
                return
            
            try:
                threads = int(self.threads_entry.get())
                timeout = float(self.timeout_entry.get())
            except ValueError:
                messagebox.showerror("Hata", "Geçersiz thread sayısı veya timeout değeri!")
                return
            
            self.is_scanning = True
            self.scan_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.results_text.delete(1.0, tk.END)
            
            self.scan_thread = threading.Thread(target=self.run_scan_thread, args=(
                target,
                self.ports_entry.get(),
                self.scan_type.get(),
                threads,
                self.service_scan.get(),
                self.web_scan.get(),
                timeout,
                self.output_entry.get() or None
            ))
            self.scan_thread.daemon = True
            self.scan_thread.start()
        
        def run_scan_thread(self, target, ports, scan_type, threads, service_scan, web_scan, timeout, output):
            try:
                results = self.scanner.run_scan(
                    target=target,
                    ports=ports,
                    scan_type=scan_type,
                    threads=threads,
                    service_scan=service_scan,
                    web_scan=web_scan,
                    timeout=timeout,
                    output=output
                )
                
                self.window.after(0, self.scan_completed, results, None)
            except Exception as e:
                self.window.after(0, self.scan_completed, None, str(e))
        
        def scan_completed(self, results, error):
            self.is_scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            
            if error:
                messagebox.showerror("Hata", f"Tarama sırasında hata oluştu:\n{error}")
            elif results:
                self.show_results(results)
                messagebox.showinfo("Başarılı", f"Tarama tamamlandı! {len(results)} açık port bulundu.")
        
        def stop_scan(self):
            if self.is_scanning:
                self.is_scanning = False
                self.scan_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
                self.results_text.insert(tk.END, "\n[!] Tarama kullanıcı tarafından durduruldu\n")
        
        def show_results(self, results):
            self.results_text.insert(tk.END, "TARAMA SONUÇLARI\n")
            self.results_text.insert(tk.END, "=" * 50 + "\n\n")
            
            for result in results:
                line = f"Port: {result['port']} | Servis: {result['service']}"
                
                if 'version' in result and result['version']:
                    line += f" | Versiyon: {result['version']}"
                
                self.results_text.insert(tk.END, line + "\n")
                
                if 'web' in result and result['web']:
                    web_info = result['web']
                    self.results_text.insert(tk.END, f"    Web: {web_info['url']} (Status: {web_info['status']})\n")
                    self.results_text.insert(tk.END, f"    Server: {web_info['server']}\n")
                    self.results_text.insert(tk.END, f"    Title: {web_info['title']}\n")
                
                self.results_text.insert(tk.END, "-" * 50 + "\n")
        
        def run(self):
            self.window.mainloop()

def main():
    parser = argparse.ArgumentParser(description='Gelişmiş Port Tarayıcı')
    parser.add_argument('target', nargs='?', help='Hedef IP veya domain')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port aralığı (örn: 1-1000) veya liste (örn: 80,443)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Thread sayısı')
    parser.add_argument('-T', '--scan-type', choices=['tcp', 'udp'], default='tcp', help='Tarama türü')
    parser.add_argument('-sV', '--service-version', action='store_true', help='Servis versiyon tespiti yap')
    parser.add_argument('-w', '--web-scan', action='store_true', help='Web servis analizi yap')
    parser.add_argument('-o', '--output', help='Sonuçları dosyaya kaydet')
    parser.add_argument('-g', '--gui', action='store_true', help='Grafiksel arayüzü başlat')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout süresi (saniye)')
    
    args = parser.parse_args()
    
    scanner = AdvancedPortScanner()
    scanner.print_banner()
    
    if args.gui or (not args.target and TKINTER_AVAILABLE):
        if not TKINTER_AVAILABLE:
            print("[!] Tkinter kullanılamıyor. GUI modu desteklenmiyor.")
            return
        gui = ScannerGUI(scanner)
        gui.run()
    elif args.target:
        scanner.run_scan(
            target=args.target,
            ports=args.ports,
            scan_type=args.scan_type,
            threads=args.threads,
            service_scan=args.service_version,
            web_scan=args.web_scan,
            timeout=args.timeout,
            output=args.output
        )
    else:
        print("[!] Hedef belirtilmedi. GUI modu için --gui kullanın.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Tarama kullanıcı tarafından durduruldu")
    except Exception as e:
        print(f"\n[!] Beklenmeyen hata: {e}")
