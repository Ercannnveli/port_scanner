#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#KODUN ÇALIŞMASI İÇİN ÖRNEK python "port tarama.py" -t 192.168.1.1 

import socket
import threading
import time
import sys
import argparse
import ipaddress
import json
import csv
import os
from datetime import datetime
from queue import Queue
from colorama import init, Fore, Style

# Colorama başlatma
init()

class PortScanner:
    """Gelişmiş Port Tarama Aracı"""
    
    def __init__(self):
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.start_time = None
        self.end_time = None
        self.target = None
        self.ip = None
        self.threads = []
        self.port_queue = Queue()
        self.thread_count = 200  # Varsayılan iş parçacığı sayısı
        self.timeout = 1.0  # Varsayılan zaman aşımı (saniye)
        self.verbose = False
        self.scan_type = "TCP"  # Varsayılan tarama türü
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
            80: "HTTP", 110: "POP3", 115: "SFTP", 135: "MSRPC",
            139: "NetBIOS", 143: "IMAP", 194: "IRC", 443: "HTTPS", 
            445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy"
        }
        # Servis algılama seçeneği
        self.service_detection = False
        # Sonuçları saklamak için
        self.results = {}
    
    def banner(self):
        """Program başlığını göster"""
        banner_text = f"""
{Fore.CYAN}┌─────────────────────────────────────┐
│ {Fore.WHITE}Gelişmiş Python Port Tarama Aracı{Fore.CYAN}    │
├─────────────────────────────────────┤
│ {Fore.GREEN}Versiyon: 1.0{Fore.CYAN}                       │
└─────────────────────────────────────┘{Style.RESET_ALL}
        """
        print(banner_text)
    
    def parse_arguments(self):
        """Komut satırı argümanlarını ayrıştır"""
        parser = argparse.ArgumentParser(description="Gelişmiş Python Port Tarama Aracı")
        parser.add_argument('-t', '--target', required=True, help='Hedef IP adresi veya alan adı')
        parser.add_argument('-p', '--ports', default='1-1000', help='Taranacak portlar (örn: 80,443,8080 veya 1-1000)')
        parser.add_argument('-T', '--threads', type=int, default=200, help='İş parçacığı sayısı (varsayılan: 200)')
        parser.add_argument('-s', '--scan-type', choices=['TCP', 'SYN', 'UDP'], default='TCP', help='Tarama türü (varsayılan: TCP)')
        parser.add_argument('-to', '--timeout', type=float, default=1.0, help='Bağlantı zaman aşımı süresi (varsayılan: 1.0 saniye)')
        parser.add_argument('-v', '--verbose', action='store_true', help='Detaylı çıktı göster')
        parser.add_argument('-o', '--output', help='Sonuçları dosyaya kaydet (desteklenen formatlar: json, csv, txt)')
        parser.add_argument('-sd', '--service-detection', action='store_true', help='Servis tespiti yap')
        
        args = parser.parse_args()
        
        self.target = args.target
        self.thread_count = args.threads
        self.timeout = args.timeout
        self.verbose = args.verbose
        self.scan_type = args.scan_type
        self.output_file = args.output
        self.service_detection = args.service_detection
        
        # Port aralığını ayarla
        self.ports = self.parse_port_range(args.ports)
        
        # IP adresini kontrol et
        try:
            self.ip = socket.gethostbyname(self.target)
        except socket.gaierror:
            print(f"{Fore.RED}Hata: Geçersiz hedef adresi.{Style.RESET_ALL}")
            sys.exit(1)
    
    def parse_port_range(self, port_arg):
        """Port aralığını ayrıştır"""
        ports = []
        
        # Özel durumlar için
        if port_arg.lower() == 'all':
            return list(range(1, 65536))
        elif port_arg.lower() == 'common':
            return list(self.common_ports.keys())
        
        # Virgülle ayrılmış portlar ve aralıklar
        for item in port_arg.split(','):
            if '-' in item:
                start, end = map(int, item.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(item))
        
        return sorted(list(set(ports)))  # Tekrarları kaldır ve sırala
    
    def get_service_name(self, port):
        """Belirli bir portun servis adını döndür"""
        return self.common_ports.get(port, "Unknown")
    
    def detect_service(self, ip, port):
        """Çalışan servisi tespit etmeye çalış"""
        if not self.service_detection:
            return self.get_service_name(port)
            
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip, port))
            
            # Banner almaya çalış
            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                s.close()
                if banner:
                    return f"{self.get_service_name(port)} ({banner.splitlines()[0] if banner.splitlines() else 'Banner alındı'})"
            except:
                s.close()
                return self.get_service_name(port)
        except:
            return self.get_service_name(port)
    
    def scan_port(self, ip, port):
        """Belirtilen portu tara"""
        try:
            if self.scan_type == "TCP":
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                result = s.connect_ex((ip, port))
                s.close()
                
                if result == 0:
                    service = self.detect_service(ip, port) if self.service_detection else self.get_service_name(port)
                    self.open_ports.append((port, service))
                    if self.verbose:
                        self.print_port_status(port, "açık", service)
                else:
                    self.closed_ports.append(port)
                    if self.verbose:
                        self.print_port_status(port, "kapalı", self.get_service_name(port))
                
            elif self.scan_type == "UDP":
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(self.timeout)
                s.sendto(b"", (ip, port))
                
                try:
                    _, _ = s.recvfrom(1024)
                    self.open_ports.append((port, self.get_service_name(port)))
                    if self.verbose:
                        self.print_port_status(port, "açık", self.get_service_name(port))
                except socket.timeout:
                    self.filtered_ports.append(port)
                    if self.verbose:
                        self.print_port_status(port, "filtrelenmiş", self.get_service_name(port))
                except:
                    self.closed_ports.append(port)
                    if self.verbose:
                        self.print_port_status(port, "kapalı", self.get_service_name(port))
                
                s.close()
                
            elif self.scan_type == "SYN":
                # Not: SYN tarama, root izni gerektirdiğinden basitleştirilmiş simülasyon
                print(f"{Fore.YELLOW}Uyarı: SYN tarama için root izni gerekli. TCP tarama kullanılıyor.{Style.RESET_ALL}")
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                result = s.connect_ex((ip, port))
                s.close()
                
                if result == 0:
                    self.open_ports.append((port, self.get_service_name(port)))
                    if self.verbose:
                        self.print_port_status(port, "açık", self.get_service_name(port))
                else:
                    self.closed_ports.append(port)
                    if self.verbose:
                        self.print_port_status(port, "kapalı", self.get_service_name(port))
                
        except KeyboardInterrupt:
            print(f"{Fore.RED}Tarama kullanıcı tarafından iptal edildi.{Style.RESET_ALL}")
            sys.exit(1)
        except socket.error:
            self.filtered_ports.append(port)
            if self.verbose:
                self.print_port_status(port, "filtrelenmiş", self.get_service_name(port))
    
    def print_port_status(self, port, status, service):
        """Port durumunu renkli olarak yazdır"""
        status_color = {
            "açık": Fore.GREEN,
            "kapalı": Fore.RED,
            "filtrelenmiş": Fore.YELLOW
        }
        
        print(f"Port {port}/tcp: {status_color.get(status, Fore.WHITE)}{status}{Style.RESET_ALL} - {service}")
    
    def worker(self):
        """İş parçacığı çalışanı"""
        while not self.port_queue.empty():
            port = self.port_queue.get()
            self.scan_port(self.ip, port)
            self.port_queue.task_done()
    
    def progress_bar(self, total_ports):
        """İlerleme çubuğu göster"""
        total = len(total_ports)
        width = 50
        
        while not self.port_queue.empty():
            completed = total - self.port_queue.qsize()
            percent = completed * 100 // total
            bar_length = width * completed // total
            
            bar = '█' * bar_length + ' ' * (width - bar_length)
            
            sys.stdout.write(f"\r{Fore.CYAN}İlerleme: [{bar}] {percent}% Tamamlandı ({completed}/{total}){Style.RESET_ALL}")
            sys.stdout.flush()
            
            time.sleep(0.1)
        
        sys.stdout.write(f"\r{Fore.GREEN}İlerleme: [{'█' * width}] 100% Tamamlandı ({total}/{total}){Style.RESET_ALL}\n")
        sys.stdout.flush()
    
    def run_scan(self):
        """Taramayı çalıştır"""
        self.banner()
        
        print(f"{Fore.CYAN}[*] Hedef: {self.target} ({self.ip}){Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Tarama başlangıç zamanı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Tarama türü: {self.scan_type}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Taranacak port sayısı: {len(self.ports)}{Style.RESET_ALL}")
        
        self.start_time = time.time()
        
        # Port kuyruğunu doldur
        for port in self.ports:
            self.port_queue.put(port)
        
        # İlerleme çubuğunu göster
        if not self.verbose:
            progress_thread = threading.Thread(target=self.progress_bar, args=(self.ports,))
            progress_thread.daemon = True
            progress_thread.start()
        
        # İş parçacıklarını başlat
        thread_count = min(self.thread_count, len(self.ports))
        for _ in range(thread_count):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True
            self.threads.append(thread)
            thread.start()
        
        # İş parçacıklarının tamamlanmasını bekle
        for thread in self.threads:
            thread.join()
        
        self.end_time = time.time()
        self.display_results()
        
        if self.output_file:
            self.save_results()
    
    def display_results(self):
        """Tarama sonuçlarını görüntüle"""
        scan_time = self.end_time - self.start_time
        
        print("\n" + "=" * 60)
        print(f"{Fore.CYAN}Tarama Sonuçları:{Style.RESET_ALL}")
        print("=" * 60)
        
        print(f"\n{Fore.CYAN}Hedef:{Style.RESET_ALL} {self.target} ({self.ip})")
        print(f"{Fore.CYAN}Tarama türü:{Style.RESET_ALL} {self.scan_type}")
        print(f"{Fore.CYAN}Tarama süresi:{Style.RESET_ALL} {scan_time:.2f} saniye")
        
        print(f"\n{Fore.GREEN}Açık portlar ({len(self.open_ports)}):{Style.RESET_ALL}")
        if self.open_ports:
            # Tablo başlığı
            print(f"\n{Fore.CYAN}{'PORT':<10}{'DURUM':<15}{'SERVİS':<20}{Style.RESET_ALL}")
            print("-" * 45)
            
            for port, service in sorted(self.open_ports):
                print(f"{port:<10}{'açık':<15}{service:<20}")
        else:
            print("Açık port bulunamadı.")
        
        # Sonuçları results sözlüğünde sakla
        self.results = {
            "target": self.target,
            "ip": self.ip,
            "scan_type": self.scan_type,
            "scan_time": f"{scan_time:.2f}",
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "open_ports": [{"port": p, "service": s} for p, s in self.open_ports],
            "total_ports_scanned": len(self.ports)
        }
    
    def save_results(self):
        """Sonuçları dosyaya kaydet"""
        filename = self.output_file
        
        # Uzantıya göre uygun formatı belirle
        if not any(filename.endswith(ext) for ext in ['.json', '.csv', '.txt']):
            filename += '.txt'  # Varsayılan format
        
        try:
            if filename.endswith('.json'):
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=4)
            
            elif filename.endswith('.csv'):
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Port', 'Durum', 'Servis'])
                    for port, service in self.open_ports:
                        writer.writerow([port, 'açık', service])
            
            else:  # .txt dosyası
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Tarama Sonuçları\n")
                    f.write(f"===============\n\n")
                    f.write(f"Hedef: {self.target} ({self.ip})\n")
                    f.write(f"Tarama türü: {self.scan_type}\n")
                    f.write(f"Tarama süresi: {self.results['scan_time']} saniye\n")
                    f.write(f"Tarama zamanı: {self.results['timestamp']}\n\n")
                    
                    f.write(f"Açık portlar ({len(self.open_ports)}):\n")
                    f.write(f"{'PORT':<10}{'DURUM':<15}{'SERVİS':<20}\n")
                    f.write("-" * 45 + "\n")
                    
                    for port, service in sorted(self.open_ports):
                        f.write(f"{port:<10}{'açık':<15}{service:<20}\n")
            
            print(f"\n{Fore.GREEN}Sonuçlar başarıyla kaydedildi: {filename}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"\n{Fore.RED}Sonuçlar kaydedilirken hata oluştu: {str(e)}{Style.RESET_ALL}")


def main():
    """Ana fonksiyon"""
    try:
        scanner = PortScanner()
        scanner.parse_arguments()
        scanner.run_scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Tarama kullanıcı tarafından iptal edildi.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}Hata: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()