import pyshark
import datetime
import collections
from rich.console import Console
from rich.table import Table
import signal
import sys

class NetworkMonitor:
    def __init__(self):
        self.console = Console()
        self.interfaces = {}
        self.target_ip = None
        self.capture = None
        self.packet_count = 0
        self.protocols = collections.defaultdict(int)
        self.activities = []
        self.running = True
        
        # Common ports and their services
        self.service_ports = {
            80: 'HTTP Web',
            443: 'HTTPS Web',
            22: 'SSH',
            3389: 'RDP',
            53: 'DNS',
            25: 'SMTP',
            21: 'FTP',
            445: 'SMB'
        }
        
        signal.signal(signal.SIGINT, self.handle_exit)

    def handle_exit(self, signum, frame):
        self.running = False
        if self.capture:
            self.capture.close()
        self.show_final_report()
        sys.exit(0)

    def detect_interfaces(self):
        self.console.print("[bold blue]Scanning Network Interfaces...[/bold blue]")
        table = Table(title="Network Interfaces")
        table.add_column("ID", style="cyan", justify="center")
        table.add_column("Interface Name", style="green")
        table.add_column("Type", style="yellow")
        table.add_column("Status", style="magenta")
        
        try:
            capture = pyshark.LiveCapture()
            for idx, interface in enumerate(capture.interfaces, 1):
                if 'NPF' in interface:
                    friendly_name = interface.split('}')[1] if '}' in interface else interface
                    interface_type = self.get_interface_type(interface)
                    
                    self.interfaces[idx] = {
                        'name': interface,
                        'friendly_name': friendly_name,
                        'type': interface_type
                    }
                    
                    table.add_row(
                        str(idx),
                        friendly_name or "Network Interface",
                        interface_type,
                        "✓ Active"
                    )
            
            self.console.print(table)
            return bool(self.interfaces)
            
        except Exception as e:
            self.console.print(f"[red]Interface detection error: {str(e)}[/red]")
            return False

    def get_interface_type(self, interface):
        if 'Wi-Fi' in interface:
            return "Wireless"
        elif 'Ethernet' in interface:
            return "Ethernet"
        elif 'Loopback' in interface:
            return "Loopback"
        return "Network Interface"

    def start_capture(self, interface_id):
        try:
            self.capture = pyshark.LiveCapture(
                interface=self.interfaces[interface_id]['name'],
                bpf_filter=f'host {self.target_ip}',
                output_file='capture.pcap'
            )
            
            self.console.print(f"\n[bold green]Network Monitor Started[/bold green]")
            self.console.print(f"Target IP: {self.target_ip}")
            self.console.print(f"Interface: {self.interfaces[interface_id]['friendly_name']}")
            self.console.print("[yellow]Press Ctrl+C to stop monitoring[/yellow]\n")
            
            self.capture.apply_on_packets(self.process_packet)
            
        except Exception as e:
            self.console.print(f"[red]Capture completed: {str(e)}[/red]")
            self.show_final_report()

    def process_packet(self, packet):
        if not self.running:
            return
            
        self.packet_count += 1
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        try:
            protocol = packet.highest_layer
            self.protocols[protocol] += 1
            
            # Detect service based on port
            if hasattr(packet, 'tcp'):
                port = int(packet.tcp.dstport)
                if port in self.service_ports:
                    self.activities.append({
                        'time': timestamp,
                        'service': self.service_ports[port],
                        'protocol': protocol
                    })
            
            self.show_live_stats()
            
        except AttributeError:
            pass

    def show_live_stats(self):
        self.console.clear()
        table = Table(title="Network Activity Monitor")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Packets Captured", str(self.packet_count))
        table.add_row("Active Protocols", str(len(self.protocols)))
        table.add_row("Activities Detected", str(len(self.activities)))
        
        # Show most recent activity if exists
        if self.activities:
            latest = self.activities[-1]
            table.add_row("Latest Activity", f"{latest['service']} ({latest['protocol']})")
        
        self.console.print(table)

    def show_final_report(self):
        self.console.print("\n[bold red]Network Analysis Report[/bold red]")
        
        # Protocol Summary
        protocol_table = Table(title="Protocol Distribution")
        protocol_table.add_column("Protocol", style="cyan")
        protocol_table.add_column("Count", style="green")
        protocol_table.add_column("Percentage", style="yellow")
        
        for protocol, count in sorted(self.protocols.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / self.packet_count * 100) if self.packet_count > 0 else 0
            protocol_table.add_row(protocol, str(count), f"{percentage:.1f}%")
        
        # Activity Summary
        activity_table = Table(title="Detected Activities")
        activity_table.add_column("Time", style="cyan")
        activity_table.add_column("Service", style="yellow")
        activity_table.add_column("Protocol", style="green")
        
        for activity in self.activities[-10:]:  # Show last 10 activities
            activity_table.add_row(
                activity['time'],
                activity['service'],
                activity['protocol']
            )
        
        self.console.print(protocol_table)
        self.console.print(activity_table)

def main():
    monitor = NetworkMonitor()
    
    if monitor.detect_interfaces():
        while True:
            try:
                interface_choice = int(input("\nSelect interface number: "))
                if interface_choice in monitor.interfaces:
                    monitor.target_ip = input("Enter target IP: ")
                    monitor.start_capture(interface_choice)
                    break
                print("Invalid interface selection")
            except ValueError:
                print("Please enter a valid number")
    else:
        print("No network interfaces detected")

if __name__ == "__main__":
    main()
