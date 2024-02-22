import scapy.all as scapy

def scan(target_ip, port_range):
    ip_packet = scapy.IP(dst=target_ip)
    
    for port in port_range:
        tcp_packet = scapy.TCP(dport=port, flags="S")
        packet = ip_packet / tcp_packet
        response = scapy.sr1(packet, timeout=1, verbose=False)
        
        if response is not None:
            if response.haslayer(scapy.TCP):
                if response[scapy.TCP].flags == 18:
                    print(f"Port {port} is open")
            elif response.haslayer(scapy.ICMP):
                if int(response[scapy.ICMP].type) == 3 and int(response[scapy.ICMP].code) in [1, 2, 3, 9, 10, 13]:
                    print(f"Port {port} is closed")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("target_ip", type=str, help="Target IP address")
    parser.add_argument("port_range", type=str, help="Port range (e.g., '1-100')")
    args = parser.parse_args()
    
    start_port, end_port = map(int, args.port_range.split("-"))
    port_range = range(start_port, end_port + 1)
    
    scan(args.target_ip, port_range)
