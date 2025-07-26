from scapy.all import sniff, IP, TCP, UDP

def get_protocol_name(proto_num):
    """Convert protocol number to readable name."""
    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    return proto_map.get(proto_num, f"Other({proto_num})")

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto_num = packet[IP].proto
        proto_name = get_protocol_name(proto_num)
        
        print(f"Src: {ip_src} -> Dst: {ip_dst}, Protocol: {proto_name}")
        
        if TCP in packet:
            print(f"    TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        if UDP in packet:
            print(f"    UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}")

def main():
    # Replace 'eth0' with your actual interface if needed
    sniff(iface="eth0", prn=packet_callback, count=20, store=0)

if __name__ == "__main__":
    main()
