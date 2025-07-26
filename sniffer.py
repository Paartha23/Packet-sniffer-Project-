from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        print(f"Src: {ip_src} -> Dst: {ip_dst}, Proto: {proto}")
        if TCP in packet:
            print(f"TCP Sport: {packet[TCP].sport} -> Dport: {packet[TCP].dport}")
        if UDP in packet:
            print(f"UDP Sport: {packet[UDP].sport} -> Dport: {packet[UDP].dport}")

def main():
    # Replace 'eth0' below with your interface (e.g., 'wlan0', 'enp0s3')
    sniff(iface="eth0", prn=packet_callback, count=20, store=0)

if __name__ == "__main__":
    main()

