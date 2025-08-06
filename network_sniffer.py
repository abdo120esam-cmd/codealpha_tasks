# Developed by Abdelrhman Essam Saad Zghloul
from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        proto = packet[IP].proto
        src = ip_layer.src
        dst = ip_layer.dst
        protocol = None
        payload = None
        if packet.haslayer(TCP):
            protocol = "TCP"
            payload = bytes(packet[TCP].payload)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            payload = bytes(packet[UDP].payload)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            payload = bytes(packet[ICMP].payload)
        else:
            protocol = str(proto)
            payload = bytes(packet.payload)

        print(f"[{protocol}] {src} → {dst} | Size: {len(packet)} bytes")
        print(f"Payload (first 50 bytes): {payload[:50]}")
        print("-" * 60)

def main():
    print("Starting packet sniffer... (press Ctrl‑C to stop)")
    sniff(prn=process_packet, store=0)

if __name__ == "__main__":
    main()
