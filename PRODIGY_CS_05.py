from scapy.all import sniff

def analyze_packet(packet):
    # Check if packet has IP layer (to filter non-IP packets)
    if packet.haslayer("IP"):
        # Extract source and destination IP addresses, and protocol
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        protocol = packet["IP"].proto

        # Extract payload data (if any)
        payload = packet.payload

        # Print captured packet information
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload}\n")

# Set up packet sniffing (no need for the socket argument)
print("Starting the packet sniffer...")
sniff(prn=analyze_packet, store=0)
