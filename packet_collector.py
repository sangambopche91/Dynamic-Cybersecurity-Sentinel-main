from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime


def process_packet(packet):
    """
    Process one captured network packet.

    This is the first stage of the real V2 live-monitoring pipeline.
    """

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    protocol = packet[IP].proto

    source_port = 0
    destination_port = 0

    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        protocol_name = "tcp"

    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
        protocol_name = "udp"

    else:
        protocol_name = str(protocol)

    packet_size = len(packet)

    print("=" * 70)
    print("LIVE NETWORK PACKET")
    print("=" * 70)
    print("Time:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("Source IP:", source_ip)
    print("Destination IP:", destination_ip)
    print("Protocol:", protocol_name)
    print("Source Port:", source_port)
    print("Destination Port:", destination_port)
    print("Packet Size:", packet_size)
    print()


def start_capture():
    """
    Continuously capture packets from the machine.
    """

    print("=" * 70)
    print("DYNAMIC CYBERSECURITY SENTINEL")
    print("V2 REAL-TIME PACKET COLLECTOR")
    print("=" * 70)

    print("\nStarting real network monitoring...")
    print("Press CTRL+C to stop.\n")

    try:
        sniff(
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\n")
        print("Real-time packet monitoring stopped.")


if __name__ == "__main__":
    start_capture()