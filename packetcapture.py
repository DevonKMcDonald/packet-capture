import time
from scapy.all import sniff, wrpcap
import argparse
import psutil

def list_interfaces():
    # Function to list available network interfaces for user to choose from
    interfaces = psutil.net_if_addrs()
    print("Available network interfaces:")
    for idx, interface in enumerate(interfaces.keys()):
        print(f"{idx}: {interface}")
    return list(interfaces.keys())

def capture_traffic(interface, duration, output_file):
    # Function to append captured packets to a list
    packets = []

    def packet_handler(packet):
        packets.append(packet)
        print(f"Captured packet: {packet.summary()}")

    # Start sniffing on the specified interface
    print(f"Starting packet capture on interface {interface} for {duration} seconds...")
    sniff(iface=interface, prn=packet_handler, timeout=duration)
    
    # Save the captured packets to a pcap file
    wrpcap(output_file, packets)
    print(f"Packet capture complete. {len(packets)} packets captured and saved to {output_file}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Capture live network traffic and save to a pcap file.")
    parser.add_argument('-i', '--interface', type=str, help='Network interface to capture packets from.')
    parser.add_argument('-d', '--duration', type=int, required=True, help='Duration of the capture in seconds.')
    parser.add_argument('-o', '--output', type=str, default='capture.pcap', help='Output pcap file name (default: capture.pcap).')
    
    args = parser.parse_args()

    # List interfaces if not provided
    if not args.interface:
        interfaces = list_interfaces()
        choice = int(input("Select the interface number: "))
        if choice < 0 or choice >= len(interfaces):
            print("Invalid choice. Exiting.")
            return
        args.interface = interfaces[choice]
    
    # Validate network interface
    interfaces = list_interfaces()
    if args.interface not in interfaces:
        print(f"Error: Interface {args.interface} does not exist.")
        return
    
    # Capture traffic
    capture_traffic(args.interface, args.duration, args.output)

if __name__ == "__main__":
    main()
