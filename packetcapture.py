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
    try:
        sniff(iface=interface, prn=packet_handler, timeout=duration)
    except Exception as e:
        print(f"An error occurred during packet capture: {e}")
        return
    
    # Save the captured packets to a pcap file
    try:
        wrpcap(output_file, packets)
        print(f"Packet capture complete. {len(packets)} packets captured and saved to {output_file}")
    except Exception as e:
        print(f"An error occurred while saving packets to file: {e}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Capture live network traffic and save to a pcap file.")
    parser.add_argument('-i', '--interface', type=str, help='Network interface to capture packets from.')
    parser.add_argument('-d', '--duration', type=int, help='Duration of the capture in seconds.')
    parser.add_argument('-o', '--output', type=str, help='Output pcap file name.')
    
    args = parser.parse_args()

    # List interfaces if not provided
    interfaces = list_interfaces()
    if not args.interface:
        choice = int(input("Select the interface number: "))
        if choice < 0 or choice >= len(interfaces):
            print("Invalid choice. Exiting.")
            return
        args.interface = interfaces[choice]
    
    # Validate network interface
    if args.interface not in interfaces:
        print(f"Error: Interface {args.interface} does not exist.")
        return
    
    # Prompt for duration if not provided
    if not args.duration:
        args.duration = int(input("Enter the capture duration in seconds: "))
    
    # Prompt for output file name if not provided
    if not args.output:
        args.output = input("Enter the output pcap file name (default: capture.pcap): ") or 'capture.pcap'
    
    # Capture traffic
    capture_traffic(args.interface, args.duration, args.output)

if __name__ == "__main__":
    main()
