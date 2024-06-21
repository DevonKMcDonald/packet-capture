# Network Traffic Capture Script

This Python script captures live network traffic from a specified network interface and saves the captured data to a pcap file. It uses the `scapy` library for packet capture and `psutil` for listing network interfaces.

## Features

- List available network interfaces.
- Select a network interface for packet capture.
- Specify the duration of the packet capture.
- Save captured traffic to a pcap file.

## Requirements

- Python 3.x
- `scapy` library
- `psutil` library

## Installation

1. Ensure you have Python 3 installed on your system.
2. Install the required Python libraries using pip:

    ```sh
    pip install scapy psutil
    ```

## Usage

To run the script, use the following command format:

```sh
sudo python capture_traffic.py -d <duration_in_seconds> -o <output_file>
