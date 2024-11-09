import argparse
import time
from scapy.all import IP, TCP, sr1
from sympy.core.random import verify_numerically


def parse_arguments():
    parser = argparse.ArgumentParser(description="TCP SYN Port Scanner")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--start", type=int, help="Start of port range", default=1)
    parser.add_argument("--end", type=int, help="End of port range", default=65535)
    parser.add_argument("--delay", type=int, help="Delay between scans (in milliseconds)", default=0)
    return parser.parse_args()

def scan_port(target, port, delay):
    #construct packets to be sent to each port
    packet = IP(dst=target)/TCP(dport=port, flags="S")
    response = sr1(packet, timeout=1, verbose=0) # Timeout 1 for scapy waiting 1 second. Verbose=0 for no logs.

    # Decipher response to decide port status.
    if response:
        if response.haslayer(TCP):
            if response[TCP].flags == "SA": # SYN-ACK response means open port.
                print(f"Port {port} is open")
            elif response[TCP].flags == "RA": # RST response means port is closed.
                print(f"Port {port} is closed")
        elif response.haslayer(ICMP):
            print(f"Port {port} is filtered ICMP packet received")

    else:
        print("Port is filtered no response")


    # Apply delay if there is one
    if delay > 0:
        time.sleep(delay / 1000) # Converts milliseconds to seconds

