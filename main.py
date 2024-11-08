import argparse
import time
from scapy.all import IP, TCP, sr1

def parse_arguments():
    parser = argparse.ArgumentParser(description="TCP SYN Port Scanner")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--start", type=int, help="Start of port range", default=1)
    parser.add_argument("--end", type=int, help="End of port range", default=65535)
    parser.add_argument("--delay", type=int, help="Delay between scans (in milliseconds)", default=0)
    return parser.parse_args()