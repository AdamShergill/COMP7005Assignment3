import argparse
import time
import socket
from scapy.all import IP, TCP, ICMP, sr1



def is_valid_ip(ip):
    """Check if the provided IP address is valid."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


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
        print(f"Port {port} is filtered (no response)")



    # Apply delay if there is one
    if delay > 0:
        time.sleep(delay / 1000) # Converts milliseconds to seconds

def main():
    args = parse_arguments()
    target = args.target
    start_port = args.start
    end_port = args.end
    delay = args.delay

    # Validate IP address
    if not is_valid_ip(target):
        print(f"Error: '{target}' is not a valid IP address.")
        return

     # Validate port range
    if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
        print("Error: Port numbers must be in the range 1-65535.")
        return
    if start_port > end_port:
        print("Error: Start port must be less than or equal to end port.")
        return

    print(f"Starting scan on {target} from port {start_port} to port {end_port} with {delay}ms delay between each scan")

    #Loop over all the ports from start to end.

    for port in range(start_port, end_port + 1):
        scan_port(target, port, delay)

if __name__ == "__main__":
    main()