import sys
import socket
import threading
import os
import time
import platform
from scapy.all import sr1, IP, UDP, ICMP

# Function to scan a range of ports using TCP
def scan_tcp_ports(target_ip, ports, results):
    try:
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                service = get_service_name(port, 'tcp')
                banner = grab_banner(s)
                results.append((port, "Open", service, banner))  # Include port state and banner in the result tuple
            s.close()
    except KeyboardInterrupt:
        print("TCP Scan interrupted by user.")
        sys.exit()
    except socket.gaierror:
        print("Hostname could not be resolved.")
        sys.exit()
    except socket.error:
        print("Couldn't connect to server.")
        sys.exit()

# Function to perform banner grabbing (TCP only)
def grab_banner(s):
    try:
        # Receive up to 1024 bytes of data from the socket
        banner = s.recv(1024)
        return banner.decode().strip('\n').strip('\r').splitlines()[0]  # Only return the first line
    except:
        return "Unknown"

# Function to scan a range of ports using UDP
def scan_udp_ports(target_ip, ports, results):
    try:
        for port in ports:
            response = sr1(IP(dst=target_ip)/UDP(dport=port), timeout=2, verbose=False)
            if response is None:
                results.append((port, "Closed"))
            elif UDP in response:
                results.append((port, "Open"))
            elif ICMP in response:
                if response[ICMP].type == 3 and response[ICMP].code in [1, 2, 3, 9, 10, 13]:
                    results.append((port, "Filtered"))
                else:
                    results.append((port, "Closed"))
    except KeyboardInterrupt:
        print("\nUDP Scan interrupted by user.")
        sys.exit()

# Function to get service name for a port
def get_service_name(port, protocol):
    try:
        service_name = socket.getservbyport(port, protocol)
        return service_name
    except OSError:
        return "Unknown"

while True:
    # Check if the correct number of arguments is provided
    if len(sys.argv) != 4:
        print("Usage: python port_scanner.py <hostname> <port_range or ports> <-tcp or -udp>")
        sys.exit()

    # Parse command-line arguments
    hostname = sys.argv[1]
    ports_arg = sys.argv[2]
    protocol = sys.argv[3]

    # Check protocol argument
    if protocol not in ['-tcp', '-udp']:
        print("Invalid protocol argument. Use '-tcp' or '-udp'.")
        sys.exit()

    # Check if the argument is a range or individual ports
    if '-' in ports_arg:
        start_port, end_port = map(int, ports_arg.split('-'))
        ports = range(start_port, end_port + 1)
    else:
        ports = [int(port) for port in ports_arg.split(',')]  # Convert comma-separated ports to a list of integers

    # Get the number of threads (logical CPUs)
    num_threads = os.cpu_count() or 1  # If cpu_count() returns None, use 1 thread
    print("Number of threads is: ", num_threads)

    start_time = time.time()

    # Create and start threads
    threads = []
    results = []
    try:
        if protocol == '-tcp':
            scan_function = scan_tcp_ports
            print("Port\tState\tService\tBanner")
            print("----\t-----\t-------\t------")
        elif protocol == '-udp':
            scan_function = scan_udp_ports
            print("Port\tState")
            print("----\t-----")
        else:
            print("Unknown Protocol")
            
        for i in range(num_threads):
            thread_ports = ports[i::num_threads]  # Distribute ports evenly among threads
            thread = threading.Thread(target=scan_function, args=(hostname, thread_ports, results))
            threads.append(thread)
            thread.start()

        # Wait for all threads to finish
        for thread in threads:
            thread.join()

        # Display the results with port state and service detection
        for result in sorted(results):
            if protocol == '-tcp':
                port, state, service, banner = result
                print(f"{port}\t{state}\t{service}\t{banner}")
            else:
                port, state = result
                print(f"{port}\t{state}")

        # Calculate time taken
        end_time = time.time()
        time_taken = end_time - start_time
        print(f"\nTime taken to complete: {time_taken:.2f} seconds")

        # Prompt for input again
        print("\nPress Ctrl+C to interrupt or provide new arguments.\n")
        try:
            # Get new arguments
            sys.argv = input("Enter arguments (e.g., <hostname> <port_range or ports> <-tcp or -udp>): ").split()
        except KeyboardInterrupt:
            print("\nExiting program.")
            sys.exit()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit()