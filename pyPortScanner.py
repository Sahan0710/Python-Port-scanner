import sys
import socket
import threading
import os
import time
import platform
import json
import csv
import pandas as pd
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
                results.append((target_ip, port, "Open", service, banner))  # Include target IP, port state, and banner in the result tuple
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
                results.append((target_ip, port, "Closed", "Unknown"))
            elif UDP in response:
                service = get_service_name(port, 'udp')
                results.append((target_ip, port, "Open", service))
            elif ICMP in response:
                if response[ICMP].type == 3 and response[ICMP].code in [1, 2, 3, 9, 10, 13]:
                    results.append((target_ip, port, "Filtered", "Unknown"))
                else:
                    results.append((target_ip, port, "Closed", "Unknown"))
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

# Function to save results to different formats
def save_results(results, output_format):
    if output_format == "json":
        with open("scan_results.json", "w") as f:
            json.dump(results, f, indent=4)
        print("Results saved to 'scan_results.json'.")
    elif output_format == "csv":
        with open("scan_results.csv", "w", newline="") as f:
            if results and len(results[0]) == 5:  # TCP results
                writer = csv.writer(f)
                writer.writerow(["Hostname", "Port", "State", "Service", "Banner"])
                writer.writerows(results)
            elif results and len(results[0]) == 4:  # UDP results
                writer = csv.writer(f)
                writer.writerow(["Hostname", "Port", "State", "Service"])
                writer.writerows(results)
        print("Results saved to 'scan_results.csv'.")
    elif output_format == "excel":
        if results and len(results[0]) == 5:  # TCP results
            df = pd.DataFrame(results, columns=["Hostname", "Port", "State", "Service", "Banner"])
        elif results and len(results[0]) == 4:  # UDP results
            df = pd.DataFrame(results, columns=["Hostname", "Port", "State", "Service"])
        df.to_excel("scan_results.xlsx", index=False)
        print("Results saved to 'scan_results.xlsx'.")
    elif output_format == "text":
        with open("scan_results.txt", "w") as f:
            if results and len(results[0]) == 5:  # TCP results
                f.write("Hostname\tPort\tState\tService\tBanner\n")  # Write title as header row
                for result in results:
                    f.write("\t".join(map(str, result)) + "\n")  # Write each result as tab-separated values
            elif results and len(results[0]) == 4:  # UDP results
                f.write("Hostname\tPort\tState\tService\n")  # Write title as header row
                for result in results:
                    f.write("\t".join(map(str, result)) + "\n")  # Write each result as tab-separated values
        print("Results saved to 'scan_results.txt'.")
    else:
        print("Invalid output format.")

while True:
    # Check if the correct number of arguments is provided
    if len(sys.argv) < 4 or len(sys.argv) > 6:
        print("Usage: python port_scanner.py <hostname(s)> <port_range or ports> <-tcp or -udp> [-o output_format]")
        sys.exit()

    # Parse command-line arguments
    hostnames = sys.argv[1].split(',')
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

    # Print titles for the scan
    if protocol == '-tcp':
        print("\nScanning TCP ports:")
        print("Hostname\tPort\tState\tService\tBanner")
        print("--------\t----\t-----\t-------\t------")
    elif protocol == '-udp':
        print("\nScanning UDP ports:")
        print("Hostname\tPort\tState\tService")
        print("--------\t----\t-----\t-------")
    else:
        print("Unknown Protocol")

    # Create and start threads for each hostname
    threads = []
    results = []
    try:
        for hostname in hostnames:
            if protocol == '-tcp':
                scan_function = scan_tcp_ports
            elif protocol == '-udp':
                scan_function = scan_udp_ports
            else:
                print("Unknown Protocol")
                continue
            
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
                target_ip, port, state, service, banner = result
                print(f"{target_ip}\t{port}\t{state}\t{service}\t{banner}")
            else:
                target_ip, port, state, service = result
                print(f"{target_ip}\t{port}\t{state}\t{service}")

        # Check if optional output format argument is provided
        if len(sys.argv) == 6 and (sys.argv[4] == "-o" or sys.argv[4] == "--output"):
            output_format = sys.argv[5]
            # Save results to the specified output format
            save_results(results, output_format)

        # Calculate time taken
        end_time = time.time()
        time_taken = end_time - start_time
        print(f"\nTime taken to complete: {time_taken:.2f} seconds")

        # Prompt for input again
        print("\nPress Ctrl+C to interrupt or provide new arguments.\n")
        try:
            # Get new arguments
            sys.argv = input("Enter arguments (e.g., <hostname(s)> <port_range or ports> <-tcp or -udp> [-o output_format]): ").split()
        except KeyboardInterrupt:
            print("\nExiting program.")
            sys.exit()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit()
