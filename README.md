# Python-Port-scanner
A multithreaded port scanner capable of scanning TCP and UDP ports, performing banner grabbing for open TCP ports, and saving results in various formats such as JSON, CSV, Excel, and plain text. It utilizes Python's socket and scapy libraries for network communication and is designed for efficiency, using multiple threads to scan port ranges across one or more target hosts. The script can be customized to scan specific ports or ranges, and provides an interactive prompt for continuous use after completing a scan.

#Key Features:

Scans both TCP and UDP ports.

Performs banner grabbing for open TCP ports.

Multithreaded for fast scanning, leveraging available CPU cores.

Saves scan results in multiple formats: JSON, CSV, Excel, and text.

Interactive mode for re-running scans with new parameters.

# Pre-requsities
pip install snapy==2.5.0

pip install pandas

pip install openpyxl
