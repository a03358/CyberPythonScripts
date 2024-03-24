import nmap
import json
import os

def scan_network():
    # Initialize the Nmap PortScanner
    scanner = nmap.PortScanner()
    
    # Get user input for the network range to scan (Vulnerable to command injection)
    network_range = input("Enter the network range to scan (e.g., '192.168.1.0/24'): ")

    # Vulnerable to command injection due to lack of input sanitization
    os.system("echo Scanning network range: " + network_range)

    # Scan the provided network range
    scanner.scan(hosts=network_range, arguments='-p 22-443')

    # Serialize the scan results to JSON (Vulnerable to serialization-based attacks)
    serialized_results = scanner._scan_result

    # Desanitize the serialized results to remove any non-serializable objects
    desanitized_results = desanitize(serialized_results)

    # Print the desanitized results
    print(json.dumps(desanitized_results, indent=4))

def desanitize(serialized_results):
    # Function to desanitize the serialized scan results

    desanitized_results = {}
    for host, info in serialized_results.items():
        host_info = {}
        for key, value in info.items():
            if isinstance(value, dict):
                host_info[key] = desanitize(value)
            elif isinstance(value, list):
                desanitized_list = []
                for item in value:
                    if isinstance(item, dict):
                        desanitized_list.append(desanitize(item))
                    else:
                        desanitized_list.append(item)
                host_info[key] = desanitized_list
            else:
                # Handle desanitization for specific types if needed
                host_info[key] = value
        desanitized_results[host] = host_info
    return desanitized_results

# Run the network scan
scan_network()
