#!/usr/bin/python3
import nmap
import re
import json

scanner = nmap.PortScanner()


def ip_scan():
    ip_addr = input("Enter the IP address you want to scan:")
    ip_format = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$') #regular expression for ip addresses 
    #ip_or_subnet_format = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/(\d{1,2}))?$')
    while not ip_format.match(ip_addr):
       print(f"OOps....! Invalid IP")
       ip_addr = input("Enter the IP address you want to scan:")
    ipscan_results = scanner.scan(ip_addr, arguments= '-A -sV -O -p- -v')
    ipscanJ_results = json.dumps(ipscan_results, indent=4)
    ipjsonload = json.loads(ipscanJ_results)
    scan_data = ipjsonload.get("scan", {})
    
    for ip, details in scan_data.items():
      print(f"IP Address: {ip}")
      print(f"\nHostnames: {details.get('hostnames', [])}")
      print(f"\nAddresses: {details.get('addresses', [])}")
      print(f"\nStatus: {details.get('status', [])}")
      tcp_port = details.get('tcp', {})
      if tcp_port:
         print("TCP Ports Details:")
         for port, port_details in tcp_port.items():
            print(f"\n Port: {'port', 'N/A'}")
            print(f"\n   State: {port_details.get('state', 'N/A')}")
            print(f"\n   Reason: {port_details.get('reason', 'N/A')}")
            print(f"\n   Name: {port_details.get('name', 'N/A')}")
            print(f"\n   Product: {port_details.get('product', 'N/A')}")
            print(f"\n   Version: {port_details.get('version', 'N/A')}")
            print(f"\n   Extra Info: {port_details.get('extrainfo', 'N/A')}")
            print(f"\n   Conf: {port_details.get('conf', 'N/A')}")
            print(f"\n   CPE: {port_details.get('cpe', 'N/A')}")
            if 'script' in port_details:
                print("    Script Information:")
                for script_name, script_value in port_details['script'].items():
                    print(f"      {script_name}: {script_value}")
                else:
                    print("TCP Ports: None")
                    print()
    
      print()


#domain scanner function
def domain_scan():
    domain = input("Enter the Domain you want to scan:")
    domain_format = domain_format = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?:[A-Za-z0-9-]{1,63}\.)*[A-Za-z]{2,}$')
    while not domain_format.match(domain):
        print(f"OOps....! Invalid Domain")
        domain = input("Enter the Domain you want to scan:")
    domainscan_results = scanner.scan(domain, arguments= '-A -sV -O -p- -v')
    domainscanJ_results = json.dumps(domainscan_results, indent=4)
    domainjsonload = json.loads(domainscanJ_results)
    scan_data = domainjsonload.get("scan", {})
    
    for ip, details in scan_data.items():
      print(f"\n IP Address: {ip}")
      print(f"\n Hostnames: {details.get('hostnames', 'N/A')}")
      print(f"\n Addresses: {details.get('addresses', 'N/A')}")
      print(f"\n Status: {details.get('status', 'N/A')}")
      tcp_port = details.get('tcp', {})
      if tcp_port:
         print("TCP Ports Details:")
         for port, port_details in tcp_port.items():
            print(f"\n Port: {'port', 'N/A'}")
            print(f"\n   State: {port_details.get('state', 'N/A')}")
            print(f"\n   Reason: {port_details.get('reason', 'N/A')}")
            print(f"\n   Name: {port_details.get('name', 'N/A')}")
            print(f"\n   Product: {port_details.get('product', 'N/A')}")
            print(f"\n   Version: {port_details.get('version', 'N/A')}")
            print(f"\n   Extra Info: {port_details.get('extrainfo', 'N/A')}")
            print(f"\n   Conf: {port_details.get('conf', 'N/A')}")
            print(f"\n   CPE: {port_details.get('cpe', 'N/A')}")
            if 'script' in port_details:
                print("    Script Information:")
                for script_name, script_value in port_details['script'].items():
                    print(f"      {script_name}: {script_value}")
                else:
                    print("TCP Ports: None")
                    print()
    
      print()
while True:
    ip_or_domain = input("Enter 0 for IP scan or 1 for domain scan:")
    if ip_or_domain == '0':
       ipscanresults = ip_scan()
       print(ipscanresults)
       break
    elif ip_or_domain == '1':
       domainscanresult =domain_scan()
       print(domainscanresult)
       break
    else:
       print("Invalid Input! Enter 0 for IP scan or 1 for domain scan:")
