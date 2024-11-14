import argparse
import nmap
import subprocess

def scan_target(targets):
    nm = nmap.PortScanner()
    services_info = []

    for target in targets:
        print(f"Scanning target: {target}...")
        nm.scan(target, arguments='-sV -p- -Pn -T4 -v')
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    service = nm[host][proto][port]['name']
                    version = nm[host][proto][port]['version']
                    product = nm[host][proto][port]['product']
                    if version:
                        services_info.append(f"{product} {version}")
                    else:
                        services_info.append(service)
    return services_info

def search_exploits(services):
    results = {}
    for service in services:
        try:
            output = subprocess.run(['searchsploit', service, '-w'], capture_output=True, text=True)
            if output.stderr:
                print("Error:", output.stderr)
            results[service] = output.stdout.strip()
        except Exception as e:
            results[service] = str(e)
    return results

def load_targets(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

def main():
    parser = argparse.ArgumentParser(description="Scan targets and search for exploits.")
    parser.add_argument('-i', '--ip', help="IP address or subnet to scan")
    parser.add_argument('-f', '--file', help="File containing a list of targets")
    args = parser.parse_args()

    targets = []
    if args.ip:
        targets.append(args.ip)
    if args.file:
        targets.extend(load_targets(args.file))

    if not targets:
        print("No targets specified. Use -i to specify an IP or subnet, or -f for a file with targets.")
        return

    services = scan_target(targets)
    print("Services and versions found:")
    for service in services:
        print(service)

    print("\nSearching for exploits...")
    exploit_results = search_exploits(services)
    for service, exploits in exploit_results.items():
        print(f"\nExploits for {service}:")
        print(exploits)

if __name__ == "__main__":
    main()
