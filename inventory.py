#!/usr/bin/env python

import nmap
import json
import sys

def scan_network(network_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=network_range, arguments='-sn')
    hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up']
    return hosts

def generate_inventory(hosts):
    inventory = {
        "all": {
            "hosts": hosts,
            "vars": {}
        }
    }
    return inventory

def main():

    network_range = "192.168.1.0/24"
    hosts = scan_network(network_range)
    inventory = generate_inventory(hosts)
    print(json.dumps(inventory, indent=2))

if __name__ == "__main__":
    main()
