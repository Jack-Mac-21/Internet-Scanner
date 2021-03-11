# This is my networking project 4
# Take an input file and return a out txt file

import sys
import os
import subprocess
import time
import json
import http.client




# Scanner takes a list of websites
class Scanner:
    def __init__(self, input_txt):
        self.websites = input_txt
        self.output = {}
        self.dns_resolvers = self.initialize_resolvers()  # List of all public DNS resolvers (hard coded in)

    def initialize_resolvers(self):
        dns_resolvers = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26",  "9.9.9.9",
                         "64.6.65.6", "91.239.100.100", "185.228.168.168", "77.88.8.7",
                         "156.154.70.1", "198.101.242.72", "176.103.130.130"]
        return dns_resolvers

    def scan(self):
        self.add_scan_time()
        self.add_server()
        self.add_ip6()
        self.add_ip4()



        json_dict = json.dumps(self.output, sort_keys=True, indent=4)
        print(json_dict)

    def add_scan_time(self):  # Acts to initialize the dictionary, with sites as keys and dict with scan time as value
        for site in self.websites:
            key = site
            value = {"scan-time": time.time()}
            self.output.update({key: value})

    def add_ip4(self):  # adds the ip4 address to each sites dictionary
        for site in self.websites:
            site_dict = self.output.get(site)
            key = "ipv4_addresses"
            address_list = []

            for resolver in self.dns_resolvers:
                try:
                    command_result = subprocess.check_output(["nslookup", "-type=A", site, resolver],
                                                             timeout=1, stderr=subprocess.STDOUT).decode("utf-8")
                except:
                    command_result = "Error occurred"

                if command_result != "Error occurred":
                    command_result = command_result.splitlines(True)
                    for string in command_result:
                        if string[0] == "A" and string != command_result[1]:
                            string = string[9:].rstrip()
                            if string not in address_list and string != "":
                                string = string.rstrip()
                                address_list.append(string)

            site_dict.update({key: address_list})
            self.output.update({site: site_dict})

    def add_ip6(self):  # adds the ip6 address to each sites dictionary, identical to ip4 implementation
        for site in self.websites:
            site_dict = self.output.get(site)
            key = "ipv6_addresses"
            address_list = []

            for resolver in self.dns_resolvers:
                try:
                    command_result = subprocess.check_output(["nslookup", "-type=AAAA", site, resolver],
                                                             timeout=1, stderr=subprocess.STDOUT).decode("utf-8")
                except:
                    command_result = "Error occurred"

                if command_result != "Error occurred":
                    command_result = command_result.splitlines(True)
                    for string in command_result:
                        if string[0] == "A" and string != command_result[1]:
                            string = string[9:].rstrip()
                            if string not in address_list and string != "":
                                string = string.rstrip()
                                address_list.append(string)

            site_dict.update({key: address_list})
            self.output.update({site: site_dict})

    def add_server(self):  # Uses curl to get an http response and records the server
        for site in self.websites:
            site_dict = self.output.get(site)
            key_server = "server"
            server_value = None

            try:
                curl_result = subprocess.check_output(["curl", "-I", site], timeout=1,
                                                      stderr=subprocess.STDOUT).decode("utf-8")
            except:
                curl_result = "Error"

            if curl_result != "Error":  # Goes through the lines of the curl response and sees if there is a server header
                curl_result = curl_result.splitlines()
                for line in curl_result:
                    if line[:7] == "Server:":
                        server_value = line[8:].rstrip()

            site_dict.update({key_server: server_value})
            self.output.update({site: site_dict})

# Takes the given command line input and reads it, modifies it and passes it to scanner
def parse_input():
    input_txt = sys.argv[1]
    with open(input_txt, 'r') as file:
        data = file.readlines()

    list = []
    for site in data:
        list.append(site.rstrip("\n"))

    scanner = Scanner(list)
    scanner.scan()


parse_input()

#  cd Documents/NU/networking/projects/pr4
