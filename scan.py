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
        self.unencrypted_listen = False  # Does the site listen to unencrypted http request on port 80
        self.redirect_count = 0  # Handling redirects for finding if it redirects to https

    @staticmethod
    def initialize_resolvers():
        dns_resolvers = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26",  "9.9.9.9",
                         "64.6.65.6", "91.239.100.100", "185.228.168.168", "77.88.8.7",
                         "156.154.70.1", "198.101.242.72", "176.103.130.130"]
        return dns_resolvers

    def scan(self):
        self.add_scan_time()
        print("\n\nADDED SCAN_TIME\n\n")
        self.get_root_ca()
        print("\n\nADDED ROOT CA\n\n")
        self.add_tls()
        print("\n\nADDED TLS\n\n")
        self.add_server()
        print("\n\nADDED HTTP HEADERS\n\n")
        self.add_ip6()
        print("\n\nADDED IP6\n\n")
        self.add_ip4()
        print("\n\nADDED ADDED IP4\n\n")

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

    # Does all http header checks
    def add_server(self):  # Uses curl to get an http response and records the server, also handles https redirect portion
        for site in self.websites:
            site_dict = self.output.get(site)
            key_server = "server"
            key_http_insecure = "insecure-http"
            key_https_redirect = "redirect-to-https:"
            key_hsts = "hsts"
            server_value = None
            http_unencrypted = False

            try:
                curl_result = subprocess.check_output(["curl", "-I", site+":80"], timeout=1,
                                                      stderr=subprocess.STDOUT).decode("utf-8")
            except Exception:
                curl_result = "Error"

            if curl_result != "Error":  # Goes through the lines of the curl response and sees if there is a server header
                curl_result = curl_result.splitlines()
                http_unencrypted = True
                for line in curl_result:
                    if line[:7] == "Server:":
                        server_value = line[8:].rstrip()
            #print("\n" + site + "curl result... ")
            #print(curl_result)
            value_https_redirect = self.http_redirect(curl_result)
            value_hsts = self.check_hsts(curl_result)
            site_dict.update({key_server: server_value})  # server
            site_dict.update({key_http_insecure: http_unencrypted})  # http listen
            site_dict.update({key_https_redirect: value_https_redirect})  # https redirect
            site_dict.update({key_hsts: value_hsts})  # hsts header bool
            self.output.update({site: site_dict})

    # Checks if redirected to https
    def http_redirect(self, curl_result):  # Returns sets the redirect portion for each site
        value_redirect = False

        if self.redirect_count >= 10:
            self.redirect_count = 0
            return "Too Many Redirects"

        if curl_result != "Error":
            location_redirect = None
            for line in curl_result:
                if line[:9] == "Location:" or line[:9] == "location:":
                    location_redirect = line[10:]
            if location_redirect is not None:
                #print("\n" + location_redirect + "\n")
                if location_redirect[:6] == "https:":
                    value_redirect = True
                    self.redirect_count = 0
                    return value_redirect
                else:
                    try:
                        #print("tried a redirect")
                        curl_result = subprocess.check_output(["curl", "-I", location_redirect], timeout=1,
                                                              stderr=subprocess.STDOUT).decode("utf-8")
                        curl_result = curl_result.splitlines()
                    except Exception:
                        curl_result = "Error"

                    #print(curl_result)
                    #print('\n\n')
                    self.redirect_count += 1
                    self.http_redirect(curl_result)
            else:
                self.redirect_count = 0
                return False
        else:
            self.redirect_count = 0
            return value_redirect

        self.redirect_count =0
        return False

    # Chackes if redirected to page with strict-transport protocol
    def check_hsts(self, input_curl):
        curl_result = input_curl
        header1 = "Strict-Transport-Security:"
        header2 = "strict-transport-security:"
        final_page = False  # Says if we reached last redirect or not

        if curl_result == "Error":
            #print("curl ERROR1")
            return False

        while not final_page:  # Loop should find the final page and return it as curl_result
            if self.redirect_count >= 9:
                #print("Too many redirects")
                break
            location_redirect = None
            for line in curl_result:
                if line[:9] == "Location:" or line[:9] == "location":
                    location_redirect = line[10:]
            if location_redirect is None:
                final_page = True
                #print("Final page found")
                break
            else:
                try:
                    #print("Trying a redirect")
                    curl_result = subprocess.check_output(["curl", "-I", location_redirect], timeout=1,
                                                              stderr=subprocess.STDOUT).decode("utf-8")
                    curl_result = curl_result.splitlines()
                except Exception:
                    curl_result = "Error"
            self.redirect_count += 1

        self.redirect_count = 0

        if curl_result == "Error":
            #print("curl ERROR2")
            return False

        for line in curl_result:
            if line[:26] == header1 or line[:26] == header2:
                #print("hsts was found")
                return True
        #print("Reached the end hst header was not found")
        return False

    # Uses nmap for each website
    def add_tls(self):
        tls_key = "tls_versions"
        possible_tls = ["SSLv2:", "SSLv3:", "TLSv1.0:", "TLSv1.1:", "TLSv1.2:", "TLSv1.3"]
        for site in self.websites:
            tls_list = []
            nmap_request = ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", site]
            ssl_request = ["openssl", "s_client", "-tls1_3", "-connect", site + ":443"]
            site_dict = self.output.get(site)

            # First checking for the first 3 versions of tls
            #print("Getting nmap result")
            try:
                nmap_result = subprocess.check_output(nmap_request, timeout=20, stderr=subprocess.STDOUT).decode("utf-8")
            except Exception:
                nmap_result = "Error\n"
            nmap_result = nmap_result.splitlines()
            #print("Going through nmap result")
            for line in nmap_result:
                line = line.strip("| ")
                #print(line)
                if line in possible_tls:
                    if line not in tls_list:
                        tls_list.append(line[:-1])
                        #print("Added TLS version to output list")

            # Second, check for TLSv1.3
            #print("Now checking for TLSv1.3 for: " + site)
            #print(ssl_request)
            try:
                ps = subprocess.Popen(["echo"], stdout=subprocess.PIPE)
                ssl_result = subprocess.check_output(ssl_request, stdin=ps.stdout, timeout=10, stderr=subprocess.STDOUT).decode("utf-8")
                ps.wait()
            except Exception:
                #print(Exception.__cause__)
                ssl_result = "Error\n"
            #print("Going through ssl_result: " + ssl_result)
            ssl_result = ssl_result.splitlines()
            for line in ssl_result:
                line = line.strip()
                #print("Current line: " + line + "\n")
                if line[:12] == "New, TLSv1.3":
                    if "TLSv1.3" not in tls_list:
                        tls_list.append("TLSv1.3")
                        #print("Appending TLSv1.3 for: " + site)
                        break

            #print("\nUpdating site dictionary for " + site + "\n")
            site_dict.update({tls_key: tls_list})

    def get_root_ca(self):
        for site in self.websites:
            print("\nGetting root CA for: " + site + "\n")
            site_dict = self.output.get(site)
            certificate_chain = []
            root_ca = None
            ca_request = ["openssl", "s_client", "-connect", "stevetarzia.com:443"]
            print("Attempting the ca_request command")
            try:
                ps = subprocess.Popen(["echo"], stdout=subprocess.PIPE)
                ca_result = subprocess.check_output(ca_request, stdin=ps.stdout, timeout=10,
                                                    stderr=subprocess.STDOUT).decode("utf-8")
            except Exception:
                print("Command request ERROR")
                ca_result ="Error"
            if ca_result != "Error":
                i = 8
                ca_result = ca_result.splitlines()
                while ca_result[i] != "---":
                    print("constructing Certificate chain for... " + site)
                    certificate_chain.append(ca_result[i])
                    i += 1
                certificate_chain = [line.strip() for line in certificate_chain]
                cc_last_line = certificate_chain[-1].split(",")
                print(cc_last_line)
                for entry in cc_last_line:
                    if entry[:6] == "i:o = ":
                        root_ca = entry[6:]
                        print("Found root CA")
                        break
                    if entry[:3] == "O = ":
                        root_ca = entry[3:]
                        print("Found Root CA")
                        break
                print("Root CA for " + site + ": " + root_ca)


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
