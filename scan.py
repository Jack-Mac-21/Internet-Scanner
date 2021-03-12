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
            print("curl ERROR1")
            return False

        while not final_page:  # Loop should find the final page and return it as curl_result
            if self.redirect_count >= 9:
                print("Too many redirects")
                break
            location_redirect = None
            for line in curl_result:
                if line[:9] == "Location:" or line[:9] == "location":
                    location_redirect = line[10:]
            if location_redirect is None:
                final_page = True
                print("Final page found")
                break
            else:
                try:
                    print("Trying a redirect")
                    curl_result = subprocess.check_output(["curl", "-I", location_redirect], timeout=1,
                                                              stderr=subprocess.STDOUT).decode("utf-8")
                    curl_result = curl_result.splitlines()
                except Exception:
                    curl_result = "Error"
            self.redirect_count += 1

        self.redirect_count = 0

        if curl_result == "Error":
            print("curl ERROR2")
            return False

        for line in curl_result:
            if line[:26] == header1 or line[:26] == header2:
                print("hsts was found")
                return True
        print("Reached the end hst header was not found")
        return False


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
