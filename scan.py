# This is my networking project 4
# Take an input file and return a out txt file

import sys
import os
import time
import json

output_dictionary = {}  # JSON dictionary as output where website is the key and dictionary of results is the value


# Scanner takes a list of websites
class Scanner:
    def __init__(self, input_txt):
        self.websites = input_txt
        self.output = {}

    def scan(self):
        for site in self.websites:
            key = site
            value = {"scan-time: ": time.time()}
            self.output.update({key: value})

        json_dict = json.dumps(self.output, sort_keys=True, indent=4)
        print(json_dict)


# Takes the given input and reads it, modifies it and passes it to scanner
def main():
    input_txt = sys.argv[1]
    with open(input_txt, 'r') as file:
        data = file.readlines()

    list = []
    for site in data:
        list.append(site.rstrip("\n"))

    scanner = Scanner(list)
    scanner.scan()


main()

#  cd Documents/NU/networking/projects/pr4
