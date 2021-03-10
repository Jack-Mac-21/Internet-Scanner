# This is my networking project 4
# Take an input file and return a out txt file

import sys
import os
import time
import json

output_dictionary = {}  # JSON dictionary as output where website is the key and dictionary of results is the value


def main():
    input_file_name = sys.argv[1]
    with open(input_file_name, 'r') as file:
        data = file.readlines()

    for site in data:
        site = site.rstrip("\n")
        key = site
        value = {"scan_time: ": time.time()}
        output_dictionary.update({key: value})

    json_dict = json.dumps(output_dictionary, sort_keys=True, indent=4)
    print(json_dict)



main()

#  cd Documents/NU/networking/projects/pr4