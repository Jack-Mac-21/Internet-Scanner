# This will generate a text report of what scan created
import sys
import json
import texttable


class ReportGenerator:
    def __init__(self, input_json):
        self.json_data = input_json
        self.websites = list(input_json.keys())

    def generate_report(self):
        output = self.json_data
        print(output.get("amazon.com"))
        print(self.websites)




def parse_input():
    input_txt = sys.argv[1]
    with open(input_txt, 'r') as file:
        data = json.load(file)
    return data


def main():
    input_json = parse_input()
    report_generator = ReportGenerator(input_json)

    report_generator.generate_report()

main()

