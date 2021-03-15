# This will generate a text report of what scan created
import sys
import json
import texttable


class ReportGenerator:
    def __init__(self, input_json):
        self.data = input_json
        self.websites = list(input_json.keys())
        self.table = texttable.Texttable()

    def generate_report(self):
        output = self.data
        print(output.get("amazon.com"))
        print(self.websites)

        self.text_table()

        print(self.table.draw())

    def text_table(self):

        self.table.add_row(["Website", "Scan-Time", "IPv4 Addresses", "IPv6 Addresses",
                            "HTTP Server", "Insecure HTTP", "Redirect to HTTPS?", "HSTS?",
                            "TLS Versions", "Root CA", "RDNS Names"])
        rows = []
        for site in self.websites:
            site_dict = self.data.get(site)
            table_entry = [site, site_dict.get("scan-time"), site_dict.get("ipv4_addresses"),
                           site_dict.get("ipv6_addresses"), site_dict.get("server"), site_dict.get("insecure-http"),
                           site_dict.get("redirect-to-https:"), site_dict.get("hsts"), site_dict.get("tls_versions"),
                           site_dict.get("root ca"), site_dict.get("rdns_names:")]
            rows.append(table_entry)
            self.table.add_row(table_entry)
        self.table.set_cols_width([12, 12, 25, 25, 10, 5, 5, 5, 5, 5, 20])

        pass




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

