# This will generate a text report of what scan created
import sys
import json
import texttable


# TODO: added RTT table after adding it's scanner
class ReportGenerator:
    def __init__(self, input_json):
        self.data = input_json
        self.websites = list(input_json.keys())
        self.all_info_table = texttable.Texttable()  # Table that gives all data collected
        self.root_ca_table = texttable.Texttable()  # Order root_ca's from most popular and gives a count
        self.server_table = texttable.Texttable()  # Order http_server from most popular and give count
        self.tls_table = texttable.Texttable()  # tls info table


    def generate_report(self):
        output = self.data
        print(output.get("amazon.com"))
        print(self.websites)

        self.fill_all_info_table()
        self.fill_ca_table()
        self.fill_server_table()
        self.fill_tls_table()

        print(self.all_info_table.draw())
        print(self.root_ca_table.draw())
        print(self.server_table.draw())
        print(self.tls_table.draw())
        with open("report_out.txt", "w") as outfile:
            outfile.write(self.all_info_table.draw() + "\n\n"
                          + self.root_ca_table.draw() + "\n\n"
                          + self.server_table.draw() + "\n\n")


    def fill_all_info_table(self):
        self.all_info_table.add_row(["Website", "Scan-Time", "IPv4 Addresses", "IPv6 Addresses",
                            "HTTP Server", "Insecure HTTP", "Redirect to HTTPS?", "HSTS?",
                            "TLS Versions", "Root CA", "RDNS Names"])
        rows = []
        for site in self.websites:
            site_dict = self.data.get(site)
            table_entry = [site, site_dict.get("scan-time"), site_dict.get("ipv4_addresses"),
                           site_dict.get("ipv6_addresses"), site_dict.get("http_server"), site_dict.get("insecure-http"),
                           site_dict.get("redirect-to-https"), site_dict.get("hsts"), site_dict.get("tls_versions"),
                           site_dict.get("root_ca"), site_dict.get("rdns_names:")]
            rows.append(table_entry)
            self.all_info_table.add_row(table_entry)
        self.all_info_table.set_cols_width([12, 12, 20, 30, 10, 5, 5, 5, 10, 15, 30])

    def fill_ca_table(self):
        root_count = self.get_root_count()
        count_list = []

        for element in root_count:
            count_list.append(element[1])


        self.root_ca_table.add_row(["Root CA", "Count"])

        for element in root_count:
            row_entry = [element[0], element[1]]
            self.root_ca_table.add_row(row_entry)
        self.root_ca_table.set_cols_width([10, 10])

    # Helper for constructing the root_ca table, returns [[root, count]...]
    def get_root_count(self):
        root_ca_list = []
        root_count = []
        for site in self.websites:
            site_dict = self.data.get(site)
            root_ca_list.append(site_dict.get("root_ca"))

        root_ca_set = set(root_ca_list)

        for ca in root_ca_set:  # for the root_ca it checks through all roots CAs and counts the occurences
            count = 0
            for cs_flist in root_ca_list:
                if ca == cs_flist:
                    count += 1
            root_count.append([ca, count])

        # Re-arranging the root count list
        count_list = []  # List of just the counts
        rearranged_root_list = []

        for element in root_count:
            count_list.append(element[1])

        for element in root_count:
            max_index = count_list.index(max(count_list))
            rearranged_root_list.append(root_count[max_index])
            count_list[max_index] = 0

        return rearranged_root_list

    # Fills the server table with number of occurences and in order of each http-server
    def fill_server_table(self):
        server_count = self.get_server_count()

        self.server_table.add_row(["HTTP-Server", "Count"])

        for element in server_count:
            row_entry = [element[0], element[1]]
            self.server_table.add_row(row_entry)
        self.server_table.set_cols_width([10, 10])

    # Gets a list of list where elements are [server, count] and places in order
    def get_server_count(self):
        server_list = []  # all servers with repeats
        server_count = []
        for site in self.websites:
            site_dict = self.data.get(site)
            server_list.append(site_dict.get("http_server"))

        server_set = set(server_list)

        for serv in server_set:  # for the root_ca it checks through all roots CAs and counts the occurences
            count = 0
            for server in server_list:
                if serv == server:
                    count += 1
            server_count.append([serv, count])

        # Re-arranging the root count list
        count_list = []  # List of just the counts
        rearranged_server_list = []

        for element in server_count:
            count_list.append(element[1])

        for element in server_count:
            max_index = count_list.index(max(count_list))
            rearranged_server_list.append(server_count[max_index])
            count_list[max_index] = 0

        return rearranged_server_list

    def fill_tls_table(self):
        info_list = self.get_tls_info()
        self.tls_table.add_row(["Protocol", "Count", "Percentage"])

        for element in info_list:
            self.tls_table.add_row(element)

        self.tls_table.set_cols_width([5, 5, 7])

    def get_tls_info(self):
        total_sites = len(self.websites)
        sslv2_count = 0
        sslv3_count = 0
        tlsv10_count = 0
        tlsv11_count = 0
        tlsv12_count = 0
        tlsv13_count = 0
        plain_http_count = 0
        https_redirect_count = 0
        hsts_count = 0
        ipv6_count = 0

        for site in self.websites:
            site_dict = self.data.get(site)
            if site_dict.get("insecure-http"):
                plain_http_count += 1
            if site_dict.get("redirect-to-https"):
                https_redirect_count += 1
            if site_dict.get("hsts"):
                hsts_count += 1
            if len(site_dict.get("ipv6_addresses")) > 0:
                ipv6_count += 1
            tls_list = site_dict.get("tls_versions")
            for tls in tls_list:
                if tls == "SSLv2":
                    sslv2_count += 1
                if tls == "SSLv3":
                    sslv3_count += 1
                if tls == "TLSv1.0":
                    tlsv10_count += 1
                if tls == "TLSv1.1":
                    tlsv11_count += 1
                if tls == "TLSv1.2":
                    tlsv12_count += 1
                if tls == "TLSv1.3":
                    tlsv13_count += 1

        protocol_count_percent_list = [["SSLv2", sslv2_count], ["SSLv3", sslv3_count] , ["TLSv1.0", tlsv10_count],
                                       ["TLSv1.1", tlsv11_count],
                                       ["TLSv1.2",tlsv12_count], ["TLSv1.3", tlsv13_count], ["Insecure_http", plain_http_count],
                                       ["https_redirect", https_redirect_count], ["hsts", hsts_count], ["IPv6", ipv6_count]]

        p_c_p_list_final = []

        for element in protocol_count_percent_list:
            new_element = element
            new_element.append(str(round(element[1]/total_sites * 100, 2)) + "%")
            p_c_p_list_final.append(new_element)

        return p_c_p_list_final


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

