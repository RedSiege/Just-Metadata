'''
This module finds assigned CIDR netblocks that are similar across loaded ips
'''

from common import helpers


class Analytics:

    def __init__(self, cli_options):
        self.cli_name = "TopNetBlocks"
        self.description = "Returns the top \"X\" number of most seen whois CIDR netblocks"
        if cli_options is None:
            self.top_number = ''
        else:
            self.top_number = int(cli_options.analyze_number)

    def analyze(self, all_ip_objects):

        if self.top_number == '':
            print "You selected the \"TopNetblocks\" module, how many CIDR blocks do you want returned?"
            print "Ex: 10"
            self.top_number = int(raw_input(' \n\n[>] Total: ').strip())

        top_cidrs = {}

        for single_ip in all_ip_objects.values():
            try:
                if 'asn_cidr' in single_ip[0].ip_whois.keys():
                    if single_ip[0].ip_whois['asn_cidr'] in top_cidrs:
                        top_cidrs[single_ip[0].ip_whois['asn_cidr']] += 1
                    else:
                        top_cidrs[single_ip[0].ip_whois['asn_cidr']] = 1
            except AttributeError:
                print helpers.color("Incorrect whois data format for " + single_ip[0].ip_address, warning=True)

        # Iterate over all ports
        sorted_top_cidrs = self.dict_sorter(top_cidrs)
        list_counter = 1
        print "*" * 70
        print helpers.color(" " * 20 + "Top CIDR NetBlocks : Number of Instances" + " " * 20)
        print "*" * 70
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_top_cidrs))):
            sorted_ports_tuple = sorted_top_cidrs[-list_counter]
            print "Port: " + helpers.color(str(sorted_ports_tuple[0])) + " - " + str(sorted_ports_tuple[1]) + " instances"
            list_counter += 1
        print

        self.top_number = ''

        return

    def dict_sorter(self, data_dictionary):
        return sorted(data_dictionary.items(), key=lambda x: x[1])
