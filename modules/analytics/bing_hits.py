'''
This module finds all systems that have "interesting" results
from bing.com
'''

from common import helpers


class Analytics:

    def __init__(self, cli_options):
        self.cli_name = "Bing_IP"
        self.description = "Returns IP addresses with hostnames found on bing.com"
        if cli_options is None:
            self.top_number = ''
        else:
            self.top_number = int(cli_options.analyze_number)

    def analyze(self, all_ip_objects):

        if self.top_number == '':
            print "You selected the \"Bing_IP\" module, how many items do you want returned?"
            print "Ex: 10"
            self.top_number = int(raw_input(' \n\n[>] Return the Top: ').strip())

        detected_count = {}

        for key, value in all_ip_objects.iteritems():
            if type(value[0].hostnames) is list:
                hits = len(value[0].hostnames)
                if hits > 0:
                    detected_count[value[0].ip_address] = hits

        print
        print "*" * 70
        print " " * 20 + "IPs and Found Hostnames" + " " * 20
        print "*" * 70
        sorted_detected_count = self.dict_sorter2(detected_count)
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_detected_count))):
            sorted_detected_count_tuple = sorted_detected_count[-list_counter]
            print sorted_detected_count_tuple[0] + ": " + str(sorted_detected_count_tuple[1]) + " count(s)"
            list_counter += 1

        return

    def dict_sorter(self, data_dictionary):
        return sorted(data_dictionary.items(), key=lambda x: len(x[1]))

    def dict_sorter2(self, data_dictionary):
        return sorted(data_dictionary.items(), key=lambda x: x[1])
