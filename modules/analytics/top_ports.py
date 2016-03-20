'''
This module displays the top X number of most used ports.
'''

# No available information within Shodan about 190.90.112.8

from common import helpers


class Analytics:

    def __init__(self, cli_options):
        self.cli_name = "TopPorts"
        self.description = "Returns the top \"X\" number of most used ports"
        if cli_options is None:
            self.top_number = ''
        else:
            self.top_number = int(cli_options.analyze_number)

    def analyze(self, all_ip_objects):

        if self.top_number == '':
            print "You selected the \"Top_Ports\" module, how many ports do you want returned?"
            print "Ex: 10"
            self.top_number = int(raw_input(' \n\n[>] Total: ').strip())

        top_ports = {}

        for path, single_ip in all_ip_objects.iteritems():
            if single_ip[0].shodan_info is not '' and\
                'No available information within Shodan about' not in\
                    single_ip[0].shodan_info:
                for item in single_ip[0].shodan_info['ports']:
                    if item in top_ports:
                        top_ports[item] += 1
                    else:
                        top_ports[item] = 1

        # Iterate over all ports
        sorted_top_ports = self.dict_sorter(top_ports)
        list_counter = 1
        print "*" * 70
        print helpers.color(" " * 20 + "Top Ports : Number of Instances" + " " * 20)
        print "*" * 70
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_top_ports))):
            sorted_ports_tuple = sorted_top_ports[-list_counter]
            print "Port: " + helpers.color(str(sorted_ports_tuple[0])) + " - " + str(sorted_ports_tuple[1]) + " instances"
            list_counter += 1
        print

        self.top_number = ''

        return

    def dict_sorter(self, data_dictionary):
        return sorted(data_dictionary.items(), key=lambda x: x[1])
