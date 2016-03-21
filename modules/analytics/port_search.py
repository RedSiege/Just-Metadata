'''
This module finds all systems that have the same public keys (https or ssh)
'''

# No available information within Shodan about 190.90.112.8

from common import helpers


class Analytics:

    def __init__(self, cli_options):
        self.cli_name = "PortSearch"
        self.description = "Returns the top \"X\" number of most used ports"
        if cli_options is None:
            self.port_search = ''
        else:
            self.port_search = int(cli_options.analyze_number)

    def analyze(self, all_ip_objects):

        if self.port_search == '':
            print "You selected the \"Port_search\" module, which port are you looking for?"
            print "Ex: 80"
            self.port_search = int(raw_input(' \n\n[>] Port: ').strip())

        top_ports = {}

        for path, single_ip in all_ip_objects.iteritems():
            if single_ip[0].shodan_info is not '' and\
                'No available information within Shodan about' not in\
                    single_ip[0].shodan_info:
                for port in single_ip[0].shodan_info['ports']:
                    if port in top_ports:
                        top_ports[port] = top_ports[port] + [single_ip[0].ip_address]
                    else:
                        top_ports[port] = [single_ip[0].ip_address]

        # Check if requested port is in dictionary
        if self.port_search in top_ports:
            print "Port " + str(self.port_search) + " is open on the following IPs:"
            print "*" * 50
            for ip_address in top_ports[self.port_search]:
                print helpers.color(ip_address)
        else:
            helpers.color("Port not open on any loaded IP address!", warning=True)

        self.port_search = ''

        return

    def dict_sorter(self, data_dictionary):
        return sorted(data_dictionary.items(), key=lambda x: len(x[1]))
