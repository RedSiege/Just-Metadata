'''
This is a module that can carry out the top X (top 10 or more/less) analysis
against the IPs loaded into the framework.
'''

from common import helpers


class Analytics:

    def __init__(self, cli_options):
        self.cli_name = "Country"
        self.description = "Search for IPs by country of origin"
        if cli_options is None:
            self.country = ''
        else:
            self.country = cli_options.analyze_string.lower()

    # This will sort the dictionary passed into it (or called on itself)
    def dict_sorter(self, data_dictionary):
        return sorted(data_dictionary.items(), key=lambda x: x[1])

    def analyze(self, all_ip_objects):

        if self.country == '':
            print "Which country are you looking for??"
            print "Ex: United States"
            self.country = raw_input(' \n\n[>] Country: ').strip()

        # Creating Dictionaries for top values
        ip_country = []

        # Looping over IP address objects
        for key, value in all_ip_objects.iteritems():
            if value[0].ip_country.lower() == self.country.lower():
                ip_country.append(value[0].ip_address)

        if len(ip_country) == 0:
            print helpers.color("No IPs were detected to come from " + self.country + "!", warning=True)
        else:
            print "#" * 50
            print " " * 20 + "IPs from " + self.country
            print "#" * 50
            for ip_address in ip_country:
                print helpers.color(ip_address)

        self.country = ''

        return
