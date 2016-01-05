'''
This is a module that reviews the data returned by mywot and parses the
information returned about the provided domains
'''

from common import helpers


class Analytics:

    def __init__(self, cli_options):
        self.cli_name = "MyWOTDomains"
        self.description = "Parse mywot domain reputation results"

    def analyze(self, all_ip_objects):

        negative_sites = {}
        questionable_sites = {}
        neutral_sites = {}
        positive_sites = {}
        trustworthiness_rating = {}
        childsafety_rating = {}

        # Looping over IP address objects
        for value in all_ip_objects.itervalues():

            # Check to make sure there is a result in mywot attribute
            if value[0].mywot != "":

                # Start parsing results and sorting into categories
                # Parse trustworthyness values
                if '0' in value[0].mywot[value[0].domain_name]:
                    if int(value[0].mywot[value[0].domain_name]['0'][1]) > 10:
                        trustworthiness_rating[value[0].domain_name] = value[0].mywot[value[0].domain_name]['0'][0]

                # Parse child safety values
                if '4' in value[0].mywot[value[0].domain_name]:
                    if int(value[0].mywot[value[0].domain_name]['4'][1]) > 10:
                        childsafety_rating[value[0].domain_name] = value[0].mywot[value[0].domain_name]['4'][0]

                if 'categories' in value[0].mywot[value[0].domain_name]:
                    # Grab negative categories
                    if '101' in value[0].mywot[value[0].domain_name]['categories']:
                        negative_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['101']
                    elif '102' in value[0].mywot[value[0].domain_name]['categories']:
                        negative_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['102']


        return
