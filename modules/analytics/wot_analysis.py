'''
This is a module that reviews the data returned by mywot and parses the
information returned about the provided domains
'''


class Analytics:

    def __init__(self, cli_options):
        self.cli_name = "MyWOTDomains"
        self.description = "Parse mywot domain reputation results"
        if cli_options is None:
            self.top_number = ''
        else:
            self.top_number = int(cli_options.analyze_number)

    def analyze(self, all_ip_objects):

        if self.top_number == '':
            print "You selected \"MyWOTDomains\" module, how many domains do you want returned?"
            print "Ex: 10"
            self.top_number = int(raw_input(' \n\n[>] Return the Top: ').strip())

        # Create dicts for site rankings
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
                    elif '103' in value[0].mywot[value[0].domain_name]['categories']:
                        negative_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['103']
                    elif '104' in value[0].mywot[value[0].domain_name]['categories']:
                        negative_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['104']
                    elif '105' in value[0].mywot[value[0].domain_name]['categories']:
                        negative_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['105']

                    # Grab questionable site categories
                    if '201' in value[0].mywot[value[0].domain_name]['categories']:
                        questionable_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['201']
                    elif '202' in value[0].mywot[value[0].domain_name]['categories']:
                        questionable_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['202']
                    elif '203' in value[0].mywot[value[0].domain_name]['categories']:
                        questionable_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['203']
                    elif '204' in value[0].mywot[value[0].domain_name]['categories']:
                        questionable_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['204']
                    elif '205' in value[0].mywot[value[0].domain_name]['categories']:
                        questionable_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['205']
                    elif '206' in value[0].mywot[value[0].domain_name]['categories']:
                        questionable_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['206']
                    elif '207' in value[0].mywot[value[0].domain_name]['categories']:
                        questionable_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['207']

                    # Grab neutral site categories
                    if '301' in value[0].mywot[value[0].domain_name]['categories']:
                        neutral_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['301']
                    elif '302' in value[0].mywot[value[0].domain_name]['categories']:
                        neutral_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['302']
                    elif '303' in value[0].mywot[value[0].domain_name]['categories']:
                        neutral_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['303']
                    elif '304' in value[0].mywot[value[0].domain_name]['categories']:
                        neutral_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['304']

                    # Grab positive site categories
                    if '501' in value[0].mywot[value[0].domain_name]['categories']:
                        positive_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['501']
                    elif '404' in value[0].mywot[value[0].domain_name]['categories']:
                        positive_sites[value[0].domain_name] = value[0].mywot[value[0].domain_name]['categories']['404']

        # Sort the dictionaries, and then get the top 10 of each dict
        sorted_negative_sites = self.dict_sorter(negative_sites)
        print
        print "        Top " + str(self.top_number) + " Negative Sites"
        print " (Domain : Ranking (higher is worse))"
        print "==================================="

        # iterate through sorted negative domain list
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter - 1) != len(sorted_negative_sites))):
            negative_tuple = sorted_negative_sites[-list_counter]
            print negative_tuple[0] + " : " + str(negative_tuple[1])
            list_counter += 1
        print


        # Sort the dictionaries, and then get the top 10 of each dict
        sorted_questionable_sites = self.dict_sorter(questionable_sites)
        print
        print "     Top " + str(self.top_number) + " Questionable Sites"
        print " (Domain : Ranking (higher is worse))"
        print "==================================="

        # iterate through sorted questionable domain list
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter - 1) != len(sorted_questionable_sites))):
            questionable_tuple = sorted_questionable_sites[-list_counter]
            print questionable_tuple[0] + " : " + str(questionable_tuple[1])
            list_counter += 1
        print


        # Sort the dictionaries, and then get the top 10 of each dict
        sorted_neutral_sites = self.dict_sorter(neutral_sites)
        print
        print "         Top " + str(self.top_number) + " Neutral Sites"
        print " (Domain : Ranking (higher is arguably worse))"
        print "==================================="

        # iterate through sorted neutral domain list
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter - 1) != len(sorted_neutral_sites))):
            neutral_tuple = sorted_neutral_sites[-list_counter]
            print neutral_tuple[0] + " : " + str(neutral_tuple[1])
            list_counter += 1
        print


        # Sort the dictionaries, and then get the top 10 of each dict
        sorted_positive_sites = self.dict_sorter(positive_sites)
        print
        print "         Top " + str(self.top_number) + " Neutral Sites"
        print " (Domain : Ranking (higher is better))"
        print "==================================="

        # iterate through sorted positive domain list
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter - 1) != len(sorted_positive_sites))):
            positive_tuple = sorted_positive_sites[-list_counter]
            print positive_tuple[0] + " : " + str(positive_tuple[1])
            list_counter += 1
        print


        # Sort the dictionaries, and then get the top 10 of each dict
        sorted_trustworthiness_sites = self.dict_sorter(trustworthiness_rating)
        print
        print "     Top " + str(self.top_number) + " Trustworthiness Sites"
        print " (Domain : Ranking (higher is better))"
        print "==================================="

        # iterate through sorted trustwothiness domain list
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter - 1) != len(sorted_trustworthiness_sites))):
            trustworthy_tuple = sorted_trustworthiness_sites[-list_counter]
            print trustworthy_tuple[0] + " : " + str(trustworthy_tuple[1])
            list_counter += 1
        print

        # Sort the dictionaries, and then get the top 10 of each dict
        sorted_childsafety_sites = self.dict_sorter(childsafety_rating)
        print
        print "      Top " + str(self.top_number) + " Child Safety Sites"
        print " (Domain : Ranking (higher is better))"
        print "==================================="

        # iterate through sorted positive domain list
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter - 1) != len(sorted_childsafety_sites))):
            csafety_tuple = sorted_childsafety_sites[-list_counter]
            print csafety_tuple[0] + " : " + str(csafety_tuple[1])
            list_counter += 1
        print

        self.top_number = ''

        return

    # This will sort the dictionary passed into it (or called on itself)
    def dict_sorter(self, data_dictionary):
        return sorted(data_dictionary.items(), key=lambda x: x[1])