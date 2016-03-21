'''
This is a module that can carry out the top X (top 10 or more/less) analysis
against the IPs loaded into the framework.
'''


class Analytics:

    def __init__(self, cli_options):
        self.cli_name = "GeoInfo"
        self.description = "Analyzes IPs geographical/ISP information"
        if cli_options is None:
            self.top_number = ''
        else:
            self.top_number = int(cli_options.analyze_number)

    # This will sort the dictionary passed into it (or called on itself)
    def dict_sorter(self, data_dictionary):
        return sorted(data_dictionary.items(), key=lambda x: x[1])

    def analyze(self, all_ip_objects):

        if self.top_number == '':
            print "You selected \"GeoInfo\" module, how many items do you want returned?"
            print "Ex: 10"
            self.top_number = int(raw_input(' \n\n[>] Return the Top: ').strip())

        # Creating Dictionaries for top values
        top_countries = {}
        top_cities = {}
        top_timezones = {}
        top_regions = {}
        top_isp = {}
        top_organization = {}
        top_zipcodes = {}
        top_gps = {}

        # Looping over IP address objects
        for key, value in all_ip_objects.iteritems():
            if value[0].ip_country is not '':
                if value[0].ip_country not in top_countries:
                    top_countries[value[0].ip_country] = value[1]
                else:
                    top_countries[value[0].ip_country] += value[1]

        # Looping over regions
            if value[0].ip_region_name is not '':
                region = value[0].ip_region_name + ", " +\
                    value[0].ip_country
                if region not in top_regions:
                    top_regions[region] = value[1]
                else:
                    top_regions[region] += value[1]

        # Looping over timezones
            if value[0].ip_timezone is not '':
                if value[0].ip_timezone not in top_timezones:
                    top_timezones[value[0].ip_timezone] = value[1]
                else:
                    top_timezones[value[0].ip_timezone] += value[1]

        # Looping over cities
            if value[0].ip_city is not '':
                city = value[0].ip_city + ", " +\
                    value[0].ip_country
                if city not in top_cities:
                    top_cities[city] = value[1]
                else:
                    top_cities[city] += value[1]

        # Looping over zip codes
            if value[0].ip_zipcode is not '':
                if value[0].ip_zipcode not in top_zipcodes:
                    top_zipcodes[value[0].ip_zipcode] = value[1]
                else:
                    top_zipcodes[value[0].ip_zipcode] += value[1]

        # Looping over ISPs
            if value[0].ip_isp is not '':
                if value[0].ip_isp not in top_isp:
                    top_isp[value[0].ip_isp] = value[1]
                else:
                    top_isp[value[0].ip_isp] += value[1]

        # Looping over Organizations
            if value[0].ip_organization is not '':
                if value[0].ip_organization not in top_organization:
                    top_organization[value[0].ip_organization] = value[1]
                else:
                    top_organization[value[0].ip_organization] += value[1]

        # Looping over GPS Coords
            if value[0].ip_latitude is not '' and\
                    value[0].ip_longitude is not '':
                gps = value[0].ip_latitude + ", " +\
                    value[0].ip_longitude
                if gps not in top_gps:
                    top_gps[gps] = value[1]
                else:
                    top_gps[gps] += value[1]

        # Sort the dictionaries, and then get the top 10 of each dict
        sorted_countries = self.dict_sorter(top_countries)
        print
        print "         Top " + str(self.top_number) + " Countries"
        print " (Country : Number of Occurances)"
        print "==================================="

        # iterate through sorted countries list
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_countries))):
            country_tuple = sorted_countries[-list_counter]
            print country_tuple[0] + " : " + str(country_tuple[1])
            list_counter += 1
        print

        # Sort the dictionaries, and then get the top 10 of each dict
        top_cities = self.dict_sorter(top_cities)
        print
        print "         Top " + str(self.top_number) + " Cities"
        print " (City : Number of Occurances)"
        print "==================================="

        # iterate through sorted countries list
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(top_cities))):
            sorted_cities = top_cities[-list_counter]
            print sorted_cities[0] + " : " + str(sorted_cities[1])
            list_counter += 1
        print

        # Sort the dictionaries, and then get the top 10 of each dict
        sorted_regions = self.dict_sorter(top_regions)
        print
        print "         Top " + str(self.top_number) + " Regions"
        print " (Region : Number of Occurances)"
        print "==================================="

        # iterate through sorted countries list
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_regions))):
            region_tuple = sorted_regions[-list_counter]
            print region_tuple[0] + " : " + str(region_tuple[1])
            list_counter += 1
        print

        # Sort the dictionaries, and then get the top 10 of each dict
        sorted_timezones = self.dict_sorter(top_timezones)
        print
        print "         Top " + str(self.top_number) + " Timezones"
        print " (Timezone : Number of Occurances)"
        print "==================================="

        # iterate through sorted countries list
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_timezones))):
            timezone_tuple = sorted_timezones[-list_counter]
            print timezone_tuple[0] + " : " + str(timezone_tuple[1])
            list_counter += 1
        print

        # Sort the dictionaries, and then get the top 10 of each dict
        sorted_gps = self.dict_sorter(top_gps)
        print
        print "         Top " + str(self.top_number) + " GPS Coordinates"
        print " (GPS Coordinates : Number of Occurances)"
        print "==================================="

        # iterate through sorted countries list
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_gps))):
            gps_tuple = sorted_gps[-list_counter]
            print gps_tuple[0] + " : " + str(gps_tuple[1])
            list_counter += 1
        print

        # Sort the dictionaries, and then get the top 10 of each dict
        sorted_zipcodes = self.dict_sorter(top_zipcodes)
        print
        print "         Top " + str(self.top_number) + " ZipCodes"
        print " (ZipCode : Number of Occurances)"
        print "==================================="

        # iterate through sorted countries list
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_zipcodes))):
            zipcode_tuple = sorted_zipcodes[-list_counter]
            print zipcode_tuple[0] + " : " + str(zipcode_tuple[1])
            list_counter += 1
        print

        # Sort the dictionaries, and then get the top 10 of each dict
        sorted_isps = self.dict_sorter(top_isp)
        print
        print "         Top " + str(self.top_number) + " ISPs"
        print " (ISPs : Number of Occurances)"
        print "==================================="

        # iterate through sorted countries list
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_isps))):
            isp_tuple = sorted_isps[-list_counter]
            print isp_tuple[0] + " : " + str(isp_tuple[1])
            list_counter += 1
        print

        # Sort the dictionaries, and then get the top 10 of each dict
        sorted_orgs = self.dict_sorter(top_organization)
        print
        print "         Top " + str(self.top_number) + " Organizations"
        print " (Organizations : Number of Occurances)"
        print "==================================="

        # iterate through sorted countries list
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_orgs))):
            org_tuple = sorted_orgs[-list_counter]
            print org_tuple[0] + " : " + str(org_tuple[1])
            list_counter += 1
        print

        self.top_number = ''

        return
