'''
This module finds all systems that have "interesting" results
from dshield
'''

from common import helpers


class Analytics:

    def __init__(self, cli_options):
        self.cli_name = "DShield"
        self.description = "Returns IP addresses with results in DShield"
        if cli_options is None:
            self.top_number = ''
        else:
            self.top_number = int(cli_options.analyze_number)

    def analyze(self, all_ip_objects):

        if self.top_number == '':
            print "You selected the \"DShield\" module, how many items do you want returned?"
            print "Ex: 10"
            self.top_number = int(raw_input(' \n\n[>] Return the Top: ').strip())

        # format is {hash: [ip, ip]}
        unique_sha256 = {}
        unique_urls = {}
        undetected_256 = {}
        referrer_samples = {}

        # Dictionary for IPs and total samples
        ip_detected_samples = {}
        ip_detected_urls = {}
        ip_undetected_samples = {}
        ip_detected_referrer = {}
        vt_detected_domains = {}
        total_detected_domains = {}

	detected_count = {}
	detected_attacks = {}
	detected_maxrisk = {}

        for key, value in all_ip_objects.iteritems():
		if type(value[0].dshield) is dict:
			ip_count = value[0].dshield.get('count')
			ip_attacks = value[0].dshield.get('attacks')
			ip_maxrisk = value[0].dshield.get('maxrisk')
			if ip_count > 0:
				detected_count[value[0].ip_address] = ip_count

			if ip_attacks > 0:
				detected_attacks[value[0].ip_address] = ip_attacks

			if ip_maxrisk > 0:
				detected_maxrisk[value[0].ip_address] = ip_maxrisk
					
	print
        print "*" * 70
        print " " * 20 + "IPs and Detected Counts" + " " * 20
        print "*" * 70
        sorted_detected_count = self.dict_sorter2(detected_count)
	list_counter = 1
	while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_detected_count))):
		sorted_detected_count_tuple = sorted_detected_count[-list_counter]
		print sorted_detected_count_tuple[0] + ": " + str(sorted_detected_count_tuple[1]) + " count(s)"
		list_counter += 1

	print
        print "*" * 70
        print " " * 20 + "IPs and Attacked Targets" + " " * 20
        print "*" * 70
        sorted_detected_attacks = self.dict_sorter2(detected_attacks)
	list_counter = 1
	while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_detected_attacks))):
		sorted_detected_attacks_tuple = sorted_detected_attacks[-list_counter]
		print sorted_detected_attacks_tuple[0] + ": " + str(sorted_detected_attacks_tuple[1]) + " target(s)"
		list_counter += 1
	print
        print "*" * 70
        print " " * 20 + "IPs and Detected Risk" + " " * 20
        print "*" * 70
        sorted_detected_maxrisk = self.dict_sorter2(detected_maxrisk)
	list_counter = 1
	while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_detected_maxrisk))):
		sorted_detected_maxrisk_tuple = sorted_detected_maxrisk[-list_counter]
		print sorted_detected_maxrisk_tuple[0] + ": " + str(sorted_detected_maxrisk_tuple[1]) + " maximum risk"
		list_counter += 1
        return

    def dict_sorter(self, data_dictionary):
        return sorted(data_dictionary.items(), key=lambda x: len(x[1]))

    def dict_sorter2(self, data_dictionary):
        return sorted(data_dictionary.items(), key=lambda x: x[1])
