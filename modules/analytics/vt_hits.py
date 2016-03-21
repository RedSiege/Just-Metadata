'''
This module finds all systems that have "interesting" results
from virustotal
'''

from common import helpers


class Analytics:

    def __init__(self, cli_options):
        self.cli_name = "Virustotal"
        self.description = "Returns IP addresses with results in VirusTotal"
        if cli_options is None:
            self.top_number = ''
        else:
            self.top_number = int(cli_options.analyze_number)

    def analyze(self, all_ip_objects):

        if self.top_number == '':
            print "You selected the \"Virustotal\" module, how many items do you want returned?"
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

        for key, value in all_ip_objects.iteritems():
            if type(value[0].virustotal) is dict and \
                    "detected_communicating_samples" in value[0].virustotal:
                for item in value[0].virustotal["detected_communicating_samples"]:
                    if value[0].ip_address in ip_detected_samples:
                        ip_detected_samples[value[0].ip_address] += 1
                    else:
                        ip_detected_samples[value[0].ip_address] = 1
                    if item['sha256'].encode('utf-8') in unique_sha256:
                        unique_sha256[item['sha256'].encode('utf-8')] = unique_sha256[item['sha256'].encode('utf-8')] + [value[0].ip_address]
                    else:
                        unique_sha256[item['sha256'].encode('utf-8')] = [value[0].ip_address]

            if type(value[0].virustotal) is dict and \
                    "detected_urls" in value[0].virustotal:
                for any_url in value[0].virustotal["detected_urls"]:
                    if value[0].ip_address in ip_detected_urls:
                        ip_detected_urls[value[0].ip_address] += 1
                    else:
                        ip_detected_urls[value[0].ip_address] = 1
                    if any_url['url'].encode('utf-8') in unique_urls:
                        unique_urls[any_url['url'].encode('utf-8')] = unique_urls[any_url['url'].encode('utf-8')] + [value[0].ip_address]
                    else:
                        unique_urls[any_url['url'].encode('utf-8')] = [value[0].ip_address]

            if type(value[0].virustotal) is dict and \
                    "undetected_communicating_samples" in value[0].virustotal:
                for item2 in value[0].virustotal["undetected_communicating_samples"]:
                    if value[0].ip_address in ip_undetected_samples:
                        ip_undetected_samples[value[0].ip_address] += 1
                    else:
                        ip_undetected_samples[value[0].ip_address] = 1
                    if item2['sha256'].encode('utf-8') in unique_sha256:
                        undetected_256[item2['sha256'].encode('utf-8')] = undetected_256[item2['sha256'].encode('utf-8')] + [value[0].ip_address]
                    else:
                        undetected_256[item2['sha256'].encode('utf-8')] = [value[0].ip_address]

            if type(value[0].virustotal) is dict and \
                    "detected_referrer_samples" in value[0].virustotal:
                for item3 in value[0].virustotal["detected_referrer_samples"]:
                    if value[0].ip_address in ip_detected_referrer:
                        ip_detected_referrer[value[0].ip_address] += 1
                    else:
                        ip_detected_referrer[value[0].ip_address] = 1
                    if item3['sha256'].encode('utf-8') in unique_sha256:
                        referrer_samples[item3['sha256'].encode('utf-8')] = referrer_samples[item3['sha256'].encode('utf-8')] + [value[0].ip_address]
                    else:
                        referrer_samples[item3['sha256'].encode('utf-8')] = [value[0].ip_address]

            if type(value[0].virustotal_domain) is dict and \
                    "detected_urls" in value[0].virustotal_domain:
                for single_url in value[0].virustotal_domain['detected_urls']:
                    if single_url['url'] in vt_detected_domains:
                        vt_detected_domains[single_url['url']] = vt_detected_domains[single_url['url']] + [value[0].domain_name]
                    else:
                        vt_detected_domains[single_url['url']] = [value[0].domain_name]
                    if value[0].domain_name in total_detected_domains:
                        total_detected_domains[value[0].domain_name] += 1
                    else:
                        total_detected_domains[value[0].domain_name] = 1

        # iterate through sorted sha256 hash list
        sorted_256 = self.dict_sorter(unique_sha256)
        list_counter = 1
        print "*" * 70
        print helpers.color(" " * 17 + "Shared Detected Communicating Samples" + " " * 16)
        print "*" * 70
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_256))):
            sha256_tuple = sorted_256[-list_counter]
            print sha256_tuple[0]
            print "*" * 64
            print "Hash is shared across the following IPs: "
            for ip in sha256_tuple[1]:
                print helpers.color(ip)
            print "\n"
            list_counter += 1
        print
        print "*" * 70
        print helpers.color(" " * 20 + "IPs and Total Detected Samples" + " " * 20)
        print "*" * 70
        sorted_detected_ips = self.dict_sorter2(ip_detected_samples)
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_detected_ips))):
            sorted_detected_ip_tuple = sorted_detected_ips[-list_counter]
            print "*" * 64
            if sorted_detected_ip_tuple[1] is not 1:
                print helpers.color(sorted_detected_ip_tuple[0] + ": " + str(sorted_detected_ip_tuple[1])) + " detected samples"
            else:
                print helpers.color(sorted_detected_ip_tuple[0] + ": " + str(sorted_detected_ip_tuple[1])) + " detected sample"
            print "\n"
            list_counter += 1
        print


        # iterate through undetected sorted sha256 hash list
        sorted_undetected_256 = self.dict_sorter(undetected_256)
        list_counter = 1
        print "*" * 70
        print helpers.color(" " * 20 + "Undetected Communicating Samples" + " " * 20)
        print "*" * 70
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_undetected_256))):
            undetected_256_tuple = sorted_undetected_256[-list_counter]
            print undetected_256_tuple[0]
            print "*" * 64
            print "Hash is shared across the following IPs: "
            for ip in undetected_256_tuple[1]:
                print helpers.color(ip)
            print "\n"
            list_counter += 1
        print
        print "*" * 70
        print helpers.color(" " * 20 + "IPs and Total Undetected Samples" + " " * 20)
        print "*" * 70
        sorted_undetected_ips = self.dict_sorter2(ip_undetected_samples)
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_undetected_ips))):
            sorted_undetected_ip_tuple = sorted_undetected_ips[-list_counter]
            print "*" * 64
            if sorted_undetected_ip_tuple[1] is not 1:
                print helpers.color(sorted_undetected_ip_tuple[0] + ": " + str(sorted_undetected_ip_tuple[1])) + " detected samples"
            else:
                print helpers.color(sorted_undetected_ip_tuple[0] + ": " + str(sorted_undetected_ip_tuple[1])) + " detected sample"
            print "\n"
            list_counter += 1
        print

        # iterate through referrers sorted sha256 hash list
        sorted_referrer_256 = self.dict_sorter(referrer_samples)
        list_counter = 1
        print "*" * 70
        print helpers.color(" " * 20 + "Detected Referrers Samples" + " " * 20)
        print "*" * 70
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_referrer_256))):
            referrer_256_tuple = sorted_referrer_256[-list_counter]
            print referrer_256_tuple[0]
            print "*" * 64
            print "Referrer is shared across the following IPs: "
            for ip in referrer_256_tuple[1]:
                print helpers.color(ip)
            print "\n"
            list_counter += 1
        print
        print "*" * 70
        print helpers.color(" " * 20 + "IPs and Total Detected Referrers" + " " * 20)
        print "*" * 70
        sorted_referrer_ips = self.dict_sorter2(ip_detected_referrer)
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_referrer_ips))):
            sorted_referrer_ip_tuple = sorted_referrer_ips[-list_counter]
            print "*" * 64
            if sorted_referrer_ip_tuple[1] is not 1:
                print helpers.color(sorted_referrer_ip_tuple[0] + ": " + str(sorted_referrer_ip_tuple[1])) + " detected samples"
            else:
                print helpers.color(sorted_referrer_ip_tuple[0] + ": " + str(sorted_referrer_ip_tuple[1])) + " detected sample"
            print "\n"
            list_counter += 1
        print

        # iterate through sorted unique urls
        sorted_urls = self.dict_sorter(unique_urls)
        list_counter = 1
        print "*" * 70
        print helpers.color(" " * 20 + "Detected Communicating URLs" + " " * 20)
        print "*" * 70
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_urls))):
            url_tuples = sorted_urls[-list_counter]
            print url_tuples[0]
            print "*" * 64
            print "URL is shared across the following IPs: "
            for ip in url_tuples[1]:
                print helpers.color(ip)
            print "\n"
            list_counter += 1
        print
        print "*" * 70
        print helpers.color(" " * 20 + "IPs and Total Detected Communicating URLs" + " " * 20)
        print "*" * 70
        sorted_urls_ips = self.dict_sorter2(ip_detected_urls)
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_urls_ips))):
            sorted_url_tuples = sorted_urls_ips[-list_counter]
            print "*" * 64
            if sorted_url_tuples[1] is not 1:
                print helpers.color(sorted_url_tuples[0] + ": " + str(sorted_url_tuples[1])) + " detected samples"
            else:
                print helpers.color(sorted_url_tuples[0] + ": " + str(sorted_url_tuples[1])) + " detected sample"
            print "\n"
            list_counter += 1
        print

        # iterate through sorted domains
        sorted_vt_detected_domains = self.dict_sorter(vt_detected_domains)
        list_counter = 1
        print "*" * 70
        print helpers.color(" " * 20 + "Detected User-Supplied Domains" + " " * 20)
        print "*" * 70
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_vt_detected_domains))):
            domain_tuple = sorted_urls[-list_counter]
            print domain_tuple[0]
            print "*" * 64
            print "Domain is shared across the following domains: "
            for ip in domain_tuple[1]:
                print helpers.color(ip)
            print "\n"
            list_counter += 1
        print
        print "*" * 70
        print helpers.color(" " * 15 + "IPs and Total Detected Communicating URLs" + " " * 25)
        print "*" * 70
        sorted_total_detected_domains = self.dict_sorter2(total_detected_domains)
        list_counter = 1
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_total_detected_domains))):
            sorted_url_tuples = sorted_total_detected_domains[-list_counter]
            print "*" * 64
            if sorted_url_tuples[1] is not 1:
                print helpers.color(sorted_url_tuples[0] + ": " + str(sorted_url_tuples[1])) + " detected domains"
            else:
                print helpers.color(sorted_url_tuples[0] + ": " + str(sorted_url_tuples[1])) + " detected domain"
            print "\n"
            list_counter += 1
        print

        self.top_number = ''

        return

    def dict_sorter(self, data_dictionary):
        return sorted(data_dictionary.items(), key=lambda x: len(x[1]))

    def dict_sorter2(self, data_dictionary):
        return sorted(data_dictionary.items(), key=lambda x: x[1])
