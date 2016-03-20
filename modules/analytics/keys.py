'''
This module finds all systems that have the same public keys (https or ssh)
'''

# No available information within Shodan about 190.90.112.8

from common import helpers


class Analytics:

    def __init__(self, cli_options):
        self.cli_name = "Keys"
        self.description = "Returns IP Addresses with shared public keys (SSH, SSL)"
        if cli_options is None:
            self.top_number = ''
        else:
            self.top_number = int(cli_options.analyze_number)

    def analyze(self, all_ip_objects):

        if self.top_number == '':
            print "You selected \"Keys\" module, how many items do you want returned?"
            print "Ex: 10"
            self.top_number = int(raw_input(' \n\n[>] Return the Top: ').strip())

        ssh_keys = {}
        https_keys = {}
        chain_keys = {}

        for path, single_ip in all_ip_objects.iteritems():
            ssh_jailbreak = False
            https_jailbreak = False
            chain_jailbreak = False
            if single_ip[0].shodan_info is not '' and\
                'No available information within Shodan about' not in\
                    single_ip[0].shodan_info:
                for item in single_ip[0].shodan_info['data']:
                    if 'opts' in item:
                        if 'ssh' in item['opts']:
                            if 'key' in item['opts']['ssh']:
                                if item['opts']['ssh']['key'].encode('utf-8') in ssh_keys:
                                    for ip_addrs in ssh_keys[item['opts']['ssh']['key']]:
                                        if ip_addrs == single_ip[0].ip_address:
                                            ssh_jailbreak = True
                                            break
                                    if not ssh_jailbreak:
                                        ssh_keys[item['opts']['ssh']['key'].encode('utf-8')] = ssh_keys[item['opts']['ssh']['key'].encode('utf-8')] + [single_ip[0].ip_address]
                                else:
                                    ssh_keys[item['opts']['ssh']['key'].encode('utf-8')] = [single_ip[0].ip_address]
                        if 'pem' in item['opts']:
                            if item['opts']['pem'].encode('utf-8') in https_keys:
                                for ip_addrs in https_keys[item['opts']['pem']]:
                                    if ip_addrs == single_ip[0].ip_address:
                                        https_jailbreak = True
                                        break
                                if not https_jailbreak:
                                    https_keys[item['opts']['pem'].encode('utf-8')] = https_keys[item['opts']['pem'].encode('utf-8')] + [single_ip[0].ip_address]
                            else:
                                https_keys[item['opts']['pem'].encode('utf-8')] = [single_ip[0].ip_address]
                    if 'ssl' in item:
                        if 'chain' in item['ssl']:
                            for chain_cert in item['ssl']['chain']:
                                if chain_cert.encode('utf-8') in chain_keys:
                                    for ip_addrs in chain_keys[chain_cert]:
                                        if ip_addrs == single_ip[0].ip_address:
                                            chain_jailbreak = True
                                            break
                                    if not chain_jailbreak:
                                        chain_keys[chain_cert.encode('utf-8')] = chain_keys[chain_cert.encode('utf-8')] + [single_ip[0].ip_address]
                                else:
                                    chain_keys[chain_cert.encode('utf-8')] = [single_ip[0].ip_address]

        # iterate through sorted unique ssh keys
        sorted_ssh_keys = self.dict_sorter(ssh_keys)
        list_counter = 1
        print "*" * 70
        print helpers.color(" " * 20 + "Shared SSH Keys" + " " * 20)
        print "*" * 70
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_ssh_keys))):
            sorted_ssh_tuple = sorted_ssh_keys[-list_counter]
            print sorted_ssh_tuple[0]
            print "*" * 64
            print "SSH Key is shared across the following IPs: "
            for ip in sorted_ssh_tuple[1]:
                print helpers.color(ip)
            print "\n"
            list_counter += 1
        print

        # Iterate over shared https certificates
        sorted_https_keys = self.dict_sorter(https_keys)
        list_counter = 1
        print "*" * 70
        print helpers.color(" " * 20 + "Shared HTTPS Certificates" + " " * 20)
        print "*" * 70
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_https_keys))):
            sorted_https_tuple = sorted_https_keys[-list_counter]
            print sorted_https_tuple[0]
            print "*" * 64
            print "HTTPS Certificate is shared across the following IPs: "
            for ip in sorted_https_tuple[1]:
                print helpers.color(ip)
            print "\n"
            list_counter += 1
        print

        # Iterate over shared certificate
        sorted_chain_keys = self.dict_sorter(chain_keys)
        list_counter = 1
        print "*" * 70
        print helpers.color(" " * 20 + "Shared Certificate Chain" + " " * 20)
        print "*" * 70
        while ((list_counter <= self.top_number) and ((list_counter -1) != len(sorted_chain_keys))):
            sorted_chain_tuple = sorted_chain_keys[-list_counter]
            print sorted_chain_tuple[0]
            print "*" * 64
            print "Certificate Chain is shared across the following IPs: "
            for ip in sorted_chain_tuple[1]:
                print helpers.color(ip)
            print "\n"
            list_counter += 1
        print

        self.top_number = ''

        return

    def dict_sorter(self, data_dictionary):
        return sorted(data_dictionary.items(), key=lambda x: len(x[1]))
