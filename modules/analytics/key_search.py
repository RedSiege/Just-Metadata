'''
This module searches the shodan data for IPs using a user-specified ssh-key
'''


from common import helpers


class Analytics:

    def __init__(self, cli_options):
        self.cli_name = "KeySearch"
        self.description = "Searches for user-provided SSH Key"
        self.ssh_key = ''
        self.found_ips = []

    def analyze(self, all_ip_objects):

        if self.ssh_key == '':
            print "Please provide the SSH Key you want to search for."
            self.ssh_key = raw_input(' \n\n[>] SSH Key: ').strip()

        for path, single_ip in all_ip_objects.iteritems():
            if single_ip[0].shodan_info is not '' and\
                'No available information within Shodan about' not in\
                    single_ip[0].shodan_info:
                for item in single_ip[0].shodan_info['data']:
                    if 'opts' in item:
                        if 'ssh' in item['opts']:
                            if 'key' in item['opts']['ssh']:
                                if self.ssh_key == item['opts']['ssh']['key'].encode('utf-8').replace('\n', '').replace('\r', ''):
                                    self.found_ips.append(single_ip[0].ip_address)

        if len(self.found_ips) > 0:
            print helpers.color("\nKey Found!")
            print "===================================="
            for ip in self.found_ips:
                print helpers.color(ip)
            print

        else:
            print helpers.color("\nKey is not found within the currently loaded data!\n", warning=True)

        self.ssh_key = ''
        self.found_ips = []

        return
