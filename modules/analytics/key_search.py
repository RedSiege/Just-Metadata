'''
This module searches the shodan data for IPs using a user-specified ssh-key
'''


from common import helpers


class Analytics:

    def __init__(self, cli_options):
        self.cli_name = "KeySearch"
        self.description = "Searches for user-provided SSH Key"
        self.ssh_key = ''
        self.key_found = False

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
                                    print helpers.color("\nKey Found!")
                                    print "===================================="
                                    print helpers.color(single_ip[0].ip_address)
                                    print
                                    self.key_found = True

        if not self.key_found:
            print helpers.color("\nKey is not found within the currently loaded data!\n", warning=True)

        self.ssh_key = ''
        self.key_found = False

        return

    def dict_sorter(self, data_dictionary):
        return sorted(data_dictionary.items(), key=lambda x: len(x[1]))
