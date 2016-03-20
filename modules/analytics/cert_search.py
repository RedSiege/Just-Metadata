'''
This module searches the shodan data for IPs using a user-specified https certificate
'''


from common import helpers


class Analytics:

    def __init__(self, cli_options):
        self.cli_name = "CertSearch"
        self.description = "Searches for user-provided HTTPS certificate"
        self.https_cert = ''
        self.found_ips = []

    def analyze(self, all_ip_objects):

        if self.https_cert == '':
            print "Please provide the HTTPS certificate you want to search for."
            self.https_cert = raw_input(' \n\n[>] HTTPS Cert (including start and end tags): ').strip()

        for path, single_ip in all_ip_objects.iteritems():
            if single_ip[0].shodan_info is not '' and\
                'No available information within Shodan about' not in\
                    single_ip[0].shodan_info:
                for item in single_ip[0].shodan_info['data']:
                    if 'opts' in item:
                        if 'pem' in item['opts']:
                            if self.https_cert.strip() in item['opts']['pem'].encode('utf-8').replace('\n', '').replace('\r', ''):
                                self.found_ips.append(single_ip[0].ip_address)

        if len(self.found_ips) > 0:
            print helpers.color("\nCertificate Found!")
            print "===================================="
            for ip in self.found_ips:
                print helpers.color(ip)
            print

        else:
            print helpers.color("\nCertificate is not found within the currently loaded data!\n", warning=True)

        self.https_cert = ''
        self.found_ips = []

        return
