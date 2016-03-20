'''
This is a module that gathers virustotal information about the
loaded IP addresses.
'''

from common import helpers


class IntelGather:

    def __init__(self):
        self.cli_name = "PassiveTotal"
        self.description = "This module checks PassiveTotal for information on loaded systems"
        self.api_key = ""
        self.api_url = 'https://api.passivetotal.org/v2/'

    def gather(self, all_ips):

        for path, incoming_ip_obj in all_ips.iteritems():

            pass

        return
