'''
This is a module that lists all IPs loaded into Just-Metadata
'''

import struct
from socket import inet_aton


class Analytics:

    def __init__(self, cli_options):
        self.cli_name = "ListIPs"
        self.description = "Lists all IPs loaded into Just-Metadata"

    def analyze(self, all_ip_objects):

        # Creating Dictionaries for top values
        loaded_ips = []

        # Looping over IP address objects
        for key, value in all_ip_objects.iteritems():
            loaded_ips.append(key.strip())

        # from - https://stackoverflow.com/questions/6545023/how-to-sort-ip-addresses-stored-in-dictionary-in-python/6545088#6545088
        loaded_ips = sorted(loaded_ips, key=lambda ip: struct.unpack("!L", inet_aton(ip))[0])

        for loaded_ip in loaded_ips:
            print(loaded_ip)

        return
