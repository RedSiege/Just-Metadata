'''
This is a module that gathers dshield information about the
loaded IP addresses.
'''

import json
import re
import time
import urllib
from common import helpers


class IntelGather:

    def __init__(self):
        self.cli_name = "DShield"
        self.description = "This module checks DShield for hits on loaded IPs"
        self.api_url = 'https://isc.sans.edu/api/ip/'

    def check_host(self, host):
        result = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", host)
        return result

    # This collapse function came from @harmj0y, thanks for the help with
    # it man
    def collapse(self, var, tabs=0):
        result = ""

        if type(var) is dict:
            for field, value in var.iteritems():
                result += "\n" + tabs * "\t" + field + ": " + self.collapse(
                    value, tabs=(tabs + 1))

        elif type(var) is list:
            for l in var:
                result += self.collapse(l, tabs=tabs) + "\n"

        else:
            result += str(var)
        return result

    def gather(self, all_ips):

        for path, incoming_ip_obj in all_ips.iteritems():

            if self.check_host(incoming_ip_obj[0].ip_address) and incoming_ip_obj[0].dshield is '':
		full_url = self.api_url + incoming_ip_obj[0].ip_address + '?json'
                try:
                    response = urllib.urlopen(full_url).read()
                    json_response = json.loads(response)['ip']

                    if json_response['count'] == None:
                        print "No information within DShield for " + incoming_ip_obj[0].ip_address
                        incoming_ip_obj[0].dshield = "No information within DShield for " + incoming_ip_obj[0].ip_address
                    else:
                        print "Information found on " + incoming_ip_obj[0].ip_address
                        incoming_ip_obj[0].dshield = json_response
                    time.sleep(16)
                except IOError:
                    print "Error while connecting to DShield for " + incoming_ip_obj[0].ip_address
                except ValueError:
                    print "Error loading JSON response for " + incoming_ip_obj[0].ip_address

        return
