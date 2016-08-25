'''
This is a module that gathers virustotal information about the
loaded IP addresses.
'''

import json
import re
import time
import urllib
from common import helpers


class IntelGather:

    def __init__(self):
        self.cli_name = "VirusTotal"
        self.description = "This module checks VirusTotal for hits on loaded IPs"
        self.api_key = ["49858c37eb67ff5a1d1f3785e7a9fc06462e097e3a3cfc8a5b2bf6e7d9fb60d4", "319e86293eac1462bf211189b392c6fd234b966e1e1423f7fd5c797f4bcf8918"]
        self.api_url = 'https://www.virustotal.com/vtapi/v2/'
        self.num_api_keys = len(self.api_key)

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
        current_key = 0
        for path, incoming_ip_obj in all_ips.iteritems():

            if current_key < self.num_api_keys:

                if self.check_host(incoming_ip_obj[0].ip_address) and incoming_ip_obj[0].virustotal is '':
                    request_url = self.api_url + 'ip-address/report?'
                    parameters = {'ip': incoming_ip_obj[0].ip_address, 'apikey': self.api_key[current_key]}
                    encoded_params = urllib.urlencode(parameters)
                    full_url = request_url + encoded_params
                    try:
                        response = urllib.urlopen(full_url).read()
                        json_response = json.loads(response)

                        if json_response['response_code'] == 0:
                            print "No information within VirusTotal for " + incoming_ip_obj[0].ip_address
                            incoming_ip_obj[0].virustotal = "No information within VirusTotal for " + incoming_ip_obj[0].ip_address
                        else:
                            print "Information found on " + helpers.color(incoming_ip_obj[0].ip_address)
                            incoming_ip_obj[0].virustotal = json_response

                    except IOError:
                        print helpers.color("Error while connecting to Virustotal for " + incoming_ip_obj[0].ip_address, warning=True)
                    except ValueError:
                        print helpers.color("Error loading JSON response for " + incoming_ip_obj[0].domain_name, warning=True)
                    current_key += 1

                if incoming_ip_obj[0].domain_name != "" and incoming_ip_obj[0].virustotal_domain is '':
                    request_url = self.api_url + 'domain/report?'
                    parameters = {'domain': incoming_ip_obj[0].domain_name, 'apikey': self.api_key[current_key]}
                    encoded_params = urllib.urlencode(parameters)
                    full_url = request_url + encoded_params
                    try:
                        response = urllib.urlopen(full_url).read()
                        json_response = json.loads(response)

                        if json_response['response_code'] == 0:
                            print "No information within VirusTotal for " + incoming_ip_obj[0].domain_name
                            incoming_ip_obj[0].virustotal_domain = "No information within VirusTotal for " + incoming_ip_obj[0].ip_address
                        else:
                            print "Information found on " + helpers.color(incoming_ip_obj[0].domain_name)
                            incoming_ip_obj[0].virustotal_domain = json_response

                    except IOError:
                        print helpers.color("Error while connecting to Virustotal for " + incoming_ip_obj[0].domain_name, warning=True)
                    except ValueError:
                        print helpers.color("Error loading JSON response for " + incoming_ip_obj[0].domain_name, warning=True)
                    current_key += 1

            else:
                time.sleep(16)
                current_key = 0

        return
