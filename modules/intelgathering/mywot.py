'''
This is a module that will request information from www.mywot.com and it will
return information about the domain's reputation
'''

import json
import urllib2
from common import helpers


class IntelGather:

    def __init__(self):
        self.cli_name = "MyWOT"
        self.description = "Requests MyWOT for domain reputation information on provided domains"
        self.api_key = ""

    def gather(self, all_ips):

        for path, incoming_ip_obj in all_ips.iteritems():

            if incoming_ip_obj[0].domain_name != "":

                if self.api_key is "":
                    print helpers.color("[*] Error: You didn't provide a MyWOT API Key!", warning=True)
                    print helpers.color("[*] Please edit the MyWOT module and add in your API Key.", warning=True)
                    print helpers.color("[*] Create an account at www.mywot.com and get a free API key.", warning=True)
                else:
                    if incoming_ip_obj[0].shodan_info is '':
                        print "Querying MyWOT for information about " + incoming_ip_obj[0].domain_name
                        try:
                            url = "http://api.mywot.com/0.4/public_link_json2?hosts=" + incoming_ip_obj[0].domain_name + "/&key=" + self.api_key
                            req = urllib2.Request(url)
                            response = urllib2.urlopen(req)
                            incoming_ip_obj[0].mywot = json.loads(response.read())
                        except urllib2.HTTPError:
                            pass
                        except ValueError:
                            print helpers.color("Error loading JSON response for " + incoming_ip_obj[0].domain_name, warning=True)
        return
