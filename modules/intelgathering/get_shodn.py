'''
This is a module that will request Shodan for information about each IP
address passed into it.
'''

import shodan
import simplejson
from common import helpers


class IntelGather:

    def __init__(self):
        self.cli_name = "Shodan"
        self.description = "Requests Shodan for information on provided IPs"
        self.api_key = ""
        self.api_object = shodan.Shodan(self.api_key)

    def collapse(self, var, tabs=0):
        result = ""

        if type(var) is dict:
            for field, value in var.iteritems():
                try:
                    result += "\n" + tabs * "\t" + field.encode('utf-8') + ": " + self.collapse(
                        value, tabs=(tabs + 1))
                except UnicodeDecodeError:
                    result += "\n" + tabs * "\t" + field.encode('utf-8') + ": " + self.collapse(
                        value.encode('utf-8'), tabs=(tabs + 1))

        elif type(var) is list:
            for l in var:
                result += self.collapse(l, tabs=tabs) + "\n"

        elif var is None:
            result += "No Information Available"

        elif type(var) is float or type(var) is int or type(var) is long\
                or type(var) is bool:
            result += str(var)

        else:
            result += str(var.encode('utf-8'))
        return result

    def gather(self, all_ips):

        for path, incoming_ip_obj in all_ips.iteritems():

            if incoming_ip_obj[0].shodan_info == "" and incoming_ip_obj[0].ip_address != "":

                if self.api_key is "":
                    print helpers.color("[*] Error: You didn't provide a Shodan API Key!", warning=True)
                    print helpers.color("[*] Please edit Shodan module and add in your API Key.", warning=True)
                else:
                    if incoming_ip_obj[0].shodan_info is '':
                        print "Querying Shodan for information about " + incoming_ip_obj[0].ip_address
                        try:
                            json_result = self.api_object.host(incoming_ip_obj[0].ip_address)
                            incoming_ip_obj[0].shodan_info = json_result
                        except shodan.exception.APIError:
                            incoming_ip_obj[0].shodan_info = "No available information within Shodan about " + incoming_ip_obj[0].ip_address
                        except simplejson.decoder.JSONDecodeError:
                            pass
        return
