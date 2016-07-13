'''
This module gathers geographical information about IP addresses loaded in 
the framework.  It uses ip-api.com
'''

import json
import time
import urllib2
from common import helpers


class IntelGather:

    def __init__(self):
        self.cli_name = "GeoInfo"
        self.description = "This script gathers geographical information about the loaded\n\t   IP addresses"

    # This will sort the dictionary passed into it (or called on itself)
    def dict_sorter(self, data_dictionary):
        return sorted(data_dictionary.items(), key=lambda x: x[1])

    def gather(self, all_ips):

        for path, incoming_ip_obj in all_ips.iteritems():

            if incoming_ip_obj[0].ip_address != "" and incoming_ip_obj[0].ip_country == "":

                # Make request for information about IPs
                print "Getting info on... " + incoming_ip_obj[0].ip_address
                try:
                    response = urllib2.urlopen('http://ip-api.com/json/' + incoming_ip_obj[0].ip_address)
                    json_response = response.read()
                    decoded_json = json.loads(json_response)

                    # Check for failed response (such as a reserved range)
                    if decoded_json['status'].encode('utf-8') == "fail":
                        print helpers.color("[*] Could not retrieve information for " + incoming_ip_obj[0].ip_address, warning=True)
                    else:

                        # Load info into IP object
                        if decoded_json['as'].encode('utf-8') is not '':
                            incoming_ip_obj[0].ip_as_number = decoded_json['as'].encode('utf-8')
                        if decoded_json['country'].encode('utf-8') is not '':
                            incoming_ip_obj[0].ip_country = decoded_json['country'].encode('utf-8')
                        if decoded_json['countryCode'].encode('utf-8') is not '':
                            incoming_ip_obj[0].ip_country_code = decoded_json['countryCode'].encode('utf-8')
                        if decoded_json['city'].encode('utf-8') is not '':
                            incoming_ip_obj[0].ip_city = decoded_json['city'].encode('utf-8')
                        if decoded_json['zip'].encode('utf-8') is not '':
                            incoming_ip_obj[0].ip_zipcode = decoded_json['zip'].encode('utf-8')
                        if decoded_json['isp'].encode('utf-8') is not '':
                            incoming_ip_obj[0].ip_isp = decoded_json['isp'].encode('utf-8')
                        if decoded_json['lat'] is not '':
                            incoming_ip_obj[0].ip_latitude = str(decoded_json['lat'])
                        if decoded_json['lon'] is not '':
                            incoming_ip_obj[0].ip_longitude = str(decoded_json['lon'])
                        if decoded_json['region'].encode('utf-8') is not '':
                            incoming_ip_obj[0].ip_region_code = decoded_json['region'].encode('utf-8')
                        if decoded_json['regionName'].encode('utf-8') is not '':
                            incoming_ip_obj[0].ip_region_name = decoded_json['regionName'].encode('utf-8')
                        if decoded_json['timezone'].encode('utf-8') is not '':
                            incoming_ip_obj[0].ip_timezone = decoded_json['timezone'].encode('utf-8')
                        if decoded_json['org'].encode('utf-8') is not '':
                            incoming_ip_obj[0].ip_organization = decoded_json['org'].encode('utf-8')

                except urllib2.URLError:
                    print helpers.color("[!] Cannot receive IP Geo Information from source!", warning=True)
                    print helpers.color("[!] Moving to the next IP address...", warning=True)

                except (IOError, httplib.HTTPException):
                    print helpers.color("[!] Cannot receive IP Geo Information from source!", warning=True)
                    print helpers.color("[!] Moving to the next IP address...", warning=True)

                # Sleep is here to make sure we don't go over API limits
                time.sleep(.5)
        return
