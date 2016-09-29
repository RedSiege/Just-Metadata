'''
This is a module that gathers hostnames from bing.com for the
loaded IP addresses.
'''

import json
import re
import time
import urllib
import urllib2
from common import helpers


class IntelGather:

    def __init__(self):
        self.cli_name = "Bing_IP"
        self.description = "This module uses bing.com to search for hostnames resolving to IPs"
        # Register at https://datamarket.azure.com/dataset/bing/search
        self.api_key = ""

    def check_host(self, host):
        result = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", host)
        return result

    def gather(self, all_ips):

        for path, incoming_ip_obj in all_ips.iteritems():

            if self.api_key is "":
                print "ERROR: You did not provide a Bing API key!"
            else:
                if self.check_host(incoming_ip_obj[0].ip_address) and incoming_ip_obj[0].hostnames is '':
                    domains = []
                    raw_domains_temp = []
                    self.count = 0
                    while 1:
                        raw_domains = self.get_bing_data(incoming_ip_obj[0].ip_address)
                        if raw_domains == raw_domains_temp:
                            break
                        raw_domains_temp = raw_domains
                        if raw_domains == -1:
                            break
                        self.count += 100
                        for d in raw_domains:
                            domains.append(d)
            incoming_ip_obj[0].hostnames = domains
            print "Found %d hostnames for %s" % (len(domains), incoming_ip_obj[0].ip_address)

    def get_bing_data(self, ip):
        domains = []
        user_agent = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)'
        credentials = (':%s' % self.api_key).encode('base64')[:-1]
        auth = 'Basic %s' % credentials
        url = 'https://api.datamarket.azure.com/Bing/Search/Web?Query=%27IP:' + ip + '%27&$format=json&$skip=' + str(self.count)
        request = urllib2.Request(url)
        request.add_header('Authorization', auth)
        request.add_header('User-Agent', user_agent)
        request_opener = urllib2.build_opener()
        try:
            response = request_opener.open(request)
        except urllib2.HTTPError, e:
            if e.code == 401:
                print "ERROR: Wrong API key or not signed in!"
                return
            print "ERROR: Connection problem. Connect connect to Bing API! (HTTP error " + e.code + ")"
            return -1

        response_data = response.read()
        json_results = json.loads(response_data)

        if len(json_results['d']['results']) == 0:
            return -1

        for i in range(len(json_results['d']['results'])):
            domain = json_results['d']['results'][i]['DisplayUrl']
            # Keep only the FQDN (drop protocol, port and URI)
            domain = domain.replace("http://", "").replace("https://", "")
            fqdn = domain.split('/', 1)[0]
            fqdn = fqdn.split(':', 1)[0]
            domains.append(fqdn)

        return domains
