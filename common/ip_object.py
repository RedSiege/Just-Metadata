'''

This is a class that is used for each IP address.  It will contain IP,
geo location information, and everything else that can be gathered about
and IP address.
'''


import re
import socket


class IP_Information:

    def __init__(self, incoming_system):
        self.ip_address = ""
        self.domain_name = ""
        self.ip_country = ""
        self.ip_country_code = ""
        self.ip_city = ""
        self.ip_region_name = ""
        self.ip_region_code = ""
        self.ip_zipcode = ""
        self.ip_latitude = ""
        self.ip_longitude = ""
        self.ip_isp = ""
        self.ip_organization = ""
        self.ip_as_number = ""
        self.ip_whois = ""
        self.ip_timezone = ""
        self.shodan_info = ""
        self.virustotal = ""
        self.virustotal_domain = ""
        self.animus_data = ""
        self.tor_exit = ""
        self.emerging_threat = ""
        self.in_alienv = ""
        self.blocklist_de = ""
        self.dragon_ssh = ""
        self.dragon_vnc = ""
        self.openblock = ""
        self.nothink_malware = ""
        self.nothink_ssh = ""
        self.feodo = ""
        self.antispam = ""
        self.malc0de = ""
        self.malwarebytes = ""
        self.mywot = ""
        self.dshield = ""

        if self.check_ip(incoming_system):
            self.ip_address = incoming_system
        else:
            self.domain_name = incoming_system
            try:
                self.ip_address = socket.gethostbyname(incoming_system)
            except socket.gaierror:
                # This hits when we can't resolve an IP from a provided domain name
                pass

    def check_ip(self, host):
        result = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", host)
        return result
