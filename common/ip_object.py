'''

This is a class that is used for each IP address.  It will contain IP,
geo location information, and everything else that can be gathered about
and IP address.
'''


class IP_Information:

    def __init__(self, provided_ip):
        self.ip_address = provided_ip
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
        self.stopforumspam = ""
