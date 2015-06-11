'''
This is a module that can carry out the top X (top 10 or more/less) analysis
against the IPs loaded into the framework.
'''

from common import helpers


class Analytics:

    def __init__(self):
        self.cli_name = "FeedHits"
        self.description = "Lists IPs being tracked in threat lists"
        self.tor_exit = []
        self.emerging_threat = []
        self.in_alienv = []
        self.blocklist_de = []
        self.dragon_ssh = []
        self.dragon_vnc = []
        self.openblock = []
        self.nothink_malware = []
        self.nothink_ssh = []
        self.feodo = []
        self.antispam = []
        self.malc0de = []
        self.malwarebytes = []
        self.animus_data = []

    def analyze(self, all_ip_objects):

        # Loop through all IPs looking for IPs used in attacks
        for path, ip_obj in all_ip_objects.iteritems():

            if ip_obj[0].tor_exit:
                self.tor_exit.append(ip_obj[0].ip_address)

            if ip_obj[0].animus_data:
                self.animus_data.append(ip_obj[0].ip_address)

            if ip_obj[0].emerging_threat:
                self.emerging_threat.append(ip_obj[0].ip_address)

            if ip_obj[0].in_alienv:
                self.in_alienv.append(ip_obj[0].ip_address)

            if ip_obj[0].blocklist_de:
                self.blocklist_de.append(ip_obj[0].ip_address)

            if ip_obj[0].dragon_ssh:
                self.dragon_ssh.append(ip_obj[0].ip_address)

            if ip_obj[0].dragon_vnc:
                self.dragon_vnc.append(ip_obj[0].ip_address)

            if ip_obj[0].openblock:
                self.openblock.append(ip_obj[0].ip_address)

            if ip_obj[0].nothink_malware:
                self.nothink_malware.append(ip_obj[0].ip_address)

            if ip_obj[0].nothink_ssh:
                self.nothink_ssh.append(ip_obj[0].ip_address)

            if ip_obj[0].feodo:
                self.feodo.append(ip_obj[0].ip_address)

            if ip_obj[0].antispam:
                self.antispam.append(ip_obj[0].ip_address)

            if ip_obj[0].malc0de:
                self.malc0de.append(ip_obj[0].ip_address)

            if ip_obj[0].malwarebytes:
                self.malwarebytes.append(ip_obj[0].ip_address)

        # Loop over dictionaries and check for hits
        if len(self.tor_exit) > 0:
            print "The following IPs are known TOR exit nodes:"
            for ip in self.tor_exit:
                print helpers.color(ip)
        else:
            print helpers.color("No Tor exit nodes detected!", warning=True)

        print
        if len(self.animus_data) > 0:
            print "The following IPs are included within the Animus Project's attacker list:"
            for ip in self.animus_data:
                print helpers.color(ip)
        else:
            print helpers.color("No loaded IPs are in the Animus Project's attackers list!", warning=True)

        print
        if len(self.emerging_threat) > 0:
            print "The following IPs are included in the Emerging Threats list:"
            for ip in self.emerging_threat:
                print helpers.color(ip)
        else:
            print helpers.color("No loaded IPs are in the Emerging Threats list!", warning=True)

        print
        if len(self.in_alienv) > 0:
            print "The following IPs are in Alienvault's reputation list:"
            for ip in self.in_alienv:
                print helpers.color(ip)
        else:
            print helpers.color("No loaded IPs are in Alienvault's reputation list!", warning=True)

        print
        if len(self.blocklist_de) > 0:
            print "The following IPs are on Blocklist:"
            for ip in self.blocklist_de:
                print helpers.color(ip)
        else:
            print helpers.color("No loaded IPs are within Blocklist!", warning=True)

        print
        if len(self.dragon_ssh) > 0:
            print "The following IPs are within Dragon Research's SSH list:"
            for ip in self.dragon_ssh:
                print helpers.color(ip)
        else:
            print helpers.color("No loaded IPs are within Dragon Research's SSH list!", warning=True)

        print
        if len(self.dragon_vnc) > 0:
            print "The following IPs are within Dragon Research's VNC list:"
            for ip in self.dragon_vnc:
                print helpers.color(ip)
        else:
            print helpers.color("No loaded IPs are within Dragon Research's VNC list!", warning=True)

        print
        if len(self.openblock) > 0:
            print "The following IPs are within Openblock:"
            for ip in self.openblock:
                print helpers.color(ip)
        else:
            print helpers.color("No loaded IPs are within Openblock!", warning=True)

        print
        if len(self.nothink_malware) > 0:
            print "The following IPs are within NoThink's Malware list:"
            for ip in self.nothink_malware:
                print helpers.color(ip)
        else:
            print helpers.color("No loaded IPs are within NoThink's Malware list!", warning=True)

        print
        if len(self.nothink_ssh) > 0:
            print "The following IPs are within NoThink's SSH list:"
            for ip in self.nothink_ssh:
                print helpers.color(ip)
        else:
            print helpers.color("No loaded IPs are within NoThink's SSH list!", warning=True)

        print
        if len(self.feodo) > 0:
            print "The following IPs are within the Feodo list:"
            for ip in self.feodo:
                print helpers.color(ip)
        else:
            print helpers.color("No loaded IPs are within the Feodo list!", warning=True)

        print
        if len(self.antispam) > 0:
            print "The following IPs are on an AntiSpam list:"
            for ip in self.antispam:
                print helpers.color(ip)
        else:
            print helpers.color("No loaded IPs are on an AntiSpam list!", warning=True)

        print
        if len(self.malc0de) > 0:
            print "The following IPs are within malc0de's list:"
            for ip in self.malc0de:
                print helpers.color(ip)
        else:
            print helpers.color("No loaded IPs are within malc0de's list!", warning=True)

        print
        if len(self.malwarebytes) > 0:
            print "The following IPs are within the MalwareBytes list:"
            for ip in self.malwarebytes:
                print helpers.color(ip)
        else:
            print helpers.color("No loaded IPs are within the MalwareBytes list!", warning=True)

        return
