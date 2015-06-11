'''
This module grabs various threat/intel feeds on the internet and will store
if the IP is in any of the feeds.

List of feeds came from the isthisipbad project - go check it out!
https://github.com/jgamblin/isthisipbad
'''

import urllib2


class IntelGather:

    def __init__(self):
        self.cli_name = "FeedLists"
        self.description = "This module checks IPs against potential threat lists"

    def gather(self, all_ips):

        print "Grabbing list of TOR exit nodes.."
        response = urllib2.urlopen(
            'http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv')
        tor_response = response.read()

        print "Grabbing attacker IP list from the Animus project..."
        response = urllib2.urlopen(
            'https://raw.githubusercontent.com/animus-project/threat_data/master/master_lists/all_ips_frequency.txt')
        animus_lines = response.read()

        print "Grabbing EmergingThreats list..."
        response = urllib2.urlopen(
            'http://rules.emergingthreats.net/blockrules/compromised-ips.txt')
        ethreats_response = response.read()

        print "Grabbing AlienVault reputation list..."
        response = urllib2.urlopen(
            'http://reputation.alienvault.com/reputation.data')
        alientvault_resp = response.read()

        print "Grabbing Blocklist.de info..."
        response = urllib2.urlopen(
            'http://www.blocklist.de/lists/bruteforcelogin.txt')
        blocklist_resp = response.read()

        print "Grabbing DragonResearch's SSH list..."
        response = urllib2.urlopen(
            'http://dragonresearchgroup.org/insight/sshpwauth.txt')
        drag_ssh_resp = response.read()

        print "Grabbing DragonResearch's VNC list..."
        response = urllib2.urlopen(
            'http://dragonresearchgroup.org/insight/vncprobe.txt')
        drag_vnc_resp = response.read()

        print "Grabbing OpenBlock IP list..."
        response = urllib2.urlopen('http://www.openbl.org/lists/date_all.txt')
        openblock_resp = response.read()

        print "Grabbing NoThinkMalware list..."
        response = urllib2.urlopen(
            'http://www.nothink.org/blacklist/blacklist_malware_http.txt')
        ntmalware_resp = response.read()

        print "Grabbing NoThinkSSH list..."
        response = urllib2.urlopen(
            'http://www.nothink.org/blacklist/blacklist_ssh_all.txt')
        ntssh_resp = response.read()

        print "Grabbing Feodo list..."
        response = urllib2.urlopen(
            'http://rules.emergingthreats.net/blockrules/compromised-ips.txt')
        feodo_resp = response.read()

        print "Grabbing antispam spam list..."
        response = urllib2.urlopen('http://antispam.imp.ch/spamlist')
        antispam_resp = response.read()

        print "Grabbing malc0de list..."
        response = urllib2.urlopen('http://malc0de.com/bl/IP_Blacklist.txt')
        malc0de_resp = response.read()

        print "Grabbing MalwareBytes list..."
        response = urllib2.urlopen('http://hosts-file.net/rss.asp')
        malbytes_resp = response.read()

        for path, incoming_ip_obj in all_ips.iteritems():

            if incoming_ip_obj[0].tor_exit is "":
                if incoming_ip_obj[0].ip_address in tor_response:
                    incoming_ip_obj[0].tor_exit = True
                else:
                    incoming_ip_obj[0].tor_exit = False

            if incoming_ip_obj[0].animus_data is "":
                if incoming_ip_obj[0].ip_address in animus_lines:
                    incoming_ip_obj[0].animus_data = True
                else:
                    incoming_ip_obj[0].animus_data = False

            if incoming_ip_obj[0].emerging_threat is "":
                if incoming_ip_obj[0].ip_address in ethreats_response:
                    incoming_ip_obj[0].emerging_threat = True
                else:
                    incoming_ip_obj[0].emerging_threat = False

            if incoming_ip_obj[0].in_alienv is "":
                if incoming_ip_obj[0].ip_address in alientvault_resp:
                    incoming_ip_obj[0].in_alienv = True
                else:
                    incoming_ip_obj[0].in_alienv = False

            if incoming_ip_obj[0].blocklist_de is "":
                if incoming_ip_obj[0].ip_address in blocklist_resp:
                    incoming_ip_obj[0].blocklist_de = True
                else:
                    incoming_ip_obj[0].blocklist_de = False

            if incoming_ip_obj[0].dragon_ssh is "":
                if incoming_ip_obj[0].ip_address in drag_ssh_resp:
                    incoming_ip_obj[0].dragon_ssh = True
                else:
                    incoming_ip_obj[0].dragon_ssh = False

            if incoming_ip_obj[0].dragon_vnc is "":
                if incoming_ip_obj[0].ip_address in drag_vnc_resp:
                    incoming_ip_obj[0].dragon_vnc = True
                else:
                    incoming_ip_obj[0].dragon_vnc = False

            if incoming_ip_obj[0].openblock is "":
                if incoming_ip_obj[0].ip_address in openblock_resp:
                    incoming_ip_obj[0].openblock = True
                else:
                    incoming_ip_obj[0].openblock = False

            if incoming_ip_obj[0].nothink_malware is "":
                if incoming_ip_obj[0].ip_address in ntmalware_resp:
                    incoming_ip_obj[0].nothink_malware = True
                else:
                    incoming_ip_obj[0].nothink_malware = False

            if incoming_ip_obj[0].nothink_ssh is "":
                if incoming_ip_obj[0].ip_address in ntssh_resp:
                    incoming_ip_obj[0].nothink_ssh = True
                else:
                    incoming_ip_obj[0].nothink_ssh = False

            if incoming_ip_obj[0].feodo is "":
                if incoming_ip_obj[0].ip_address in feodo_resp:
                    incoming_ip_obj[0].feodo = True
                else:
                    incoming_ip_obj[0].feodo = False

            if incoming_ip_obj[0].antispam is "":
                if incoming_ip_obj[0].ip_address in antispam_resp:
                    incoming_ip_obj[0].antispam = True
                else:
                    incoming_ip_obj[0].antispam = False

            if incoming_ip_obj[0].malc0de is "":
                if incoming_ip_obj[0].ip_address in malc0de_resp:
                    incoming_ip_obj[0].malc0de = True
                else:
                    incoming_ip_obj[0].malc0de = False

            if incoming_ip_obj[0].malwarebytes is "":
                if incoming_ip_obj[0].ip_address in malbytes_resp:
                    incoming_ip_obj[0].malwarebytes = True
                else:
                    incoming_ip_obj[0].malwarebytes = False

        return
