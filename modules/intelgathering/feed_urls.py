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

        try:
            print "Grabbing list of TOR exit nodes.."
            req = urllib2.Request(
                'http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            tor_response = response.read()
        except NameError:
            tor_response = "Not able to grab information"
        except urllib2.HTTPError:
            tor_response = "Not able to grab information"

        try:
            print "Grabbing attacker IP list from the Animus project..."
            req = urllib2.Request(
                'https://raw.githubusercontent.com/animus-project/threat_data/master/master_lists/all_ips_frequency.txt')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            animus_lines = response.read()
        except NameError:
            animus_lines = "Not able to grab information"
        except urllib2.HTTPError:
            animus_lines = "Not able to grab information"

        try:
            print "Grabbing EmergingThreats list..."
            req = urllib2.Request(
                'http://rules.emergingthreats.net/blockrules/compromised-ips.txt')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            ethreats_response = response.read()
        except NameError:
            ethreats_response = "Not able to grab information"
        except urllib2.HTTPError:
            ethreats_response = "Not able to grab information"

        try:
            print "Grabbing AlienVault reputation list..."
            req = urllib2.Request(
                'http://reputation.alienvault.com/reputation.data')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36')
            response = urllib2.urlopen(req)
            alientvault_resp = response.read()
        except NameError:
            alientvault_resp = "Not able to grab information"
        except urllib2.HTTPError:
            alientvault_resp = "Not able to grab information"

        try:
            print "Grabbing Blocklist.de info..."
            req = urllib2.Request(
                'http://www.blocklist.de/lists/bruteforcelogin.txt')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            blocklist_resp = response.read()
        except NameError:
            blocklist_resp = "Not able to grab information"
        except urllib2.HTTPError:
            blocklist_resp = "Not able to grab information"

        try:
            print "Grabbing DragonResearch's SSH list..."
            req = urllib2.Request(
                'http://dragonresearchgroup.org/insight/sshpwauth.txt')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            drag_ssh_resp = response.read()
        except NameError:
            drag_ssh_resp = "Not able to grab information"
        except urllib2.HTTPError:
            drag_ssh_resp = "Not able to grab information"

        try:
            print "Grabbing DragonResearch's VNC list..."
            req = urllib2.Request(
                'http://dragonresearchgroup.org/insight/vncprobe.txt')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            drag_vnc_resp = response.read()
        except NameError:
            drag_vnc_resp = "Not able to grab information"
        except urllib2.HTTPError:
            drag_vnc_resp = "Not able to grab information"

        #try:
        #    print "Grabbing OpenBlock IP list..."
        #    req = urllib2.Request('http://www.openbl.org/lists/date_all.txt')
        #    req.add_header(
        #        'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
        #    response = urllib2.urlopen(req)
        #    openblock_resp = response.read()
        #except NameError:
        #    openblock_resp = "Not able to grab information"
        #except urllib2.HTTPError:
        #    openblock_resp = "Not able to grab information"

        try:
            print "Grabbing NoThinkMalware list..."
            req = urllib2.Request(
                'http://www.nothink.org/blacklist/blacklist_malware_http.txt')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            ntmalware_resp = response.read()
        except NameError:
            ntmalware_resp = "Not able to grab information"
        except urllib2.HTTPError:
            ntmalware_resp = "Not able to grab information"

        try:
            print "Grabbing NoThinkSSH list..."
            req = urllib2.Request(
                'http://www.nothink.org/blacklist/blacklist_ssh_all.txt')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            ntssh_resp = response.read()
        except NameError:
            ntssh_resp = "Not able to grab information"
        except urllib2.HTTPError:
            ntssh_resp = "Not able to grab information"

        try:
            print "Grabbing Feodo list..."
            req = urllib2.Request(
                'https://feodotracker.abuse.ch/blocklist/?download=ipblocklist')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            feodo_resp = response.read()
        except NameError:
            feodo_resp = "Not able to grab information"
        except urllib2.HTTPError:
            feodo_resp = "Not able to grab information"

        try:
            print "Grabbing antispam spam list..."
            req = urllib2.Request('http://antispam.imp.ch/spamlist')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            antispam_resp = response.read()
        except NameError:
            antispam_resp = "Not able to grab information"
        except urllib2.HTTPError:
            antispam_resp = "Not able to grab information"

        try:
            print "Grabbing malc0de list..."
            req = urllib2.Request('http://malc0de.com/bl/IP_Blacklist.txt')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            malc0de_resp = response.read()
        except NameError:
            malc0de_resp = "Not able to grab information"
        except urllib2.HTTPError:
            malc0de_resp = "Not able to grab information"

        try:
            print "Grabbing MalwareBytes list..."
            req = urllib2.Request('http://hosts-file.net/rss.asp')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            malbytes_resp = response.read()
        except NameError:
            malbytes_resp = "Not able to grab information"
        except urllib2.HTTPError:
            malbytes_resp = "Not able to grab information"

	try:
            print "Grabbing BadIPs (HTTP) list..."
            req = urllib2.Request('https://www.badips.com/get/list/http/0?age=12h')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            badips_http_resp = response.read()
        except NameError:
            badips_http_resp = "No able to grab information"
        except urllib2.HTTPError:
            badips_http_resp = "No able to grab information"

	try:
            print "Grabbing BadIPs (Bruteforce) list..."
            req = urllib2.Request('https://www.badips.com/get/list/bruteforce/0?age=12h')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            badips_bruteforce_resp = response.read()
        except NameError:
            badips_bruteforce_resp = "No able to grab information"
        except urllib2.HTTPError:
            badips_bruteforce_resp = "No able to grab information"

	try:
            print "Grabbing BadIPs (Telnet) list..."
            req = urllib2.Request('https://www.badips.com/get/list/telnet/0?age=12h')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            badips_telnet_resp = response.read()
        except:
            badips_telnet_resp = "No able to grab information"

	try:
            print "Grabbing BadIPs (Badbots) list..."
            req = urllib2.Request('https://www.badips.com/get/list/badbots/0?age=12h')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            badips_badbots_resp = response.read()
        except NameError:
            badips_badbots_resp = "No able to grab information"
        except urllib2.HTTPError:
            badips_badbots_resp = "No able to grab information"

	try:
            print "Grabbing BadIPs (SMTP) list..."
            req = urllib2.Request('https://www.badips.com/get/list/smtp/0?age=12h')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            badips_smtp_resp = response.read()
        except NameError:
            badips_smtp_resp = "No able to grab information"
        except urllib2.HTTPError:
            badips_smtp_resp = "No able to grab information"

	try:
            print "Grabbing Webiron list..."
            req = urllib2.Request('https://www.webiron.com/bot_feed//?format=json')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            webiron_resp = response.read()
        except NameError:
            webiron_resp = "No able to grab information"
        except urllib2.HTTPError:
            webiron_resp = "No able to grab information"

	try:
            print "Grabbing Techhelp list..."
            req = urllib2.Request('https://techhelplist.com/block/ip.txt')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            techhelp_resp = response.read()
        except NameError:
            techhelp_resp = "No able to grab information"
        except urllib2.HTTPError:
            techhelp_resp = "No able to grab information"

	try:
            print "Grabbing CIArmy Bad Guys list..."
            req = urllib2.Request('http://cinsscore.com/list/ci-badguys.txt')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            ciarmy_resp = response.read()
        except NameError:
            ciarmy_resp = "No able to grab information"
        except urllib2.HTTPError:
            ciarmy_resp = "No able to grab information"

	try:
            print "Grabbing Rutgers.edu list..."
            req = urllib2.Request('http://report.rutgers.edu/DROP/attackers')
            req.add_header(
                'User-agent', 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0')
            response = urllib2.urlopen(req)
            rutgers_resp = response.read()
        except NameError:
            rutgers_resp = "No able to grab information"
        except urllib2.HTTPError:
            rutgers_resp = "No able to grab information"

        for path, incoming_ip_obj in all_ips.iteritems():

            if incoming_ip_obj[0].ip_address != "":

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

                #if incoming_ip_obj[0].openblock is "":
                #    if incoming_ip_obj[0].ip_address in openblock_resp:
                #        incoming_ip_obj[0].openblock = True
                #    else:
                #        incoming_ip_obj[0].openblock = False

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

                if incoming_ip_obj[0].badips_http is "":
                    if incoming_ip_obj[0].ip_address in badips_http_resp:
                        incoming_ip_obj[0].badips_http = True
                    else:
                        incoming_ip_obj[0].badips_http = False
                if incoming_ip_obj[0].badips_bruteforce is "":
                    if incoming_ip_obj[0].ip_address in badips_bruteforce_resp:
                        incoming_ip_obj[0].badips_bruteforce = True
                    else:
                        incoming_ip_obj[0].badips_bruteforce = False

                if incoming_ip_obj[0].badips_telnet is "":
                    if incoming_ip_obj[0].ip_address in badips_telnet_resp:
                        incoming_ip_obj[0].badips_telnet = True
                    else:
                        incoming_ip_obj[0].badips_telnet = False

                if incoming_ip_obj[0].badips_badbots is "":
                    if incoming_ip_obj[0].ip_address in badips_badbots_resp:
                        incoming_ip_obj[0].badips_badbots = True
                    else:
                        incoming_ip_obj[0].badips_badbots = False

                if incoming_ip_obj[0].badips_smtp is "":
                    if incoming_ip_obj[0].ip_address in badips_smtp_resp:
                        incoming_ip_obj[0].badips_smtp = True
                    else:
                        incoming_ip_obj[0].badips_smtp = False

                if incoming_ip_obj[0].webiron is "":
                    if incoming_ip_obj[0].ip_address in webiron_resp:
                        incoming_ip_obj[0].webiron = True
                    else:
                        incoming_ip_obj[0].webiron = False

                if incoming_ip_obj[0].techhelp is "":
                    if incoming_ip_obj[0].ip_address in techhelp_resp:
                        incoming_ip_obj[0].techhelp = True
                    else:
                        incoming_ip_obj[0].techhelp = False

                if incoming_ip_obj[0].ciarmy is "":
                    if incoming_ip_obj[0].ip_address in ciarmy_resp:
                        incoming_ip_obj[0].ciarmy = True
                    else:
                        incoming_ip_obj[0].ciarmy = False

                if incoming_ip_obj[0].rutgers is "":
                    if incoming_ip_obj[0].ip_address in rutgers_resp:
                        incoming_ip_obj[0].rutgers = True
                    else:
                        incoming_ip_obj[0].rutgers = False

        return
