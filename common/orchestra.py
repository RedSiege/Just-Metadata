'''

This is the conductor class which essentially controls everything for this
tool.

'''


import csv
import glob
import imp
import netaddr
import os
import pickle
import sys
import time
import colorama
from common import helpers
from common import ip_object
from modules.analytics import *
from modules.intelgathering import *


class Conductor:

    def __init__(self, command_args):
        # Create dictionaries of supported modules
        # empty until stuff loaded into them
        # IP Object module will be where all IPs and their objects (with info)
        # about them will be stored
        # Stored in following format {'IPAddress': [IP_Object, # Instances of IP]}
        self.system_objects = {}

        # Intel gathering transforms is used to gather information about the
        # loaded IPs
        self.intelgathering_transforms = {}

        # Analytical transforms perform actions against the IPs loaded into
        # the framework
        self.analytical_transforms = {}

        # Fix the unicode error issue
        reload(sys)
        sys.setdefaultencoding('utf-8')

        # Command line arguments
        self.cli_args = command_args

        # help_commands just contains commands to be used in the "shell"
        self.commands = {
            "analyze": "Run [module] on the loaded IP addresses",
            "export" : "Exports all data on all IPs to CSV",
            "gather" : "Requests information and gathers statistics on loaded IP addresses",
            "help   ": "Displays commands and command descriptions",
            "import ": "Import's saved state into Just Metadata",
            "ip_info": "Display's all info about an IP address",
            "load   ": "Loads IPs into the framework for analysis",
            "list   ": "Prints loaded [analysis] or [gather] modules",
            "save   ": "Saves IPs and attributes to disk for reloading in the future",
            "exit   ": "Exits out of Just-Metadata"
        }

        # command given by the user
        self.user_command = ""

        # Load the intel gathering modules
        self.load_intelgathering_functions()

        # Load the analytical modules
        self.load_analytical_functions()

    def check_cli(self):
        if self.cli_args is not None:
            sys.exit()
        return

    # This collapse function came from @harmj0y, thanks for the help with
    # it man
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

    def export_info(self):
        # Date and Time for export File
        current_date = time.strftime("%m/%d/%Y").replace("/", "")
        current_time = time.strftime("%H:%M:%S").replace(":", "")
        # True for printing the header on the first system
        # after that, only values
        add_header = True

        for path, ip_objd in self.system_objects.iteritems():
            attrs = vars(ip_objd[0])
            with open('export_' + current_date + '_' + current_time + '.csv', 'a') as export_file:
                csv_file = csv.DictWriter(export_file, attrs.keys())
                if add_header:
                    csv_file.writeheader()
                    add_header = False
                csv_file.writerow(attrs)

        print helpers.color("\nExport file saved to disk at export_" + current_date + "_" + current_time + ".csv")
        return

    def load_ips(self, file_of_systems):

        # Check to make sure file given is a valid file
        if os.path.isfile(file_of_systems):
            # read in IPs from a file
            with open(file_of_systems, "r") as system_file:
                justmetadata_system_list = system_file.readlines()
            total_systems = 0

            # Cast each IP its own object
            for system in justmetadata_system_list:
                if "/" in system:
                    try:
                        for ip in netaddr.IPSet([system]):
                            ip = str(ip)
                            activated_system_object = ip_object.IP_Information(ip)
                            if ip in self.system_objects:
                                self.system_objects[ip][1] = self.system_objects[ip][1] + 1
                                total_systems += 1
                            else:
                                self.system_objects[ip] = [activated_system_object, 1]
                                total_systems += 1
                    except netaddr.core.AddrFormatError:
                        print helpers.color("[*] Error: Bad IP CIDR range detected! (" + str(system).strip() + ")", warning=True)
                        continue
                else:
                    activated_system_object = ip_object.IP_Information(system.strip())
                    if system in self.system_objects:
                        self.system_objects[system][1] = self.system_objects[system][1] + 1
                        total_systems += 1
                    else:
                        self.system_objects[system] = [activated_system_object, 1]
                        total_systems += 1

            print helpers.color("[*] Loaded " + str(total_systems) + " systems")

        else:
            print helpers.color("\n\n[*] Error: Invalid file path provided!", warning=True)
            print helpers.color("[*] Error: Please provide the valid path to a file.", warning=True)
        return

    def load_intelgathering_functions(self):
        for name in glob.glob('modules/intelgathering/*.py'):
            if name.endswith(".py") and ("__init__" not in name):
                loaded_ig = imp.load_source(
                    name.replace("/", ".").rstrip('.py'), name)
                self.intelgathering_transforms[name] = loaded_ig.IntelGather()
        return

    def load_analytical_functions(self):
        for name in glob.glob('modules/analytics/*.py'):
            if name.endswith(".py") and ("__init__" not in name):
                loaded_analytics = imp.load_source(
                    name.replace("/", ".").rstrip('.py'), name)
                self.analytical_transforms[name] = loaded_analytics.Analytics(self.cli_args)
        return

    def menu_system(self):

        # Reinitialize colorama as sys.stdout/stderr may have changed since program started
        colorama.reinit()

        while self.user_command == "":

            try:

                if self.cli_args is not None:

                    if self.cli_args.list is not None:
                        self.run_list_command(self.cli_args.list)

                    if self.cli_args.load is not None:
                        try:
                            self.load_ips(self.cli_args.load)
                        except IndexError:
                            print helpers.color("\n\n[*] Error: Load command requires a path to a file!", warning=True)
                            print helpers.color("[*] Ex: load /root/file.txt", warning=True)
                            sys.exit()

                    if self.cli_args.file_import is not None:
                        self.run_import_command(self.cli_args.file_import)

                    if self.cli_args.gather is not None:
                        self.run_gather_command(self.cli_args.gather)

                    if self.cli_args.save:
                        self.save_state()

                    if self.cli_args.analyze is not None:
                        self.run_analyze_command(self.cli_args.analyze)

                    if self.cli_args.ip_info is not None:
                        self.run_ipinfo_command(self.cli_args.ip_info)

                    if self.cli_args.export:
                        self.export_info()

                    sys.exit()

                else:

                    while True:
                        self.user_command = raw_input(' \n\n[>] Please enter a command: ').strip()
                        helpers.print_header()

                        if self.user_command is not "":
                            # Check if command is to load IP addresses into framework
                            if self.user_command.startswith('load'):
                                try:
                                    self.load_ips(self.user_command.split()[1])
                                except IndexError:
                                    print helpers.color("\n\n[*] Error: Load command requires a path to a file!", warning=True)
                                    print helpers.color("[*] Ex: load /root/file.txt", warning=True)
                                self.user_command = ""

                            elif self.user_command.startswith('gather'):
                                try:
                                    self.run_gather_command(
                                        self.user_command.split()[1])
                                except IndexError:
                                    print helpers.color("\n\n[*] Error: Module command requires a module to load!", warning=True)
                                    print helpers.color("[*] Ex: gather geoinfo", warning=True)
                                self.user_command = ""

                            elif self.user_command.startswith('help'):
                                self.print_commands()
                                self.user_command = ""

                            elif self.user_command.startswith('exit'):
                                print helpers.color(
                                    "\n\n[!] Exiting Just Metadata..\n",
                                    warning=True)
                                sys.exit()

                            # Code for saving current state to disk
                            elif self.user_command.startswith('save'):
                                self.save_state()
                                self.user_command = ""

                            # Code for loading state from disk
                            elif self.user_command.startswith('import'):
                                try:
                                    self.run_import_command(
                                        self.user_command.split()[1])
                                except IndexError:
                                    print helpers.color("[*] Error: Please provide path to file that will be imported.", warning=True)
                                    print helpers.color("[*] Ex: import metadata1111_1111.state", warning=True)
                                self.user_command = ""

                            elif self.user_command.startswith('ip_info'):
                                try:
                                    self.run_ipinfo_command(
                                        self.user_command.split()[1])
                                except IndexError:
                                    print helpers.color("[*] Error: The \"ip_info\" command requires an IP address!", warning=True)
                                    self.check_cli()
                                self.user_command = ""

                            # This will be the export command, used to export
                            # all information into a csv file
                            elif self.user_command.startswith('export'):
                                self.export_info()
                                self.user_command = ""

                            elif self.user_command.startswith('analyze'):
                                try:
                                    self.run_analyze_command(
                                        self.user_command.split()[1])
                                except IndexError:
                                    print helpers.color("\n\n[*] Error: Analyze command requires a module to load!", warning=True)
                                    print helpers.color("[*] Ex: analyze GeoInfo", warning=True)
                                self.user_command = ""

                            elif self.user_command.startswith('list'):
                                try:
                                    self.run_list_command(
                                        self.user_command.split()[1])
                                except IndexError:
                                    print helpers.color("\n\n[*] Error: You did not provide a module type to display!", warning=True)
                                    print helpers.color("[*] Ex: list analysis", warning=True)
                                self.user_command = ""

                            else:
                                print helpers.color("\n\n[*] Error: You did not provide a valid command!", warning=True)
                                print helpers.color("[*] Type \"help\" to view valid commands", warning=True)

            except KeyboardInterrupt:
                print helpers.color("\n\n[!] You just rage quit...", warning=True)
                sys.exit()

            #except Exception as e:
            #    print helpers.color("\n\n[!] Encountered Error!", warning=True)
            #    print helpers.color(e)
            #    print helpers.color("[!] Saving state to disk...", warning=True)
            #    print helpers.color("[!] Please report this info to the developer!", warning=True)
            #    self.save_state()

        return

    def print_commands(self):
        # Function used to print all available commands
        print
        for command, description in self.commands.iteritems():
            print command + " => " + description
        return

    def run_analyze_command(self, analyze_command):
        try:
            hit_module = False
            for path, analytics_obj in self.analytical_transforms.iteritems():
                if analyze_command.lower() == 'all':
                    analytics_obj.analyze(self.system_objects)
                    hit_module = True
                elif analyze_command.lower() == analytics_obj.cli_name.lower():
                    analytics_obj.analyze(self.system_objects)
                    hit_module = True
                    break
        except IndexError:
            print helpers.color("\n\n[*] Error: Analyze command requires a module to load!", warning=True)
            print helpers.color("[*] Ex: analyze GeoInfo", warning=True)
            self.check_cli()
        if not hit_module:
            print helpers.color("\n\n[*] Error: You didn't provide a valid module!", warning=True)
            print helpers.color("[*] Please re-run and use a valid module.", warning=True)
            self.check_cli()
        return

    def run_gather_command(self, gather_module):
        gather_module_found = False
        try:
            for path, ig_obj in self.intelgathering_transforms.iteritems():
                if gather_module.lower() == 'all':
                    ig_obj.gather(self.system_objects)
                    gather_module_found = True
                elif gather_module.lower() == ig_obj.cli_name.lower():
                    ig_obj.gather(self.system_objects)
                    gather_module_found = True
                    break
            if not gather_module_found:
                print helpers.color("\n\n[*] Error: You didn't provide a valid gather module!", warning=True)
                print helpers.color("[*] Please re-run and use a valid module.", warning=True)
                self.check_cli()
        except IndexError:
            print helpers.color("\n\n[*] Error: Module command requires a module to load!", warning=True)
            print helpers.color("[*] Ex: gather geoinfo", warning=True)
            self.check_cli()
        except KeyboardInterrupt:
            print helpers.color("\n\n[*] You rage quit your intel gathering!", warning=True)
            self.check_cli()
        return

    def run_import_command(self, import_path):
        try:
            if os.path.isfile(import_path):
                try:
                    self.system_objects = pickle.load(open(import_path, 'rb'))
                    print helpers.color("[*] Successfully imported " + import_path)
                except IndexError:
                    print helpers.color("[*] Error: Invalid state file.", warning=True)
                    print helpers.color("[*] Please provide the path to a valid state file.", warning=True)
                    self.check_cli()
                except KeyError:
                    print helpers.color("[*] Error: Problem parsing your state file.", warning=True)
                    print helpers.color("[*] Error: Has it been tampered with...?", warning=True)
                    self.check_cli()
            else:
                print helpers.color("[*] Error: Please provide path to file that will be imported.", warning=True)
                self.check_cli()
        except IndexError:
            print helpers.color("[*] Error: Please provide path to file that will be imported.", warning=True)
            print helpers.color("[*] Ex: import metadata1111_1111.state", warning=True)
            self.check_cli()
        return

    def run_ipinfo_command(self, ip_addr):
        ip_found = False
        try:
            for path, ip_objd in self.system_objects.iteritems():
                if ip_objd[0].ip_address == ip_addr or ip_addr.lower() == 'all':
                    attrs = vars(ip_objd[0])
                    print ip_objd[0].ip_address
                    print "*" * 25
                    for key, value in attrs.iteritems():
                        print helpers.color(key) + ": " + self.collapse(value)
                    ip_found = True
            if not ip_found:
                print helpers.color("[*] Error: The provided IP address is not loaded in the framework!", warning=True)
                print helpers.color("[*] Error: Please provide a new IP.", warning=True)
                self.check_cli()
        except IndexError:
            print helpers.color("[*] Error: The \"ip_info\" command requires an IP address!", warning=True)
            self.check_cli()
        return

    def run_list_command(self, list_cmd):
        try:
            if len(list_cmd.split()) == 1:
                list_command = list_cmd
            else:
                list_command = list_cmd.split()[1]
            if list_command.lower() == 'analysis':
                for path, object_name in self.analytical_transforms.iteritems():
                    print object_name.cli_name + " => " + object_name.description
                print "All => Invokes all of the above Analysis modules"
            elif list_command.lower() == 'gather':
                for path, object_name in self.intelgathering_transforms.iteritems():
                    print object_name.cli_name + " => " + object_name.description
                print "All => Invokes all of the above IntelGathering modules"
        except IndexError:
            print helpers.color("\n\n[*] Error: You did not provide module type to display!", warning=True)
            print helpers.color("[*] Ex: list analysis", warning=True)
            self.check_cli()
        return

    def save_state(self):
        current_date = time.strftime("%m/%d/%Y").replace("/", "")
        current_time = time.strftime("%H:%M:%S").replace(":", "")

        # Save state to disk
        pickle.dump(self.system_objects, open(
            'metadata' + current_date + "_" + current_time
            + '.state', 'wb'))
        print helpers.color("\nState saved to disk at metadata" + current_date + "_" + current_time + ".state")
        return
