#!/usr/bin/env python


'''
This tool is designed to be used to gather information about a large number
of IP addresses and perform some analytics against them.  Ideally, it will
be extensible to easily add new functionality.
'''

import argparse
import sys
from common import helpers
from common import orchestra
from colorama import init
init()

if __name__ == '__main__':

    # print the title screen for the first "run"
    helpers.print_header()

    # Default CLI Options, should be none unless specified
    args = None

    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            add_help=False, description="Just-Metadata is a tool used to\
            gather and analyze metadata about computer systems.")
        parser.add_argument(
            '-h', '-?', '--h', '-help', '--help', action="store_true",
            help=argparse.SUPPRESS)

        load_options = parser.add_argument_group('IP load/import options')
        load_options.add_argument(
            '-l', '--load', metavar='Filename', default=None,
            help='File containing IPs to load')
        load_options.add_argument(
            '-i', '--file-import', metavar='Filename', default=None,
            help='Previously saved state to load')

        module_options = parser.add_argument_group('List modules')
        module_options.add_argument(
            '--list', metavar='[analysis] or [gather]', default=None,
            help='List modules')

        output_options = parser.add_argument_group('STDOUT options')
        output_options.add_argument(
            '--ip-info', metavar='8.8.8.8', default=None,
            help='List all known information about an IP address')

        gather_options = parser.add_argument_group('Gather Modules')
        gather_options.add_argument(
            '-g', '--gather', metavar='[intelgather module]', default=None,
            help='IntelGathering module to run')

        analyze_options = parser.add_argument_group('Analysis Modules')
        analyze_options.add_argument(
            '-a', '--analyze', metavar='[analysis module]', default=None,
            help='Analysis module to run')
        analyze_options.add_argument(
            '--analyze-number', metavar='Answer to Analysis prompt', default=10,
            help='Answer to analysis prompt (Ex: How many IPs to return, port number, etc.)')
        analyze_options.add_argument(
            '--analyze-string', metavar='Answer to Analysis prompt', default='None',
            help='Answer to analysis prompt (Ex: What country are you searching for, etc.)')

        export_options = parser.add_argument_group('Export Options')
        export_options.add_argument(
            '-e', '--export', default=False, action='store_true',
            help='Analysis module to run')
        export_options.add_argument(
            '-s', '--save', default=False, action='store_true',
            help='Save state to disk')

        # parse arguments
        args = parser.parse_args()

        if args.h:
            parser.print_help()
            sys.exit()

        if args.list is not None and args.list.lower() != 'analysis' and args.list.lower() != 'gather':
            print helpers.color("[*] The list options requires you to specify what to list!", warning=True)
            print helpers.color("[*] Ex: list analysis or list gather", warning=True)
            sys.exit()

        if args.load is None and args.file_import is None and args.list is None:
            print helpers.color("[*] You did not provide a file with IPs, or state to load!", warning=True)
            print helpers.color("[*] Please re-run and provide a file!", warning=True)
            sys.exit()

    # instantiate the orchesta object and call the main menubar
    the_conductor = orchestra.Conductor(args)
    the_conductor.menu_system()
