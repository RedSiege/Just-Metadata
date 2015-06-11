#!/usr/bin/env python


'''
This tool is designed to be used to gather information about a large number
of IP addresses and perform some analytics against them.  Ideally, it will
be extensible to easily add new functionality.
'''

from common import helpers
from common import orchestra

if __name__ == '__main__':

    # print the title screen for the first "run"
    helpers.print_header()

    # instantiate the orchesta object and call the main menubar
    the_conductor = orchestra.Conductor()
    the_conductor.menu_system()
