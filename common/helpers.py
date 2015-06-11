'''
This is a helpers file that contains miscellaneous functions used throughout
the tool.
'''

import os


def print_header():
    os.system('clear')
    print "#" * 80
    print "#" + " " * 32 + "Just-Metadata" + " " * 33 + "#"
    print "#" * 80
    return


# Taken from veil-evasion
def color(string, status=True, warning=False, bold=True):
    """
    Change text color for the linux terminal, defaults to green.
    Set "warning=True" for red.
    """
    attr = []
    if status:
        # green
        attr.append('32')
    if warning:
        # red
        attr.append('31')
    if bold:
        attr.append('1')
    return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
