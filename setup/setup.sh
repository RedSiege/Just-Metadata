#!/bin/bash

# Global Variables
userid=`id -u`
osinfo=`cat /etc/issue|cut -d" " -f1|head -n1`

# Clear Terminal (For Prettyness)
clear

# Print Title
echo '#######################################################################'
echo '#                       Just-Metadata Setup                           #'
echo '#######################################################################'
echo

# Check to make sure you are root!
# Thanks to @themightyshiv for helping to get a decent setup script out
if [ "${userid}" != '0' ]; then
  echo '[Error]: You must run this setup script with root privileges.'
  echo
  exit 1
fi

# OS Specific Installation Statement
case ${osinfo} in
  # Kali Dependency Installation
  Kali)
    echo '[*] Installing Kali Dependencies'
    apt-get install -y python-pip
    easy_install -U pip
    pip install ipwhois
    pip install ipwhois --upgrade
    pip install requests
    pip install requests --upgrade
    pip install shodan
    pip install shodan --upgrade
    pip install netaddr
    pip install netaddr --upgrade
	# Finish Message
	echo '[*] Setup script completed successfully, enjoy Just-Metadata! :)'
  ;;
  # Debian 7+ Dependency Installation
  Debian)
    echo '[*] Installing Debian Dependencies'
    apt-get install -y python-pip
    easy_install -U pip
    pip install ipwhois
    pip install ipwhois --upgrade
    pip install requests
    pip install requests --upgrade
    pip install shodan
    pip install shodan --upgrade
    pip install netaddr
    pip install netaddr --upgrade
    echo
	# Finish Message
	echo '[*] Setup script completed successfully on Debian, enjoy Just-Metadata! :)'
  ;;
  # Ubuntu (tested in 13.10) Dependency Installation
  Ubuntu)
    echo '[*] Installing Ubuntu Dependencies'
    apt-get install -y python-pip
    easy_install -U pip
    papt-get install python-colorama
    pip install ipwhois
    pip install ipwhois --upgrade
    pip install requests
    pip install requests --upgrade
    pip install shodan
    pip install shodan --upgrade
    pip install netaddr
    pip install netaddr --upgrade
    echo
    echo
	# Finish Message
	echo '[*] Setup script completed successfully on Ubuntu, enjoy Just-Metadata! :)'
	cat /etc/issue
	uname -a
  ;;
  *)
  	echo '[!] Error:  Unable to recognize operating system.'
	echo '[*] In order to use Just-Metadata, you must manually install '
	echo '[*] and update pip, and the ipwhois, requests, and shodan python modules.'
	echo
  ;;
esac

echo
