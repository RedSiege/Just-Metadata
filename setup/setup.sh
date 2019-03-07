#!/bin/bash

# Global Variables
userid=`id -u`
osinfo=`cat /etc/issue|cut -d" " -f1|head -n1`

if [ -z "$osinfo" ]; then
    osinfo=`uname -s`
fi



# Clear Terminal (For Prettyness)
clear

# Print Title
echo '#######################################################################'
echo '#                       Just-Metadata Setup                           #'
echo '#######################################################################'
echo

SUDO=" "
# Check to make sure you are root!
# Thanks to @themightyshiv for helping to get a decent setup script out
if [ "${userid}" != '0' ]; then
    if type -path sudo >/dev/null 2>&1 ; then
        SUDO="sudo "
    else
        echo '[Error]: You must run this setup script with root privileges.' >&2
        echo
        exit 1
    fi
fi

# Install pip if needed
if ! type -path "pip" >/dev/null 2>&1 ; then
    if [ "$osinfo" = "Darwin" -a -x /opt/local/bin/port ]; then
        $SUDO port selfupdate
        $SUDO port -y install py-pip
    elif [ "$osinfo" = "Darwin" -a -x /usr/local/bin/brew ]; then
        brew update
        brew install python
    elif [ -x /usr/bin/apt-get ]; then
        $SUDO apt-get install -y python-pip
    fi

    #Following 2 blocks are fallbacks if we still don't have pip
    if ! type -path "pip" >/dev/null 2>&1 && type -path easy_install >/dev/null 2>&1 ; then
        $SUDO easy_install -U pip
    fi

    if ! type -path "pip" >/dev/null 2>&1 ; then
        $SUDO python -m ensurepip
    fi

    if ! type -path "pip" >/dev/null 2>&1 ; then
        echo 'Unable to find or install pip.  Please install it and rerun this setup script.' >&2
        exit 1
    fi
fi


# OS Specific Installation Statement
case ${osinfo} in
    # Kali/Debian 7+/Ubuntu (tested in 13.10)/Deepin (tested in 15.5)/Darwin(macos) Dependency Installation
    Kali|Debian|Ubuntu|Deepin|Darwin)
        echo '[*] Installing '"$osinfo"' Dependencies'
	if [ "$osinfo" = "Ubuntu" -o "$osinfo" = "Deepin" ]; then
		$SUDO apt-get install -y python-colorama
	else
		$SUDO -H pip install colorama
		$SUDO -H pip install colorama --upgrade
	fi
	for one_pkg in ipwhois requests shodan netaddr simplejson ; do
		$SUDO -H pip install "$one_pkg"
		$SUDO -H pip install "$one_pkg" --upgrade
	done
	# Finish Message
	echo -e '\n\n[*] Setup script completed successfully on '"$osinfo"', enjoy Just-Metadata! :)'
	if [ "$osinfo" = "Deepin" ]; then
            cat /etc/issue
            uname -a
	fi
        ;;
    *)
        echo "[!] Error:  Unable to recognize operating system. (${osinfo})" >&2
        echo '[*] In order to use Just-Metadata, you must manually install ' >&2
        echo '[*] and update pip, and the ipwhois, requests, shodan, netaddr, and simplejson python modules.' >&2
        echo >&2
        exit 1
        ;;
esac

echo
