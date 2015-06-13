# Just-Metadata

Just-Metadata is a tool that can be used to gather intelligence information passively about a large number of IP addresses, and attempt to extrapolate relationships that might not otherwise be seen.  Just-Metadata has "gather" modules which are used to gather metadata about IPs loaded into the framework across multiple resources on the internet.  Just-Metadata also has "analysis" modules.  These are used to analyze the data loaded Just-Metadata and perform various operations that can identify potential relationships between the loaded systems.

Just-Metadata will allow you to quickly find the Top "X" number of states, cities, timezones, etc. that the loaded IP addresses are located in.  It will allow you to search for IP addresses by country.  You can search all IPs to find which ones are used in callbacks as identified by VirusTotal.  Want to see if any IPs loaded have been documented as taking part of attacks via the Animus Project, Just-Metadata can do it.

Additionally, it is easy to create new analysis modules to let people find other relationships between IPs loaded based on the available data.  New intel gathering modules can be easily added in just as easily!

## Setup

Ideally, you should be able to run the setup script, and it will install everything you need.

For the Shodan information gathering module, YOU WILL NEED a Shodan API key.  This costs like $9 bucks, come on now, it's worth it :).

## Usage

As of now, Just metadata is designed to read in a single text file containing IPs, each on their own new line.  Create this file from any source (C2 callback IPs, web server logs, etc.).  Once you have this file, start Just-Metadata by calling it:

*./Just-Metadata.py*

## Commands

**help** - Once in the framework, to see a listing of available commands and a description of what they do, type the "help" command.

**load &lt;filename&gt;** - The load command takes an extra parameter, the file name that you (the user) want Just-Metadata to load IP addresses from.  This command will open, and load all IPs within the file to the framework.

Ex: load ipaddresses.txt

**save** - The save command can be used to save the current working state of Just-Metadata.  This is helpful in multiple cases, such as after gathering information about IPs, and wanting to save the state off to disk to be able to work on them at a later point in time.  Simply typing "save" will result in Just-Metadata saving the state to disk, and displaying the filename of the saved state.

**import &lt;statefile&gt;** - The import command can be used to load a previously saved Just-Metadata state into the framework.  It will load all IPs that were saved, and all information gathered about the IP addresses.  This command will require an extra parameter, the name of the state file that you want Just-Metadata to load.

Ex: import goodfile.state

**list &lt;module type&gt;** - The list command can be used to list the different types of modules loaded into Just-Metadata.  This command will take an extra parameter, either "analysis" or "gather".  Just-Metadata will display all mofules of the type that the user requests is listed.

Ex: list analysis

Ex: list gather

**gather &lt;gather module name&gt;** - The gather command tells Just-Metadata to run the module specified and gather information from that source.  This can be used to gather geographical information, Virustotal, whois, and more.  It's all based on the module.  The data gathered will be stored within the framework in memory and can also be saved to disk with the "save" command.

Ex: gather geoinfo

Ex: gather virustotal

**analyze &lt;analysis module name&gt;** - The analyze command tells Metadata to run an analysis module against the data loaded into the framework.  These modules can be used to find IP addresses that share the same SSH keys or SSL Public Key certificates, or certificate chains.  They can also be used to find IP addresses used in the same callbacks by malicious executables.

**ip_info &lt;IP Address&gt;** - This command is used to dump all information about a specific IP address.  This is currently being used after having run analysis modules.  For example, after identifying IP addresses that share the same SSH keys, I can dump all information about those IPs.  I will see if they have been used by malware, where they are located, etc.

**export** - The export command will have Just-Metadata dump all information that's been gathered about all IP addresses currently loaded into the framework to CSV.

## Thanks

Thanks to Justin Warner (@sixdub) for helping to give me some initial feedback, design ideas, and act as a sounding board during development!
