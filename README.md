coisc
========

Coisc (Irish for "block") is a tool for generating advertising,
malware and tracking blocks on a level beyond the browser. The tool
harvests blacklists over HTTP and writes out files to implement
blocking in multiple formats.

Coisc can be used to write a hosts file to block undesired hosts via /etc/hosts for a single computer, or to configure a DNS server that provides DNS for whole networks. For example, this functionality is ideal for blocking advertising and tracking hosts for every device on a home network, including devices that do not have native adblocking (iOS devices and others). This pattern also works on DNS servers for VPN clients for mobile devices etc.

Example use
--------
```coisc.py --output /etc/dnsmasq.d/adblocks --format dnsmasq```

Configuration
--------
Block sources can be added by including them in the ```blocks*.txt``` files. ```blocks-hosts_style.txt``` is specifically for sites that host lists in hosts-file notation (ie with an IP address provided).

The `-D` flag can be used to write top-level blocks for domains based on the contents of a file. Domains are simply listed separated by newlines. Currently this functionality is only supported when using the dnsmasq output format. For example, a file named `domains.txt` containing
```
example.com
example.edu
```
And processed with the command
```
./coisc.py -D blockdomains.txt  -o /tmp/dnsmasqblock --format dnsmasq
```
Will generate a file (`/tmp/dnsmasqblock`) containing (amongst other lines):
```
domain=/example.com/127.0.0.1
domain=/example.edu/127.0.0.1
```
Which will block the top level and all subdomains of example.com and example.edu.

A brief list of location tracking/marketing is available in the file `location_services_domains.txt`.

Currently supported formats
--------
* ```/etc/hosts``` style
* [dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) ```address``` entries
* bind A records

Caveats
--------
* There are some basic protections in place to avoid issues with the hosts files, but no assurances can be made about hosts files and how a malicious actor could coopt the block lists to harm users.
* Be courteous about how often you run the script or how it is automated.
* If writing out /etc/hosts style files, use additional templating or concatenation to ensure that you don't overwrite existing labels for things like localhost.
