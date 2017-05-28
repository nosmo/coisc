coisc
========

coisc (Irish for "block") is a tool for generating advertising,
malware and tracking blocks on a level beyond the browser. The tool
harvests blacklists over HTTP and writes out files to implement
blocking in multiple formats.

Example use
--------
```coisc.py --output /etc/dnsmasq.d/adblocks --format dnsmasq```

Configuration
--------
Block sources can be added by including them in the ```blocks*.txt```
files. ```blocks-hosts_tyle.txt``` is specifically for sites that host
lists in hosts-file notation (ie with an IP address provided),

Currently supported formats
--------
* ```/etc/hosts``` style
* [dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) ```address``` entries

Caveats
--------
* There are some basic protections in place to avoid issues with the hosts files, but no assurances can be made about hosts files and how a malicious actor could coopt the block lists to harm users.
* Be courteous about how often you run the script or how it is automated.
* If writing out /etc/hosts style files, use additional templating or concatenation to ensure that you don't overwrite existing labels for things like localhost.
