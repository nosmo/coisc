#!/usr/bin/env python

import argparse
import requests

# urls that have hostsfile-style notation
HOST_FILE_URLS = "blocks-hosts_style.txt"

# urls that are just a list of domains
NONHOST_FILE_URLS = "blocks.txt"

# IPs in a hosts file to consider safe
SAFE_IPS = ["0.0.0.0", "127.0.0.1", "255.255.255.255", "::1"]

# filter some words out of domains - we can write these ourselves
FILTER_DOMAIN = ["localhost", "localhost.localdomain"]

REDIRECT_IP = "127.0.0.1"


def filter_url_list(url_name, url_list, ip_provided):
    """Filter a list of URLs to remove comments.

     url_name: a label to identify the list
     url_list: a list of URL strings
     ip_provided: is the IP provided each line?
    """

    filtered_list = []

    for url in url_list:
        url = url.strip()
        if url.startswith("#") or not url:
            continue
        if "#" in url:
            # fix up lines that "have comments # here"
            url = url.partition("#")[0]
        if ip_provided:
            ip, hostname = [ i.strip() for i in url.split() ]

            if ip not in SAFE_IPS:
                print "WARNING!! Unsafe IP found in file %s: %s" % (url_name, url)
                raise SystemExit
        else:
            hostname = url
        filtered_list.append(hostname)

    return filtered_list

def process_url_dict(url_dict, ip_provided):
    """Download and process a label:url dict of URLs containing blocks.

     url_dict: a label:url dict of URLs
     ip_provided: is the IP provided each line? (/etc/hosts style)
    """
    for label, url in url_dict.iteritems():
        print "Processing %s" % label
        downloaded_req = requests.get(url)
        if downloaded_req.ok:
            downloaded_list = downloaded_req.text.strip().split("\n")
            filtered_list = filter_url_list(label, downloaded_list, ip_provided)
    return filtered_list

def format_dnsmasq(redirect_ip, domain):
    return "address=/%s/%s\n" % (domain, redirect_ip)

def format_hosts(redirect_ip, domain):
    return "%s\t%s\n" % (redirect_ip, domain)

OUTPUT_DICT = {
    "dnsmasq": format_dnsmasq,
    "hosts": format_hosts
}

def urlfile_to_dict(file_path):
    url_dict = {}
    with open(file_path) as url_f:
        for url_str in url_f.read().split("\n"):
            url_str = url_str.strip()
            if url_str:
                url_label, url = url_str.split(" ")
                url_dict[url_label] = url
    return url_dict

def main(output_format, output_path):
    full_domain_list = []
    full_domain_list += process_url_dict(urlfile_to_dict(HOST_FILE_URLS), True)
    full_domain_list += process_url_dict(urlfile_to_dict(NONHOST_FILE_URLS), False)
    print "Got %d entries" % len(full_domain_list)
    print "Of which %d were duplicates" % (len(full_domain_list) - len(set(full_domain_list)))

    with open(output_path, "w") as output_f:
        for domain in full_domain_list:
            output_f.write(OUTPUT_DICT[output_format](REDIRECT_IP, domain))
    print "Complete - wrote using %s format to %s" % (output_format, output_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Generate system-level advertising/malware blocklists')
    parser.add_argument("--output", "-o", dest="output_path", action="store", default="",
                        help="Where to write output", required=True)
    parser.add_argument("--format", "-f", dest="output_format", action="store", default="hosts",
                        help="Format to write output using", choices=OUTPUT_DICT.keys())
    args = parser.parse_args()

    main(args.output_format, args.output_path)
