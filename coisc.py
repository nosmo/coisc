#!/usr/bin/env python3

"""
Generate a list of DNS blocks for a given set of hosts.

"""

import argparse
import os.path
import sys

import requests

# TODO don't assume these defaults, allow for specification
# urls that have hostsfile-style notation
HOST_FILE_URLS = "blocks-hosts_style.txt"

# urls that are just a list of domains
NONHOST_FILE_URLS = "blocks.txt"

# file containing a list of domains to block all of
DOMAIN_BLOCK_FILE = "blockdomains.txt"

# IPs in a hosts file to consider safe
SAFE_IPS = ["0.0.0.0", "127.0.0.1", "255.255.255.255", "::1",
            "fe00::0", "ff00::0", "ff02::1", "ff02::2", "ff02::3"]

# filter some words out of domains - we can write these ourselves
FILTER_DOMAIN = ["localhost", "localhost.localdomain"]

REDIRECT_IP = "127.0.0.1"

USER_AGENT = "Coisc (https://github.com/nosmo/coisc)"


class UnsupportedFormat(Exception):
    pass


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
            url_split = url.split()
            if len(url_split) > 2:
                continue

            ip, hostname = [ i.strip() for i in url.split() ]

            if ip not in SAFE_IPS:
                print("WARNING!! Unsafe IP found in file {}: {}".format(
                    url_name, url))
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
    for label, url in url_dict.items():
        print("Processing %s" % label)
        downloaded_req = requests.get(url, headers={"User-Agent": USER_AGENT})
        if downloaded_req.ok:
            downloaded_list = downloaded_req.text.strip().split("\n")
            filtered_list = filter_url_list(label, downloaded_list,
                                            ip_provided)
        else:
            sys.stderr.write("Failed to download URL {}: {}\n".format(url, downloaded_req.text))
    return filtered_list


# TODO make these their own class
def format_dnsmasq(redirect_ip, domain):
    return "address=/{}/{}\n".format(domain, redirect_ip)


def extract_dnsmasq(record_string):
    return record_string.strip().split("/")[1]


def format_hosts(redirect_ip, domain):
    return "{}\t{}\n".format(redirect_ip, domain)


def extract_hosts(record_string):
    return record_string.split()[1]


def format_bind(redirect_ip, domain):
    return "{}.\tIN\tA\t{}\n".format(domain, redirect_ip)


def extract_bind(record_string):
    return record_string.split()[0]


def domain_block_dnsmasq(redirect_ip, domain):
    """Domain-wide block for a domain using dnsmasq
    """

    return "domain=/{}/{}\n".format(domain, redirect_ip)


def domain_block_hosts(redirect_ip, domain):
    """Domain-wide block for a domain using hostsfile

    Not supported for hostsfile due to lack of support
    """

    raise UnsupportedFormat("No top-level block support for hosts file")


def domain_block_bind(redirect_ip, domain):
    """Domain-wide block for a domain using bind

    Not supported for bind yet.
    """
    raise UnsupportedFormat("No top-level block support for bind")


EXTRACT_DICT = {
    "dnsmasq": extract_dnsmasq,
    "hosts": extract_hosts,
    "bind": extract_bind
}

OUTPUT_DICT = {
    "dnsmasq": format_dnsmasq,
    "hosts": format_hosts,
    "bind": format_bind
}

DOMAIN_OUTPUT_DICT = {
    "dnsmasq": domain_block_dnsmasq,
    "hosts": domain_block_hosts,
    "bind": domain_block_bind
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


def main(output_format, output_path, add_mode, domain_block_files):

    full_domain_list = []
    domain_blocks = []
    for domain_file in domain_block_files:
        with open(domain_file) as domain_f:
            for l in domain_f.read().strip().split("\n"):
                domain_blocks.append(l)

    full_domain_list += process_url_dict(urlfile_to_dict(HOST_FILE_URLS), True)
    full_domain_list += process_url_dict(urlfile_to_dict(NONHOST_FILE_URLS), False)
    print("Got %d entries" % len(full_domain_list))
    print("Of which %d were duplicates" % (len(full_domain_list) - len(set(full_domain_list))))

    existing_list = []
    if os.path.exists(output_path):
        with open(output_path, "r") as output_f:
            # TODO this function isn't called - why?
            extract_function = EXTRACT_DICT[output_format]
            existing_list = [extract_function(i.strip())
                             for i in output_f.read().split("\n")
                             if i.strip()]
    if add_mode:
        full_domain_list = set(full_domain_list + existing_list)

    if domain_blocks:
        print("Got {} domain blocks".format(len(domain_blocks)))

    with open(output_path, "w") as output_f:
        for domain in full_domain_list:
            output_f.write(OUTPUT_DICT[output_format](REDIRECT_IP, domain))

        for domain_block in domain_blocks:
            try:
                output_f.write(DOMAIN_OUTPUT_DICT[output_format](REDIRECT_IP, domain_block))
            except UnsupportedFormat as exc:
                sys.stderr.write(
                    "Not writing domain block for unsupported format {}: {}\n".format(
                        output_format, exc))
                break

    print("Complete - wrote using %s format to %s" % (output_format, output_path))
    if not add_mode and existing_list and existing_list != full_domain_list:
        print("Added %d entries" % len(set(full_domain_list).difference(existing_list)))
        print("Removed %d entries" % len(set(existing_list).difference(full_domain_list)))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Generate system-level advertising/malware blocklists')
    parser.add_argument("--domainlist", "-D", dest="domain_blocks", action="store", default="",
                        help="File to read domain blocks from", required=True, nargs='*')
    parser.add_argument("--output", "-o", dest="output_path", action="store", default="",
                        help="Where to write output", required=True)
    parser.add_argument("--format", "-f", dest="output_format", action="store", default="hosts",
                        help="Format to write output using", choices=list(OUTPUT_DICT.keys()))
    parser.add_argument("--add", "-a", dest="add", action="store_true", default=False,
                        help="Don't remove any lines, only add new ones")
    args = parser.parse_args()

    main(args.output_format, args.output_path, args.add, args.domain_blocks)
