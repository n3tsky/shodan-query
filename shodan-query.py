#!/usr/bin/python
import sys
import signal
try:
    from shodan import Shodan, APIError
    import argparse
    import json
except:
    print "[!] Please install required modules (shodan, argparse)"
    sys.exit(1)

# API Key goes here
API_KEY = ""

# Handle SIGINT
def exit_signal(signal, frame):
    print "User abort.\nExiting..."
    sys.exit(1)

signal.signal(signal.SIGINT, exit_signal)

#
# Basic check for API key
def check_api():
    if len(API_KEY) == 0:
        print "[!] Please provide a Shodan API key"
        sys.exit(1)
    # Try validity of API KEY?

# Parse provided (user) args 
def parse_args():
    parser = argparse.ArgumentParser(description="Shodan Query")
    parser.add_argument("-i", "--ip", help="provide a single IP address")
    parser.add_argument("-f", "--file", help="provide a file with IP address(es)")
    parser.add_argument("-t", "--time", help="time to wait between requests (default: 0)")
    args = parser.parse_args()
    return parser, args

# Read content of a file (given filename) into a list
def read_file_into_list(filename):
    with open(filename, "r") as fin:
        lines = fin.read().splitlines()
    print "[!] Loaded %s IPs from \"%s\"" % (len(lines), filename)
    return lines


def display(msg, value):
    try:
        print "%s: %s" % (msg, value)
    except KeyError:
        pass

def deliver_generic_info(json):
    print "\n---- Generic info ----"
    display("Country code", json["country_code"])
    display("Country name", json["country_name"])
    display("City", json["city"])
    display("Hostname(s)", (', '.join(json["hostnames"])))
    display("Organisation", json["org"])
    display("Latest update", json["last_update"])
    display("Shodan", "https://www.shodan.io/host/%s" % (json["ip_str"]))

def deliver_services(json):
    print "\n---- Ports ----"
    if "ports" in json.keys():
        display("Ports", (", ".join(repr(str(n)) for n in json["ports"])))

def deliver_http(http):
    pass

def deliver_data(json, verbose=False):
    print "\n---- Services ----"
    if "data" in json.keys():
        for d in json["data"]:
            if "port" in d.keys():
                display("Port", d["port"])

            for values in ["product", "version", "os", "hostnames", "domains"]:
                if values in d.keys():
                    if (type(d[values]) == list) and (len(d[values])>0):
                        display(" - %s" % (values), d[values])
                    if (type(d[values]) == unicode) and (d[values] != None):
                        display(" - %s" % (values), d[values])
            
            if "http" in d.keys():
                deliver_http(d["http"])

def deliver_vulns(json, verbose=False):
    print "\n---- Vulns ----"
    if "vulns" in json.keys():
        display("Vulns", (", ".join(json["vulns"])))

    if verbose:
        if "data" in json.keys():
            deliver_data(json["data"])
            return
            print data["port"] 

            if "vulns" in data.keys():
                for k, v in data["vulns"].iteritems():
                    print " . %s: " % (k)
                    if "summary" in v:
                        print "  Summary: %s" % (v["summary"])
                    if "references" in v:
                        print "  References:\n  - %s" % ("\n  - ".join(v["references"]))


def parse_response(json_response):
    j = json.loads(json.dumps(json_response))
    print j
    print "###########################"
    print "Host: %s" % (j["ip_str"])
    deliver_generic_info(j)
    deliver_services(j)
    deliver_data(j, verbose=True)
    print "###########################"

# Query shodan for info about IP address
def query(ip):
    try:
        host = api.host(ip)
        parse_response(host)
    except APIError, e:
        if e.value == "Invalid IP":
            print "[!] Invalid IP format"
        else:
            print "[!] Unkown error (\"%s\")" % (e.value)

def do(args):
    try:
        if (args.ip):
            query(args.ip)
        elif (args.file):
            pass
        else:
            args.display_help()
            print "[*] Nothing to do"
    except APIError, e:
        print "[!] APIError (msg: \"%s\")" % (e)
        sys.exit(1)

#####################
# Main starts here
#####################
if __name__ == "__main__":
    check_api()

    parser, args = parse_args()
    api = Shodan(API_KEY)

    # Do main work
    try:
        if (args.ip):
            query(args.ip)
        elif (args.file):
            pass
        else:
            parser.print_help()
    except APIError, e:
        print "[!] APIError (msg: \"%s\")" % (e)
        sys.exit(1)
