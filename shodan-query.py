#!/usr/bin/python
import sys
try:
    from shodan import Shodan, APIError
    import argparse
    import json
except:
    print "[!] Please install required modules (shodan, argparse)"
    sys.exit(1)

# API Key goes here
API_KEY = ""

# Basic check for API key
def check_api():
    if len(API_KEY) == 0:
        print "[!] Please provide a Shodan API key"
        sys.exit(1)
    else:
        # Try validity of API KEY
        return 1

# Parse provided (user) args 
def parse_args():
    parser = argparse.ArgumentParser(description="Shodan Query")
    parser.add_argument("-i", "--ip", help="provide a single IP address")
    args = parser.parse_args()
    return args

# Read content of a file (given filename) into a list
def read_file_into_list(filename):
    with open(filename, "r") as fin:
        lines = fin.read().splitlines()
    print "[!] Loaded %s IPs from \"%s\"" % (len(lines), filename)
    return lines

def parse_response(json_response):
    j = json.loads(json.dumps(json_response))
    print j["ip_str"]

# Query shodan for info about IP address
def query(ip):
    try:
        host = api.host(ip)
        parse_response(host)
    except APIError, e:
        print e
        if e.value == "Invalid IP":
            print "[!] Invalid IP format"
        else:
            print "[!] Unkown error (\"%s\")" % (e.value)

def do(args):
    try:
        query(args.ip)
    except APIError, e:
        print "[!] APIError (msg: \"%s\")" % (e)
        sys.exit(1)

#####################
# Main starts here
#####################
if __name__ == "__main__":
    check_api()

    args = parse_args()
    api = Shodan(API_KEY)

    # Do main work
    do(args)
