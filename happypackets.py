#!/usr/bin/env python3
DOCUMENTATION = '''
Copyright (c) 2018, Palo Alto Networks

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

Author: Sandy Wenzel <swenzel@paloaltonetworks.com>
'''

import argparse
import sys
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import xml.etree.ElementTree as ET

#Arguments passed from user input from meta-cnc file
parser = argparse.ArgumentParser(description='Get meta-cnc Params')
parser.add_argument("-f", "--firewall", help="IP address of the firewall", required=True)
parser.add_argument("-u", "--username", help="Firewall API Key", required=True)
parser.add_argument("-p", "--password", help="Firewall API Key", required=True)
parser.add_argument("-l", "--log_forwarding", help="Log Forwarding Profile name", required=True)
parser.add_argument("-a", "--AS_Profile", help="Anti-Spyware Profile name", required=True)
parser.add_argument("-r", "--allowall", help="Anti-Spyware Profile name", required=True)
parser.add_argument("-d", "--DAG", help="Dynamic Address Group name", required=True)
args = parser.parse_args()

fwHost = args.firewall
uName = args.username
pWord = args.password
urlLogProfile = args.url_forwarding
urlProfile = args.url_profile
allowRule = args.allowall
dag = args.DAG

# Generate API key
call = "https://%s/api/?type=keygen&user=%s&password=%s" % (fwHost,uName,pWord)
try:
    r = requests.get(call, verify=False)
    tree = ET.fromstring(r.text)
    if tree.get('status') == "success":
        apiKey = tree[0][0].text

except requests.exceptions.ConnectionError as e:
    print("There was a problem connecting to the firewall.  Please check the connection information and try again.")

try:
    apiKey
except NameError as e:
    print("There was a problem connecting to the firewall.  Please check the connection information and try again.")

else:

    #Create URL Log-Forwarding Profile
    xpath = "/config/shared/log-settings/profiles"
    element = "<entry name='%s'/>" % (urlLogProfile)
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    lfp_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(lfp_create_r.text)

    xpath = "/config/shared/log-settings/profiles/entry[@name='%s']/match-list" % (urlLogProfile)
    element = "<entry name='UNQuarantine'/>"
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    lfp_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(lfp_create_r.text)

    xpath = "/config/shared/log-settings/profiles/entry[@name='%s']/match-list/entry[@name='UNQuarantine']" % (urlLogProfile)
    element = "<log-type>url</log-type><filter>(action eq override)</filter><send-to-panorama>yes</send-to-panorama><actions><entry name='RemoveQuarantineTag'><type><tagging><action>remove-tag</action><tags><member>quarantine</member></tags><target>source-address</target><registration><localhost/></registration></tagging></type></entry></actions>"
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    lfp_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(lfp_create_r.text)
    print("Creating URL Log Forwarding Profile: " + tree.get('status'))

    #Create URL Filtering profile for Override
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/url-filtering"
    element = "<entry name='%s'/>" % (urlProfile)
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    lfp_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(lfp_create_r.text)

    #get URL categories
    categories = []

    xpath = "/config/predefined/pan-url-categories"
    values = {'type': 'config', 'action': 'get', 'xpath': xpath, 'key': apiKey}
    collect_call = 'https://%s/api/' % (fwHost)
    r = requests.get(collect_call, params=values, verify=False)
    tree = ET.fromstring(r.text)
    for element in tree[0]:
        entries = element.findall('entry')
        for entry in entries:
            category = entry.get('name')
            categories.append (str(category))

    #set categories to override
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/url-filtering/entry[@name='%s']/override" % (urlProfile)
    element = ""
    for category in categories:
        element += "<member>%s</member>" % (category)
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    override_call = 'https://%s/api/' % (fwHost)
    r = requests.post(override_call, data=values, verify=False)
    tree = ET.fromstring(r.text)
    print("Override on all categories: " + tree.get('status'))
    print(r.text)