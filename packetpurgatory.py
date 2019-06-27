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
parser.add_argument("-l", "--log_forwarding", help="Log Forwarding Profile name", type=str)
parser.add_argument("-a", "--AS_Profile", help="Anti-Spyware Profile name", type=str)
parser.add_argument("-d", "--DAG", help="Dynamic Address Group name", type=str)
args = parser.parse_args()
      
fwHost = args.firewall
uName = args.username
pWord = args.password
lfProfile = args.log_forwarding
asProfile = args.AS_Profile
dag = args.DAG

# Generate API key
call = "https://%s/api/?type=keygen&user=%s&password=%s" % (fwHost,uName,pWord)
try:
    r = requests.get(call, verify=False)
    tree = ET.fromstring(r.text)
    if tree.get('status') == "success":
        apiKey = tree[0][0].text

except requests.exceptions.ConnectionError as e:
    print ("There was a problem connecting to the firewall.  Please check the connection information and try again.")

try:
    apiKey
except NameError as e:
    print ("There was a problem connecting to the firewall.  Please check the connection information and try again.")

else:

    '''
#Create URL filtering profile called 'alert-all'
    type = "config"
    action = "set"
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/url-filtering"
    element = "<entry name='alert-all'/>"
    call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwHost, type, action, xpath, element, apiKey)
    r = requests.post(call, verify=False)
    tree = ET.fromstring(r.text)
    print ("Create alert-all URL filtering profile: " + tree.get('status') + " - " + str(tree[0].text))
'''

#Create Log-Forwarding Profile
    xpath = "/config/shared/log-settings/profiles"
    element = "<entry name='%s'/>" % (lfProfile)
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    lfp_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(lfp_create_r.text)

    xpath = "/config/shared/log-settings/profiles/entry[@name='%s']/match-list" % (lfProfile)
    element = "<entry name='Quarantine'/>"
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    lfp_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(lfp_create_r.text)

    xpath = "/config/shared/log-settings/profiles/entry[@name='%s']/match-list/entry[@name='Quarantine']" % (lfProfile)
    element = "<log-type>threat</log-type><filter>action eq sinkhole</filter><actions><entry name='AddQuarantineTag'><type><tagging><tags><member>quarantine</member></tags><target>source-address</target></tagging></type></entry></actions>"
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    lfp_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(lfp_create_r.text)
    print ("Creating log forwarding profile: " + tree.get('status') + " - " + str(tree[0].text))


# Commit the Changes and Monitor for Completion
    cmd = '<commit><force></force></commit>'
    values = {'type': 'commit', 'cmd': cmd, 'key': apiKey}
    palocall = 'https://{host}/api/'.format(host=fwHost)
    r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(r.text)
    jobID = tree[0][1].text
    print ("Commit job - " + str(jobID))

    committed = 0
    while (committed == 0):
        cmd = '<show><jobs><id>{jobid}</id></jobs></show>'.format(jobid=jobID)
        values = {'type': 'op', 'cmd': cmd, 'key': apiKey}
        palocall = 'https://{host}/api/'.format(host=fwHost)
        r = requests.post(palocall, data=values, verify=False)
        tree = ET.fromstring(r.text)
        if (tree[0][0][5].text == 'FIN'):
            print ("Commit status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete")
            committed = 1

        else:
            status = "Commit status - " + " " + str(tree[0][0][12].text) + "% complete"
            print ('{0}\r'.format(status)),


