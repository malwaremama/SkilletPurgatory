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
lfProfile = args.log_forwarding
asProfile = args.AS_Profile
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

#Create objects

    #create log forwarding profile
    xpath = "/config/shared/log-settings/profiles/entry[@name='%s']/match-list/entry[@name='Quarantine']" % (lfProfile)
    element = "<log-type>traffic</log-type><filter>All Logs</filter><send-to-panorama>yes</send-to-panorama><actions><entry name='AddQuarantineTag'><type><tagging><action>add-tag</action><tags><member>quarantine</member></tags><target>source-address</target><registration><localhost/></registration></tagging></type></entry></actions>"
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    lfp_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(lfp_create_r.text)
    print("Creating log forwarding profile: " + tree.get('status'))

    #create FQDN object
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='sinkhole.paloaltonetworks.com']"
    element = "<fqdn>sinkhole.paloaltonetworks.com</fqdn>"
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    fqdn_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(fqdn_create_r.text)

    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']/dynamic" % (dag)
    element = "<filter>quarantine</filter>"
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    dag_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(dag_create_r.text)
    print("Creating Dynamic Address Group: " + tree.get('status'))


#Change Security Profile in Existing Rule

    #Delete Existing Spyware Profile From Rule
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='%s']/profile-setting/profiles/spyware" % (allowRule)
    values = {'type': 'config', 'action': 'delete', 'xpath': xpath, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    spyware_remove = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(spyware_remove.text)

    #Update with Spyware Profile taken from Input
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='%s']/profile-setting/profiles/spyware" % (allowRule)
    element = "<member>%s</member>" % (asProfile)
    values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
    palocall = 'https://%s/api/' % (fwHost)
    spyware_switch = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(spyware_switch.text)


#Create Security Rules

    #create sinkhole traffic security rule
xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='SinkholeTraffic']"
element = "<from><member>trust</member></from><to><member>untrust</member></to><destination><member>sinkhole.paloaltonetworks.com</member></destination><application><member>any</member></application><service><member>any</member></service><category><member>any</member></category><source><member>any</member></source><action>allow</action><log-setting>%s</log-setting>" % (lfProfile)
values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
palocall = 'https://%s/api/' % (fwHost)
sinkhole_rule_create = requests.post(palocall, data=values, verify=False)
tree = ET.fromstring(sinkhole_rule_create.text)

    #move sinkhole rule to the top
xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='SinkholeTraffic']"
values = {'type': 'config', 'action': 'move', 'xpath': xpath, 'where': 'top', 'key': apiKey}
palocall = 'https://%s/api/' % (fwHost)
move = requests.get(palocall, params=values, verify=False)
tree = ET.fromstring(move.text)

    #isolation security rule
xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='IsolateQuarantinedHosts']"
element = "<from><member>trust</member></from><to><member>untrust</member></to><destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><category><member>any</member></category><source><member>%s</member></source><action>deny</action><log-setting>Default-Logging-Profile</log-setting>" % (dag)
values = {'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': apiKey}
palocall = 'https://%s/api/' % (fwHost)
rule_create_r = requests.post(palocall, data=values, verify=False)
tree = ET.fromstring(rule_create_r.text)

    #move isolation rule to the top
xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='IsolateQuarantinedHosts']"
values = {'type': 'config', 'action': 'move', 'xpath': xpath, 'where': 'top', 'key': apiKey}
palocall = 'https://%s/api/' % (fwHost)
move = requests.get(palocall, params=values, verify=False)
tree = ET.fromstring(move.text)
print("Populating Security Rules and Moving to the Top of Policy: " + tree.get('status'))

#Commit Changes to the NGFW
cmd = '<commit><force></force></commit>'
values = {'type:': 'commit', 'cmd': cmd, 'key': apiKey}
commit_call = 'https://%s/api/' % (fwHost)
commit_r = requests.post(commit_call, data=values, verify=False)
tree = ET.fromstring(commit_r.text)
jobid = tree[0][1].text
print("Committing Policy (JobID): " + str(jobid))

print(r'''\ Now go forth and create havoc on your Win7 Victim!
                       ______
                    .-"      "-.
                   /            \
       _          |              |          _
      ( \         |,  .-.  .-.  ,|         / )
       > "=._     | )(__/  \__)( |     _.=" <
      (_/"=._"=._ |/     /\     \| _.="_.="\_)
             "=._ (_     ^^     _)"_.="
                 "=\__|IIIIII|__/="
                _.="| \IIIIII/ |"=._
      _     _.="_.="\          /"=._"=._     _
     ( \_.="_.="     `--------`     "=._"=._/ )
      > _.="                            "=._ <
     (_/   ssw                              \_)
                                         ''')
