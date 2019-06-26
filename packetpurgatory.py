#!/usr/bin/env python
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
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import xml.etree.ElementTree as ET


def create_lfp_profile (fwHost, apiKey, lfProfile):
    log_settings_xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/log-settings/profiles"
    element = "<entry name = '{lf_profile}'/>".format(lf_profile=lfProfile)
    element += "<match-list><entry name = 'Quarantine'/></match-list>"
    element += "<actions><entry name = 'AddQuarantineTag'/></actions>"
    element += "<tags><member>quarantine</member></tags>"
    element += "<target>source-address</target>"
    element += "<action>add-tag></action>"
    element += "<log-type>threat</log-type>"
    element += "<filter>(action eq sinkhole></filter>"
    element += "<send-to-panorama>yes</send-to-panorama>"
    values = {'type': 'config','action': 'set', 'xpath': log_settings_xpath, 'element': element, 'key': apiKey}
    palocall = 'https://{host}/api/'.format(host=fwHost)
    lfp_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(lfp_create_r.text)
    print("Creating Log Forwarding Profile")


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

def main():

    # python skillets currently use CLI arguments to get input from the operator / user. Each argparse argument long
    # name must match a variable in the .meta-cnc file directly
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--firewall", help="IP address of the firewall", required=True)
    parser.add_argument("-u", "--apikey", help="Firewall API Key", required=True)
    parser.add_argument("-u", "--lfpQuarantine", help="Log Forwarding Profile name", type=str)
    parser.add_argument("-u", "--asProfile", help="Anti-Spyware Profile name", type=str)
    parser.add_argument("-u", "--dag", help="Dynamic Address Group name", type=str)
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        parser.exit()
        exit(1)

    fwHost = args.firewall
    apiKey = args.apikey
    lfProfile = args.log_forwarding
    asProfile = args.AS_Profile
    dag = args.DAG


if __name__ == '__main__':
    main()
