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
import logging
import sys
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import xml.etree.ElementTree as ET

def getApiKey(fwHost, uname, pword):

    """
    Generates a Paloaltonetworks api key from username and password credentials
    :param hostname: Ip address of firewall
    :param username:
    :param password:
    :return: api_key API key for firewall
    """


    call = "https://%s/api/?type=keygen&user=%s&password=%s" % (fwHost, uname, pword)

    apiKey = ""
    while True:
        try:
            # response = urllib.request.urlopen(url, data=encoded_data, context=ctx).read()
            response = send_request(call)


        except DeployRequestException as updateerr:
            logger.info("No response from FW. Wait 20 secs before retry")
            time.sleep(10)
            continue

        else:
            api_key = ET.XML(response.content)[0][0].text
            logger.info("FW Management plane is Responding so checking if Dataplane is ready")
            logger.debug("Response to get_api is {}".format(response))
            return apiKey


def create_lfp_profile (fwHost, apiKey, lfProfile):
    
    log_settings_xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/log-settings/profiles"
    element = "<entry name='{log_fw}'/>".format(log_fw=lfProfile)
    values = {'type': 'config', 'action': 'set', 'xpath': log_settings_xpath, 'element': element, 'key': apiKey}
    palocall = 'https://{host}/api/'.format(host=fwHost)
    lfp_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(lfp_create_r.text)
    
    match_list_xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/log-settings/profiles/entry[@name='{log_fw}']/match-list".format(log_fw=lfProfile)
    element += "<entry name='Quarantine'/></match-list>"
    element += "<log-type>threat</log-type>"
    element += "<filter>(action+eq+sinkhole></filter>"
    element += "<send-to-panorama>yes</send-to-panorama>"
    values = {'type': 'config', 'action': 'set', 'xpath': match_list_xpath, 'element': element, 'key': apiKey}
    palocall = 'https://{host}/api/'.format(host=fwHost)
    match_list_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(match_list_r.text)
    
    actions_xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/log-settings/profiles/entry[@name='{log_fw}']/match-list/entry[@name='Quarantine']/actions".format(log_fw=lfProfile)
    element += "<entry name='AddQuarantineTag'/>"
    values = {'type': 'config', 'action': 'set', 'xpath': actions_xpath, 'element': element, 'key': apiKey}
    palocall = 'https://{host}/api/'.format(host=fwHost)
    actions_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(actions_r.text)
    
    tags_xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/log-settings/profiles/entry[@name='{log_fw}']/match-list/entry[@name='Quarantine']/actions/entry[@name='AddQuarantineTag']/type/tagging".format(log_fw=lfProfile)
    element += "<tags><member>quarantine</tags></member>"
    element += "<target>source-address</target>"
    element += "<action>add-tag></action>"
    values = {'type': 'config', 'action': 'set', 'xpath': tags_xpath, 'element': element, 'key': apiKey}
    palocall = 'https://{host}/api/'.format(host=fwHost)
    tag_create_r = requests.post(palocall, data=values, verify=False)
    tree = ET.fromstring(tag_create_r.text)


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
    parser = argparse.ArgumentParser(description='Get meta-cnc Params')
    parser.add_argument("-f", "--firewall", help="IP address of the firewall", required=True)
    parser.add_argument("-u", "--username", help="Firewall API Key", required=True)
    parser.add_argument("-p", "--password", help="Firewall API Key", required=True)
    parser.add_argument("-l", "--log_forwarding", help="Log Forwarding Profile name", type=str)
    parser.add_argument("-a", "--AS_Profile", help="Anti-Spyware Profile name", type=str)
    parser.add_argument("-d", "--DAG", help="Dynamic Address Group name", type=str)
    args = parser.parse_args()
    
    if len(sys.argv) < 2:
        parser.print_help()
        parser.exit()
        exit(1)
        
    fwHost = args.firewall
    uname = args.username
    pword = args.password
    lfProfile = args.log_forwarding
    asProfile = args.AS_Profile
    dag = args.DAG


if __name__ == '__main__':
    main()
