# Packet Purgatory Skillet
This is the initial release of the Packet Purgatory Skillet. 

#### Purpose:
This skillet can be used to demo the auto-tagging feature in PAN-OS 8.x NGFW and onward by detecting and quarantine a host that is actively communicating to C2. This would closely mimick a customer environment. It will auto-tag the host into a dynamic address group and isolate them in a security rule that is set to deny. 


#### Requirements and Dependencies:
This demo is based off of resources available in the SE LiAB v2.x. You will need these host VM's up and running in order to execute the demo:
* msft-esm-dc (Internal DNS server and UID Server)
* msft-victim-7 (Query all the bad thingz)
* pan-panos-vm50

It is assumed that you have all the appropriate content updates already installed for the PA-VM as well as active subscriptions for Threat Prevention and URL Filtering (DNS Subscription is optional).


#### Walkthrough:
Import this into Panhandler and you just SEND IT! Panhandler will push these configuration items to the specified environment(s) within Panhandler. Panorama is not required as the skillet config is pushed directly to the PA-VM. The Logs, however, are configured to be forwarded to Panorama to provide additional log data for any future demos of Panorama.

## Support Policy
The code and templates in the repo are released under an as-is, best effort,
support policy. These scripts should be seen as community supported and
Palo Alto Networks will contribute our expertise as and when possible.
We do not provide technical support or help in using or troubleshooting the
components of the project through our normal support options such as
Palo Alto Networks support teams, or ASC (Authorized Support Centers)
partners and backline support options. The underlying product used
(the VM-Series firewall) by the scripts or templates are still supported,
but the support is only for the product functionality and not for help in
deploying or using the template or script itself. Unless explicitly tagged,
all projects or work posted in our GitHub repository
(at https://github.com/PaloAltoNetworks) or sites other than our official
Downloads page on https://support.paloaltonetworks.com are provided under
the best effort policy.
