# open_relay_udp_amp
This script allows users to scan networks for detecting Open Relay on SNMP, UDP Amplification on DNS and NTP.

### Educational purposes only! Use in you own pentest lab (will give docker files links for such in future, but basic DNS image, NTP server with MONLIST vulnerability and open relay server are good enough)

This script utilises weaknesses of DNS and NTP, that allows for amplifying. It works because unlike TCP, UDP doesn't perform any connection check, only if package's control sum is correct. Thanks to tha, we can change a source address of our request, making a server send packages to our target.

- For NTP, I am using **MONLIST** vulnerability (https://security-tracker.debian.org/tracker/CVE-2013-5211). It allows to get addresses used by server to check current time for them
- For DNS, there isn't any specific vulnerability. In this case i used facebook.com with query type TXT, that showed the best amplification factor