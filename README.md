# BBDNS
Basic configurable DNS service redirector for network traffic analysis
<img width="978" height="492" alt="image" src="https://github.com/user-attachments/assets/3785557d-351b-413f-bdbb-6863c0277fbe" />

# Info
This is designed to be a basic and simple to setup DNS server for redirecting network trafic.

### How it works
If you set both your primary and secondary DNS settings on your device to the ip of this service, you can force your device to use our DNS<br>
Your device will ask the DNS hey, whats the IP for google.com? And we can then lie and say oh its 192.168.0.1. Then your device is like okie cool I trust you, I will now send all traffic meant for google to 192.168.0.1.<br>
IP addresses are what the devices actually use to communicate, the urls are just for people to use in browsers.

### Why
Well say your device is reaching out to a "secret" api.backdoor.com and you want to intercept that traffic to either analyze it, or just dump the traffic into the void so it doesn't get sent to the owner of that url, now you can.<br>
from the devices point of view its still talking to the real api.backdoor.com. Its just the only phonebook the device can use to get the phone number for api.backdoor.com is our modified one. But the device dosent know that. It thinks everything is normal.

# Recommendations
This tool pears well with a proxy like mitm-proxy. You redirect the traffic to the proxy, then you can inspect and alter the traffic however you want, sending the traffic back as the domain given to us by the dns so the device doesn't know we messed with it.
