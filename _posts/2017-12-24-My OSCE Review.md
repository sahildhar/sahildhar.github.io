---
layout: post
title: My OSCE Experience
---

Hello Everyone, as requested by one of my friends, I would like to share my experience about *Offensive Security's* one of the most dreaded exam [Offensive Security Certified Expert](https://www.offensive-security.com/information-security-certifications/osce-offensive-security-certified-expert/). I have divided this post in following sections:

* How I have prepared
* What to expect from course
* Myths regarding this course
* Exam
* Important links

### How I have prepared

Before I start with this section, I would like you to know that this course is definitely not an entry level. It also **doesn't** means that you cannot pass this exam if you have just cleared your CEH/OSCP. We can say that, it requires more **persistence** and **thorough understanding** of lots of new concepts that course brings with it.

In my case, I would like to point this out that I haven't done any Security certification before, neither from Offensive Security nor do I possess CEH certification. So the question remains, *How did I directly jump to it, instead of doing some entry level certs?*. Well I would say its matter of choice and experience for any other exam out there for which you need following simple things:

* You prepare
* You push your limits
* You practise a lot
* You pass the Exam

Coming to more technical part, I have referred following things **before** starting with the course registration:

1. [SLAE] 32 bit (Security tube's Linux Assembly Expert)
> One of best and most simpler way of understanding 32 bit ASM. Don't panic when the OSCE course contents introduces you to windows shellcoding, the concepts remains exactly same.

2. Backdooring PE files [101][1] [102][2] [103][3].
> One of the best and detailed read on backdooring PE files. Atleast the one I have read :P

3. [Corelan]'s articles on exploit development.
> Can't praise enough about it.

4.  [ROP] Chaining from Fuzzy Security
> Not required though, but if you want to learn, Ruben has explained it in very simpler way.

5. Web Application Hacker's Handbook [WAHH].

6. Exploit-exerices.com's [Protostar] and [Nebula]
> You would love them, if you are starting binary exploitation. If you get stuck or want an introduction to any problem in there I have written a series of blog posts on solving Protostar problems  [here](http://resources.infosecinstitute.com/author/sahildhar/).

7. Some of the exploits I have written during my prep time can be found [here](https://github.com/sahildhar/OSCE-Exploits).

### What to expect from course

The course is heavily focused on Binary exploitation, which means 80%  of the time you will either be writing/tweaking your fuzzing scripts or debugging exploits with in the debugger. Familiarity with any debugger and scripting language will definitely help you in a long run. This course won't make you a *Software Exploitation Ninja* in a day, however if you want to be one, it will definitely help you to get a bit closer to that goal.


*Some TIPS*

* Do not depend entirely on SPIKE learn other fuzzing framework like PEACH and thank me later.

* Before proceeding with exploitation of any binary, thoroughly understand the working of binary and what is it meant for and ask your self some questions. for example:
  * Is it a server? \[Remote\]
  * Is it a file reader? \[Local\]
  * Does is spawn multiple threads on connecting? \[Remote\]
> Based on the information gathered in this step your debugging options will vary.


### Myths Regarding this course

Before starting with this course, I always get this vibe from other people who have passed this exam that it requires you to be super elite to pass this exam. **ANSWER IS STRAIGHT NO** I repeat **NO**. I am not saying it is easy but it definitely not that difficult as it **POTRAYED** out there. So, don't get discourage because of these rumors.

Anything will be difficult till the time you haven't mastered it very well. So, keep this in mind the course is not super hard its just you don't know about some concepts or you haven't done enough practise like for any other exam.


### The Exam

Now the fun part begins, this is a **72 hours** exam out of that **47.45 hours**  are given for exam and remaining time is for writing reports. I would not bore you with the details of how I approach the exam in terms of exploitation timings and eureka moments \(believe me it was similar for me too as you might have read on other people reviews\) instead I would like to share some details based on my experience on what and what not to do before and after enrolling for it:

#### Are you ready ?
These are very generic questions you would like to ask yourself before thinking of booking an exam slot. You can assess them as follows:

* Do I know how to apply the web application security exploits discussed in this course?
* Can I successfully backdoor any PE file with at least 80-90% evasion success rate.
* Can I write an eggHunter, Can I modify the eggHunter code written by someone else?
* Do I understand all concepts of SEH and Stack overflows exploits.
* Am I able find and exploit the vulnerabilities discussed in binary exploitation section of the course?
* Am I able to write exploit for the vulnerabilities discussed in course from scratch?
* Am I able to use fuzzing tools and using the same am I able to find, reproduce and write exploits?

#### Don't make assumptions
Following are the assumptions I have made in my case that doesn't work very well:

1. Oh!! Any easy question I will do it later
> Remember every question is meant to take a minimum of 6 hours so manage your time accordingly.

2. If the question said, do it manually then do it manually
> Oh yes automation is awesome only if it works perfectly. In my case the script I have written during my lab time fucked up in exam and I end up wasting in lot of hours and finally did it manually.

3. Backtrack sucks, At least it did for me
> The course recommends you to use a BT machine thorough out the lab and exam. Well I did use it for lab time but when I was starting my exam it was not able to even get an IP from DHCP. I had this feeling that it will get stuck and I had backup Kali x86 machine ready. Still the whole process of shifting to new machine in the middle of exam wasted one hour.

4. Have rest and food in between
> As this was my first Offsec exam, I was not much familiar with the importance of rest :p. Yes, the continuous working of 20-30 hours will fuck up your mind badly. You will starting to get tunnel vision for any problem thrown at you and that's where my friend you have fucked up.


### Important links

* [OSCE Prep - Baseline Security](https://baselinesecurity.wordpress.com/tag/osce/)
* [OSCE Study Plan - Chapter Wise](http://www.abatchy.com/2017/03/osce-study-plan)
* [Windows Reverse TCP Shellcode Explaination](http://sh3llc0d3r.com/category/windows-reverse-shell/)
* [Netsec Slack Group](https://netsecfocus.slack.com)
* [Online x86 and x64 Disassembler](https://defuse.ca/online-x86-assembler.htm#disassembly2)

[SLAE]: http://www.pentesteracademy.com/course?id=3
[1]: https://medium.com/@vysec.private/backdoor-101-f318110e1fcb
[2]: https://medium.com/@vysec.private/backdoor-102-9226ae40ab10
[3]: https://medium.com/@vysec.private/backdoor-103-fully-undetected-adff649bac10
[ROP]: http://www.fuzzysecurity.com/tutorials/expDev/7.html
[Corelan]: https://www.corelan.be/index.php/articles/
[WAHH]: https://www.amazon.in/Web-Application-Hackers-Handbook-Exploiting/dp/8126533404
[Protostar]: https://exploit-exercises.com/protostar/
[Nebula]: https://exploit-exercises.com/nebula/
