---
layout: post
title:  "Juno XSS Challenge"
date:   2019-06-01 07:10:14 +0000
categories: Web Penetration-Testing Hacking
tags:
    - Web
    - Hacking
    - Penetration Testing
thumbnail: computer
---
Recently during one weekend i was bored and decided to browse a around various sources for something to do related to security during this, I saw juno (link) had pushed out a challenge for Cross site scripting, 
however some of my Cross site scripting ablity is lacking, i found this challengne and the ending result which i was unable to achive quite neat.
The link for the challenge is here:
```http://x.imjuno.com/funny/?comment=XSS``` However at the time of posting the link is currently not active. 

The final payload was ``````http://x.imjuno.com/funny/?comment=w://%27name=%27www%27onfocus=%27alert(document.domain);%27.github.io#www`````` provided by [stypr](https://twitter.com/hayakudesu) 

this would allow the malicous cross site scripting to execute, however during testing one would notice this seemed to be in a unexploitable condition. payloads such as ```comment=<svg/onload=prompt(1)>``` would display as ```var1:[0]{array> <svg/onload=prompt(1)>}``` making triggering this vulnerablity signficatly harder. So lets break down the above payload to understand why this triggered the condition.
```?comment=``` being the injectable parameter.
```w://``` is quite important this causes the application accept the payload. This could be replaced with ```file://```, ```tel://``` and any other [URI Handlers](https://www.w3.org/wiki/UriSchemes)

```'name='www'``` set the name variable tag to later be rendered out.
```'onfocus'alert(document.domain);'``` this setups the exploitable condition to be a zero interaction condition. ```onload and onclick``` will not execute in this condition.
The next part is quite tricky. ```.github.io```  for this to execute you must use a existing domains such as ``` *.withgoogle.com, *.github.io```. This causes the payload to become executable, to trigger the payload you must use the URL hash bypass the zero interactive parameter. This then causes the cross site scripting to execute successfully. 

I was unable to solve this successfully during the time but i did find the ability to chain this together quite neat. 
