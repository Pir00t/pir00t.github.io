---
layout: post
title: To stack or not to stack?
subtitle: You don't always have to reinvent the wheel...
image: /img/independent.png
tags: [coding]
---

Yesterday I read a rather interesting article on the BBC News site titled '[_Copycat coders create 'vulnerable' apps_](https://www.bbc.co.uk/news/technology-49960387)'. In short, _'lazy'_ developers reusing the code of others from sites such as Stack Overflow without considering what it may actually do, thus creating potential security risks.  
  
![https://me.me/i/ahoy-stack-overflow-again-seriously-me-wondering-how-ifucked-up-c6260f0cedd5491b98b8864172ae6c85](/img/ahoy.png)

The article has coincided with some recent code review I have done on some personal projects, some of which have reused code from online blogs and sites such as Stack Overflow. It made me think, how many people _actually_ understand the code they are copying. I mean, many questions that are asked on sites such as Stack are there due to a lack of knowledge or proper understanding on how to achieve something! Anyways, onward to some considerations. 

# Should I reuse code?
**Yes**, to a point and within reason. 
- If what you are trying to achieve is already out there and working well, utilise it
- Open source code and techie forums are fantastic places to find answers from like minded individuals
- **BUT** you should take the time to understand what the code that you plan to copy will do
  - Run tests in a development environment first to ensure things work as expected

> Sometimes writing code is a bit like doing University coursework, adapt it and make it your own, though give credit where it is due.

# What to be wary of (or avoid altogether)
- Some answers on the likes of Stack Overflow are years old and may not be up to standard with dependencies required (outdated/insecure)
- Sites you have never heard of that host code (especially hacking tools)
  - Some sites are setup to catch people out with malicious code/tools they may not understand
- Hardcoded values in open source tools/code
  - I've seen this happen for the tools such as Cobalt Strike where the default has not been removed/updated (OSINT search the hardcoded Cert for example)

There are many more arguments on this subject, however, I think the above notes cover a few key points. I've uploaded an example to my [Github](https://github.com/Pir00t/PY-Clean) of a Windows Directory Cleaner (written in **Python3**) which reused functions from a blog [post](https://www.pythoncentral.io/finding-duplicate-files-with-python/) on the topic. Some functions have been kept '_as is_' because they work, and I understand what they do. Others have been reworked or rewritten completely to suit my use for the script.

Drop me a line if you have any feedback :smiley: