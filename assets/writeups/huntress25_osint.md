---
layout: page
title: Huntress CTF 2025 OSINT
tags: [CTF, Learning, OSINT]
---

# Follow The Money

> Hey Support Team,
> We had a bit of an issue yesterday that I need you to look into ASAP. There's been a possible case of money fraud involving our client, Harbor Line Bank. They handle a lot of transfers for real estate down payments, but the most recent one doesn't appear to have gone through correctly.
> Here's the deal, we need to figure out what happened and where the money might have gone. The titling company is looping in their incident response firm to investigate from their end. I need you to quietly review things on our end and see what you can find. Keep it discreet and be passive.
> I let Evelyn over at Harbor Line know that someone from our team might reach out. Her main email is offline right now just in case it was compromised, she's using a temporary address until things get sorted out:

`evelyn.carter@51tjxh.onmicrosoft.com`

Read through the messages and identify likely BEC of Justin Case's account. Comparing his signature in Email 1 vs Email 5, there is a typo-squatted version of the evergatetitle domain:

```
Original: hxxps://evergatetitle.netlify.app/
Typo-Squatted: hxxps://evergatetltle.netlify.app/
```

Visting this site and entering fake details reveals a pop up with a base64 encoded string: `aHR0cHM6Ly9uMHRydXN0eC1ibG9nLm5ldGxpZnkuYXBwLw==` which decodes to:

`hxxps://n0trustx-blog.netlify.app/`

So flag 1 is `n0trustx`.

Visiting the _'hackers'_ blog, there is a linked [Github](https://github.com/N0TrustX). Reviewing the **spectre.html** file finds:

`<div id="encodedPayload" class="hidden">ZmxhZ3trbDF6a2xqaTJkeWNxZWRqNmVmNnltbHJzZjE4MGQwZn0=</div>`

Which gives the final flag:

**`flag{kl1zklji2dycqedj6ef6ymlrsf180d0f}`**

# Follow the Money - The Sequel

Found users X [account](https://x.com/N0TrustX) - reverse image lookup on [this image](https://x.com/N0TrustX/status/1974846974567629253/photo/1) got the town flag:

**`Wytheville`**

User also mentioned good Java and leaving compliments. A quick Google reveals a coffee shop across the street from the image that provided the town name called The Grind (also hinted at in an X post):

![the_grind](/assets/img/huntress_ctf25/the_grind.jpg)

Filtered Google reviews for the coffee shop by most recent to find the flag:

**`Flag{this_is_good_java}`**