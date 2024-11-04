---
layout: page
title: Huntress CTF 24 Warmups
tags: [CTF, Learning, Warmups]
---

# Technical Support

_Comes with hint that flag may be in discord channel - `#ctf-open-ticket`_

With the hint, head over to the discord channel `#ctf-open-ticket` and grab the ~~same flag as last year~~ flag: 

**`flag{a98373a74abb8c5ebb8f5192e034a91c}`**

# Read The Rules

Follow link provided. View the page source code and perform a search for _flag{_ to find the same flag as last year:

**`flag{90bc54705794a62015369fd8e86e557b}`**

# base64by32

Use CyberChef to decode for flag. Recipe:

```
Label('top')
From_Base64('A-Za-z0-9+/=',true,false)
Jump('top',31)
```

**`flag{8b3980f3d33f2ad2f531f5365d0e3970}`**

# Too many bits

Decode binary string with CyberChef:

**`flag{d01471702a10134cdad1ddde06678f2f}`**

# MatryoshkaQR

Render and parse the QR code using CyberChef which produces PNG bytes. Tried cleaning up in CyberChef, then gave up and just used Python to write the bytes to a file. Copy the new file into CyberChef again to get the flag:

**`flag{01c6e24c48f48856ee3adcca00f86e9b}`**

# No need for Brutus

Google "brutus cryptography" and get results referencing Caesar/Vigenere - missed the plaintext when looking at Caesar in CyberChef, so ended up using [dcode](https://www.dcode.fr/vigenere-cipher) to decode with key (QQQ) and get the plaintext: **caesarissimplenoneedforbrutus** which means flag in requested format is:

**`flag{c945bb2173e7da5a292527bbbc825d3f}`**

# Cattle

Given the name, and content of the file I Googled for "cow cipher" and found this [link](https://mysterytoolbox.organisingchaos.com/Ciphers/cipher/Moo) - entered the content and decrypted for the flag:

**`flag{6cd6392eb609c6ae4c332ef6a321d9dd}`**

# Unbelievable

Check file format - it isn't an mp3, but a PNG - change extension and open to get the flag:

**`flag{a85466991f0a8dc3d9837a5c32fa0c91}`**

# TXT Message

Click the link to see reference to Octal - use this [site](https://centralops.net) to get the TXT record, copy into CyberChef and decode with Octal to get the flag:

**`flag{14e072f705d45882401d141c562fdc0b}`**

# Whamazon

Given this is a warmup challenge, assume some form of 'bogus' entry will enable me to beat the system. Submit a negative integer to get enough money i.e. -111111111111111111111. Then buy the flag, win Rock, Paper, Scissors (simple logic...)

**`flag{18bdd83cee5690321bb14c70465d3408}`**

# Mystery

Use an online Enigma emulator https://cryptii.com/pipes/enigma-machine to crack the code with the given settings:

**`flag{fdfeabcacbebfbadaefbeccaadddbafe}`**

# I Can't SSH

Since we have the private key to use, try connecting with -i to pass the key file - get message about permissions being too open so fix with `chmod 600 id_rsa`. Get a new errors about the key being invalid. `cat` to terminal and spot a missing newline at the end, add this and connect successfully. List directory then `cat` the flag file:

**`flag{ee1f28722ec1ce1542aa1b486dbb1361}`**