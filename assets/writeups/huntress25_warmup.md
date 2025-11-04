---
layout: page
title: Huntress CTF 25 Warmups
tags: [CTF, Learning, Warmups]
---

# Read The Rules

Follow link provided. Inspected the page source code and perform a search for **_flag{_** to find the flag:

**`flag{bf61aced6e7f9335385a70f33b20d188}`**

# Technical Support

Comes with hint that flag may be in discord channel - _#ctf-open-ticket_

With the hint, head over to the discord channel `#ctf-open-ticket` and grab the flag: 

**`flag{68cc5f95b59112d7d6b041cd16f9f19d}`**

# Spam Test

As suggested, a quick Google for the term **Generic Test for Unsolicited Bulk Email** returns a [Wiki](https://en.wikipedia.org/wiki/GTUBE) that contains a table of hashes for the string, thus giving the flag:

**`flag{6a684e1cdca03e6a436d182dd4069183}`**

# Cover All Your Bases

CyberChef is your friend for the majority of the flags in this one, which seen an increment to the Base **n** for each decoding.

| Encoding | Flag |
| :--- | :--- |
| Binary | `flag{678ac45487c9862a6c2c00a1affed9dc}` |
| Octal | `flag{fe580e05e527f20421290605809caec9}` |
| Base10 | `flag{7d1eb2e0776cd7c5c78df01010f30e50}` |
| | (Charcode Base 10 in CyberChef) |
| HEX | `flag{d3cb2be3e4e4a8f517d9c5ce4372b0b7}` |
| Base32 | `flag{9bb5bb8ea508bcffbc51bd5e11efb29cc}` |
| Base45 | `flag{b5bef376027104b8c73dafbe95be47f4}` |
| Base64 | `flag{cd0164ff64726f2972b2d8f2ac0119db}` |
| Base85 | `flag{a414ae096381d9594c58e785b3c95dfb}` |
| Base92 | `flag{0c97042d855d7b353dc87c91ea902129}` |
| | (Remove whitespace first in CyberChef) |
| Base65536 | `flag{4571745dcd4d16f8d6f0a7fdaf71528c}` |
| | (Decode with this [link](https://www.better-converter.com/Encoders-Decoders/Base65536-Decode)) |

# Just a Little Bit

Another for the Chef that is Cyber... Popped the data into CyberChef, reducing the byte length of "From Binary" to 7 to reveal the flag:

**`flag{2c33c169aebdf2ee31e3895d5966d93f}`**

# QRception

Plenty of online QR Code decoders, the output was all messed up but looked like another QR code in ASCII format. This [site](https://dnschecker.org/qr-code-scanner.php) gave the best output format. I took a screenshot of the output, chucked it in CyberChef to render the image and Parse QR Code for the flag:

**`flag{e1487f138f885bfef64f07cdeac96908}`**

# RFC 9309 (AKA Robots Exclusion Protocol)

Start the instance, browse to **vm/robots.txt** and perform a search for **_flag{_**:

**`flag{aec1142c199aa5d8ad0f3ae3fa82e13c}`**

# See In the Dark (REMOVED DUE TO HOST PROVIDER)

Open the onion link in TOR browser for the flag:

**`flag{a9d40962c465c571fe4edd288bf0f0b5}`**

# Maximum Sound

This one took way longer to pick up on the decoding method than the team would like to admit I reckon! After establishing the file was utilising SSTV, used an online [tool](https://sstv-decoder.mathieurenaud.fr/) to extract the image from the WAV. Cropped the unusual 'QR' looking code, which is apparently something called **Aztec** (Thanks ChatGPT):

![sstv_image](/assets/img/huntress_ctf25/sstv_decoded.png)

Found a [decoder](https://zxing.org/w/decode.jspx) online to extract the flag:

**`flag{d60ea9faec46c2de1c72533ae3ad11d7}`**

# Snooze

Run `file` command on the provided file - doesn't give much away. Pop into CyberChef - identifies as **tar.z** file. Change the extension of the file and run `uncompress snooze.tar.z`. 

`cat` the flag from returned snooze.tar

**`flag{c1c07c90efa59876a97c44c2b175903e}`**