---
layout: page
title: Huntress CTF 23 Warmups
subtitle: "Difficulty: Easy"
tags: [CTF, Learning, Warmups]
---

# Technical Support

_Comes with hint that flag may be in discord channel - `#ctf-open-ticket`_

With the hint, head over to the discord channel `#ctf-open-ticket` and grab the flag: 

**flag{a98373a74abb8c5ebb8f5192e034a91c}**

# Read The Rules

Follow link provided - the flag is not displayed anywhere. View the page source code and perform a search for _flag{_ to find it:

**flag{90bc54705794a62015369fd8e86e557b}**

# String Cheese

Taking the challenge name as a hint, run `strings` on the file for the flag:

**flag{f4d9f0f70bf353f2ca23d81dcf7c9099}**

# Notepad

No extension so run `file` to establish: _UTF-8 Unicode text_. `cat` the file to return the contents and retrieve the flag:

**flag{2dd41e3da37ef1238954d8e7f3217cd8}**

# Query Code

Check file type using `file` which returns that this should be a PNG file. Update the extension to be provided with a QR Code. Scan the QR code using this [site](https://online-barcode-reader.inliteresearch.com/) which returns the flag:

**flag{3434cf5dc6a865657ea1ec1cb675ce3b}**

# Book By Its Cover

Check file type using `file` which returns that this should be a PNG file. Update the extension and open to see the flag (typed out as OCR didn't pick up correctly):

**flag{f8d32a346745a6c4bf4e9504ba5308f0}**

# Caesar Mirror

_NOTE: this flag does not follow the usual MD5 hash standard flag format. It is still wrapped with the code>flag{} prefix and suffix._

Based on the challenge name and the ~~subtle~~ hint, one can assume ROT13 is in play here. However, the format being mirrored means that ROT13 only gets half text readable at one time. At the time, I used CyberChef with ROT13 to read each flag section, then reverse by Line to read the other half of the text to establish the flag:

**flag{julius_in_a_reflection}**

After completing I chucked together a small script that 'unmirrored' the text so the whole lot could have ROT13 applied correctly:

```python
with open('caesarmirror.txt', 'r') as f:
    lines = f.read().splitlines()

splits = []
for line in lines:
    splits.append(line.split('   '))

for split in splits:
    filtered = [s for s in split if s != ''] # remove empty results
    filtered[1] = filtered[1][::-1] # reverse mirrored portion
    print("".join(filtered))
```

![caesarmirror](/assets/img/huntress_ctf23/caesarmirror.png)

# BaseFFFF+1

From the challenge name, it can be determined that FFFF+1 is 65536 but not what to do with it. After some searching, find right result by googling _"base64 decode 65536 characters"_ which is a very niche [conversion tool](https://www.better-converter.com/Encoders-Decoders/Base65536-Decode).

**flag{716abce880f09b7cdc7938eddf273648}**

# Dialtone

My initial step was to check waveforms and spectogram for the flag but with no success. Next I researched other number audio forensics and discover **DTMF**. Try a few decoders and get the same result:

`13040004482820197714705083053746380382743933853520408575731743622366387462228661894777288573`

After failing to decode in CyberChef, look up INT types and decide to treat as a _long int_. Doing so in Python allowed for conversion to get the flag:

```python
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(13040004482820197714705083053746380382743933853520408575731743622366387462228661894777288573))
```

**flag{6c733ef09bc4f2a4313ff63087e25d67}**

# Layered Security

Check file type: _GIMP XCF image data_. Open in gimp and start removing layers until I landed on one with a flag in it:

**flag{9a64bc4a390cb0ce31452820ee562c3f}**

# Comprezz

Check file type: _compress'd data 16 bits_. Try 7-zip on the off chance which gives me **comprezz~**. Check the file type again and its ASCII text. `cat` for the flag:

**flag{196a71490b7b55c42bf443274f9ff42b}**

# Chicken Wings

File is _UTF-8 Unicode_. `cat` produces various symbols so start researching chicken type cipher (well there is a pigpen one!). Based on this I stumbed across wingding images! Found decoder [online](https://www.dcode.fr/wingdings-font) which I used to get the flag: - catch on that Unicode like this represents wingdings - find online decryptor and get flag:

**flag{e0791ce68f718188c0378b1c0a3bdc9e}**

# F12

Connect to the instance provided and use F12 to inspect content. I could see JavaScript to call `./capture_the_flag.html` so append this to the instance URL. From here, view source to find the flag:

**flag{03e8ba07d1584c17e69ac95c341a2569}**

# Baking

Start instance and connect with dev tools open. Spot a cookie which is a base64 string that when decoded, contains a date/time format. Initial attempts to _hack_ the timer resulted in more time being added. It was then I realised I had to convert a timestamp from _"the past"_ into base64 and apply it as a new cookie value. Doing so retrieved the flag:

**flag{c36fb6ebdbc2c44e6198bf4154d94ed4}**
