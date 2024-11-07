---
layout: page
title: Huntress CTF 24 Reverse Engineering
tags: [CTF, Learning, Malware]
---

# OceanLocust (without debug info)

Start with some basic checks - file is 64-bit console app, strings suggest PNG has to be supplied as an argument. Additionally spot ref to chacha expand 32-byte k (turned out not to be relevant for the flag).

Review Huntress [post](https://www.huntress.com/blog/advanced-persistent-threat-targeting-vietnamese-human-rights-defenders) on the TA of similar naming as the challenge; OceanLotus.

Trying to run the program throws an error, that suggests a PNG path is missing. Loaded into Ghidra, searched for the string and identified where this string was being utilised: **140007c30**. This is quite a large function that is undefined within Ghidra. Analysis suggests it checks for args that have been passed from command line (which are read in this main function: **14001eb44**).

Ok, so next step was to run the file with the PNG provided as an argument. We get an error asking for a flag. Review the function 140001370 again as this is where the error string is called and spot a check if arg is < 0x7. Armed with this new info, I tried running like so:

`png-challenge.exe inconspicuous.png 1234567`

> Prior to loading into x64dbg, I removed the DLL can move attribute on the binary to disable ASLR.

Knowing now that the PNG was likely to be read, I set a break on NtReadFile as this is imported by the binary. The function containing the call for NtReadFile (**140010660**) is called by **140010350** and **1400104c0**, which ultimately, lead back to the undefined function of interest: **140001370**.

At **1400018ff**, there is a call to **140005c60**, which passes the PNG as arg[2]. Within this function, there is another call made to **140005e50** which contains some interesting behaviour:

- Calls 140006560 which is like a PNG validator - 
  - seemed to also break up into chunks
- Loop starts just after the above is called which processes the PNG chunks
- addr 140005F50 - loops over the characters but I hadn't ID'd the XOR key statically

Dynamically, spotted a trend of **biT[a-h]** being read after the standard PNG data chunks. It seems clear XOR is at play, however, watching the data process shows no sign of the flag. R8 is continually updated and then reset each chunk. However, after noting the counter (9) and that each **biT[a-h]** is followed by a similar number of bytes - could this be a clue for decryption? Play around with the bytes, assuming biTa will be first if its for a flag. Copy the 5 bytes after the section name into CyberChef, and try decoding with the bytes that biT[a-h] produce when walking through the loop - no dice! Try just XOR using the section name and dang, we have a flag{ string!

Wrote a rudimentary Python script to extract the necessary bytes, and XOR decrypt the data to get the flag:

```python
import re

# XOR function for two byte sequences
def xor_bytes(key, data):
	return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def find_and_decrypt_bytes(file_path):

	final_result = b""

	# Regex to match 'biT[a-h]' followed by 5 bytes
	pattern = re.compile(rb'(biT[a-h])(.....)')

	with open(file_path, 'rb') as f:
		data = f.read()

		matches = list(pattern.finditer(data))
		sorted_matches = sorted(matches, key=lambda match: match.group(1))

		for match in sorted_matches:
			key = match.group(1) # 'biT[a-h]' (5 bytes)
			encrypted_data = match.group(2) # The 5 bytes following 'biT[a-h]'

			decrypted_data = xor_bytes(key, encrypted_data)

			# Filter out non-printable bytes from decrypted data
			printable_data = ''.join(chr(b) for b in decrypted_data if 32 <= b <= 126)

			final_result += printable_data.encode('utf-8')

	# Convert final result to a string
	try:
		return final_result.decode('utf-8')
	except UnicodeDecodeError:
		return final_result.decode('utf-8', errors='ignore')

file_path = 'inconspicuous.png'
result = find_and_decrypt_bytes(file_path)
print("Final decrypted result:", result)
```

**`flag{fec87c690b8ec8d65b8bb10ee7bb65d0}`**

# GoCrackMe1

Load in Ghidra, spot some hex values being loaded then XOR'd by **0x56** in **main.main**.

Copy them out into CyberChef, swap endianness, then XOR with 0x56 for the flag:

**`flag{bb59566e21f55e5680d589f3dbbec0f8}`**

# GoCrackMe2

Load in Ghidra and resolve function names, strings etc. via GhidraScripts.

Flag generation takes place in **main.main** - spot XOR value of **0x6d** and a load of variables being loaded in registers. Try running the binary - note that it randomly generates parts of the beginning of the flag, but flag{ is always visible so begin to wonder where it comes from:

![gcm2_flag_parts](/assets/img/huntress_ctf24/gcm2.png)

A further review of the code let me to this section:

![gcm2_code](/assets/img/huntress_ctf24/gcm2code.png)

Which, when playing with the XOR key and the variables (swapped endianness) established all parts of the flag. I set a breakpoint on the final instruction in image above, then stepped once before viewing the register data with `x /64bx $rsp+0x2a` to obtain the bytes I needed (I've removed the 2 irrelevant bytes from my memory dump).

```
0xc00008ccea:	0x5c	0x09	0x0e	0x5d	0x54	0x5b	0x5b	0x5b
0xc00008ccf2:	0x0b	0x5a	0x58	0x5d	0x55	0x5a	0x55	0x0b
0xc00008ccfa:	0x5e	0x54	0x5d	0x5a	0x58	0x5c	0x10	0x0b
0xc00008cd02:	0x01	0x0c	0x0a	0x16	0x58	0x5a	0x0b	0x0e
0xc00008cd0a:	0x59	0x09	0x5f	0x5e	0x5f	0x59		
```

Based on the largest output of testing (screenshot above) and knowing the last part of the flag ending with "}", I was able to format the flag:

**`flag{f75087857fc4d23241dc09666f390751}`**

# In Plain Sight (The one that got away...)

So this was the only challenge the team and I didn't manage to solve. Turns out we were so close, having extracted the required data. We just hadn't realised what to do with it for making the flag!

Side note: unsure if the author used this [tool](https://github.com/Nordgaren/stealth-win), though what I seen in the binary seemed to suggest perhaps they did. Also, the general approach was a little like Rusty Bin (undocumented due to time) except it was noted this one had additional layers of XOR for key data points.

Onto the challenge. After a bit of static analysis, and disabling ASLR, I opened the binary in x64dbg. An address that stood out was **1400019B0** as this loaded a PNG into memory, suggesting perhaps some data extraction or manipulation - coming back to this later.

Continuing analysis reaches 1400034D0, which decodes the bytes that print text into the console. I was able to establish that the XOR key bytes were loaded from the PNG into memory, while the data to be decoded via XOR was loaded from the .rsrc section. Still not sure how useful it would have been but I noted the keys were 0x6E7 bytes apart in the PNG file. Perhaps a mix of dynamic, then static for scripting would extract the necessary info.

A bit like the Rusty Bin challenge, the correct password was established by tracking the program flow through XOR. In the case of this challenge, multiple layers of XOR were used before anything was printed out. I also observed a few of the XOR loops not touched when doing a "correct" run through with the password: **password12345**

![ips_bps](/assets/img/huntress_ctf24/ips_bps.png)

To break into these other areas, the key point in program seemed to be **140002A90**, where it would make a comparison against AAAAA. Playing around with the jump instruction directly after this would alter what data is loaded and decrypted - for reference, I counted hitting this point 14 times which led me to **140002B07**. This loaded a big blob of encrypted data from the .rsrc section, with bytes split by 00 bytes. Continuing analysis, it reads an XOR key 0x58f bytes long!

Eventually, we end up with:

![ips_out](/assets/img/huntress_ctf24/ips_out.png)

*My team mate had cycled through other additional messages which saved me time reaching this point!

Unfortunately, time was running out and we hadn't established the IP's related to the flag. So upon the competition ending, I revisited this and put together a script that would have recovered the flag had we known what to look for:

```python
ips = ["10.25.3.103", "10.5.13.54", "10.185.7.102", "172.21.29.54", "172.20.20.51", "172.30.27.54", "192.168.34.57", "192.168.71.6", "10.76.2.97", "10.199.9.97", "192.168.245.16", "172.25.31.54", "192.168.226.0", "10.215.6.57", "192.168.41.1", "10.212.10.49", "10.119.16.50", "10.0.0.102", "172.30.21.57", "192.168.43.2", "192.168.113.16", "172.26.24.100", "192.168.89.12", "172.21.33.101", "192.168.37.125", "172.17.19.49", "10.169.8.52", "10.179.4.123", "172.29.22.50", "192.168.180.8", "172.28.26.97", "172.24.23.50", "192.168.40.18", "172.16.30.98", "10.13.1.108", "192.168.42.0", "172.16.17.102", "10.105.11.55", "192.168.36.49", "172.30.18.56", "172.24.25.99", "192.168.100.12", "192.168.35.97", "172.30.28.99", "172.27.32.53", "192.168.58.18", "10.184.15.101", "192.168.50.15", "10.129.5.53", "10.126.12.98", "10.32.14.57"]

key_pairs = []
for ip in ips:
    octets = ip.split('.')
    key_pair = {
        "pos": octets[-2],
        "char": octets[-1]
    }
    key_pairs.append(key_pair)

# Sort the key-pairs by the 'host' key
sorted_key_pairs = sorted(key_pairs, key=lambda x: int(x['pos']))

flag = []
for kp in sorted_key_pairs:
    flag.append(chr(int(kp['char'])))

print("".join(flag))
```

**`flag{59f4a17b69e2f813922dca6c6b65e9a1}`**