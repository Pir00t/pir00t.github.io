---
layout: page
title: Huntress CTF 24 Reverse Engineering
tags: [CTF, Learning, Reverse Engineering]
---

# Rust Tickler

So we had a rust binary. Running `strings` spotted an encoded one that looked long enough to be the flag.

Opening the file in Ghidra, could see the string being compared by **memcmp**. For fun, wrote a simple Python script for finding flag based on known plaintext and XOR. 

```python
flag_bytes = bytes.fromhex("37 3d 30 36 2a 67 61 67 67 33 30 64 30 33 67 66 32 60 66 35 67 35 64 62 61 33 63 30 68 68 63 64 32 63 60 34 62 2c")
known_plaintext = b"flag{"

for key in range(256):
	decoded = bytes(b ^ key for b in flag_bytes)
	if decoded.startswith(known_plaintext):
		full_flag = decoded.decode()
		print(f"   Key (Hex): 0x{key:02x}")
		print(f"   Flag: {full_flag}")
```

Found the flag, but also noted that putting the string into CyberChef and using the XOR Bruteforce found flag with key **0x51** as well:

**`flag{6066ba5ab67c17d6d530b2a9925c21e3}`**

