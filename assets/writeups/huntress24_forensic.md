---
layout: page
title: Huntress CTF 24 Forensics
tags: [CTF, Learning, Forensics]
---

# Nightmare on Hunt Street

**What is the IP address of the host that the attacker used?**

`10.1.1.42` - Ran Chainsaw and found this in lateral movement output.

**Times brute forced (jsmith)**

`32` - chainsaw output

**What is the name of the offensive security tool that was used to gain initial access? Answer in all lowercase.**

`psexec` - based on remote service being added (Event ID 7045) and the random named binary 

**How many unique enumeration commands were run with net.exe? Answer just the integer value.**

`3` - Performed search with Chainsaw for **net.exe**. Then a Regex in CyberChef to establish the count- CommandLine: .*

**What password was successfully given to the user created?**

`Susan123!` - found alongside previous answer

# Little Shop of Hashes

**What is the name of the service that the attacker ran and stopped, which dumped hashes on the first compromised host?**

Host B - `Remote Registry`

**What lateral movement technique did the threat actor use to move to the other machine?**

`Pass The Hash`

**What is the full path of the binary that the threat actor used to access the privileges of a different user with explicit credentials?**

`C:\Users\DeeDee\Documents\runasc.exe`

**How many accounts were compromised by the threat actor?**

Host A - `3` - Chainsaw, checked lateral movement output - excluding administrator = 3

**What is the full path of the binary that was used as a callback to the threat actor's machine?**

Host A - `C:\Users\DeeDee\Documents\nc.exe`

# Zimmer Down

Had issues with RegistryExplorer so ran RegRipper instead. Spotted:

```
2024-10-02 02:48:04Z
{F38BF404-1D43-42F2-9305-67DE0B28FC23}\c3NlcnRudUhzc2VydG51SHNzZXJ0bnVIc3NlcnRudUhzc2VydG51SHNzZXJ0bnVI.exe (2)
2024-10-02 02:47:57Z
  {F38BF404-1D43-42F2-9305-67DE0B28FC23}\aXRzX2FfcmVkX2hlcnJpbmcgbG9s.exe (1)

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.dll
LastWrite Time 2024-10-02 02:48:01Z
MRUListEx = 1,0
  1 = d2FmZmxld2FmZmxld2FmZmxld2FmZmxl.dll
```

Decoded from base64, these are false flags but also spot this:

```
Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.b62
LastWrite Time 2024-10-02 02:47:01Z
MRUListEx = 0
  0 = VJGSuERgCoVhl6mJg1x87faFOPIqacI3Eby4oP5MyBYKQy5paDF.b62
```

Base62 decoded via CyberChef for flag:

**`flag{4b676ccc1070be66b1a15dB601c8d500}`**
