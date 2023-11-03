---
layout: page
title: Huntress CTF 23 Misc
subtitle: "Difficulty: Easy / Medium"
tags: [CTF, Learning, Misc]
---

# I Won't Let You Down - Easy

_OK Go take a look at this IP: Connect here: http://155.138.162.158_

_USING ANY OTHER TOOL OTHER THAN NMAP WILL DISQUALIFY YOU. DON'T USE BURPSUITE, DON'T USE DIRBUSTER. JUST PLAIN NMAP, NO FLAGS!_

NMAP the IP provided with command such as `nmap -sV 155.138.162.158`. Based on the results, and this being an Easy challenge I presume either port **80** or **8888** will be where to find the flag. As it happens, visiting the site on port **8888** displays some well known Rick Astley lyrics, followed by the flag which then disappears/resets. A couple of options are available here - fastest finger (time it write to kill the page connection and keep the flag) or connect to the service with the likes of `telnet`.

The second option, prints the song lyrics to terminal along with the flag so it is a simple job to copy/paste for the points:

**`flag{93671c2c38ee872508770361ace37b02}`**

# Rock, Paper, Psychic - Medium

Straight away, I think this will be a "crack me" type of challenge so I open in the binary in Ghidra. Poking around, I spot a function for **playerWins @ offset: 004169d0** which is what we presumably want to do! Backtrack via XREFs to find out where this would be called from and just below a function for **determineWinner** is a `JNZ @ offset 00416be6`. This Jump Not Zero is never going to be taken, given the "Psychic" nature of the program. 

Before firing up x64dbg, I popped the file into CFF Explorer and validated the binary does not use ASLR (i.e. the memory address mapping will match Ghidra). With this checked, I opened the binary in x64dbg, set a breakpoint at `00416be6` then hit F9 to run. Enter any of the options when prompted in the console and you'll eventually hit the breakpoint:

![rockpaperpsychic](/assets/img/huntress_ctf23/rockpaperpsychic.png)

Note that here, the ZF is set to 1 (highlighted purple). Double click this value to change it to 0, then continue running the program to get the flag:

![rppwin](/assets/img/huntress_ctf23/rppwin.png)

**`flag{35bed450ed9ac9fcb3f5f8d547873be9}`**

To solve purely statically, the function **fromRC4 @ offset 00416919** is clearly of interest, given the algorithm is a popular one for string encryption. Reviewing the XREF, when the function is called there are 2 long strings of interest being passed to it. _param\_1_ contains `gnnhexnyjkwpaghynzfthadollhtrhballsdmhhnbjppewgjkhnlhspwjswqoxtgdykxrhwlabblekxj` and passed to **genKeystream @ offset 00416311** which is used to create the KSA S-Box for the algorithm. Following this, the PRGA loop is implemented to loop through 0-256, utilising _param\_2_ for input (which by now can be assumed to be the ciphertext: `D1E2A0D9FA89CABED207EDF4F55C688E04EBE20F077351BDAA1E110D5A74805C916AF12F054C`). 

With this information, you could use CyberChef to decrypt the ciphertext with the following recipe:

```json
[
  { "op": "RC4",
    "args": [{ "option": "UTF8", "string": "gnnhexnyjkwpaghynzfthadollhtrhballsdmhhnbjppewgjkhnlhspwjswqoxtgdykxrhwlabblekxj" }, "Hex", "Latin1"] }
]
```

# M Three Sixty Five - Easy

There was 4 flags to find within the instance provided for this challenge. Once connected, the banner displayed suggested that [AADInternals](https://aadinternals.com/aadinternals/) was to be utilised. From there it was a case of searching the documentation to find the relevant commands to complete each task.

## General Info - Find the street address

`Get-AADIntTenantDetails | Select street`

**`flag{dd7bf230fde8d4836917806aff6a6b27}`**

## Conditional Access - Lookup Conditional Access Policies

The only one I had an issue with in which running the correct command returned 0 policies. Eventually on my 3rd reset of an instance this command worked!

`Get-AADIntConditionalAccessPolicies`

**`flag{d02fd5f79caa273ea535a526562fd5f7}`**

## Teams - Find the sensitive message in Teams

`Get-AADIntTeamsMessages | Select Content`

**`flag{f17cf5c1e2e94ddb62b98af0fbbd46e1}`**

## The President - Find the unintentionally left information

Initial search to find user with "President" in their Title:

`Get-AADIntUsers | Select UserPrincipalName,ObjectId,Title`

Followin this, rerun but solely select the president to view all their details and get the flag:

`Get-AADIntUsers | where Title -eq 'President`

**`flag{1e674f0dd1434f2bb3fe5d645b0f9cc3}`**

# PRESS PLAY ON TAPE - Easy

_While walking home through a dark alley you find an archaic 1980s cassette tape. It has "PRESS PLAY ON TAPE" written on the label. You take it home and play it on your old tape deck. It sounds awful. The noise made you throw your headphones to the floor immediately. You snagged a recording of it for analysis._ 

Sounds like an _"old"_ modem when played, but research along this route doesn't provide anything useful. Try googling the name of the challenge which points towards commodore 64? Apparently, you can turn WAV files into relevant files for the console - who knew!

Find this [toolset](https://wav-prg.sourceforge.io/index.html) which I downloaded and installed onto my VM. After a little trial and error on the output, selecting PRG file was the correct option; which when opened in text editor provides a variant of the flag: **FLAG\[32564872D760263D52929CE58CC40071\]**. Convert to proper format:

**`flag{32564872d760263d52929ce58cc40071}`**

# Babel - Medium

Checking the file type, reveals it is C++ source. On opening there is some apparent text and variable obfuscation and a big blob of encoded text which could be interesting. I converted the functions into Python like so in order to decode the blob:

```python
def transform_text(t, k):
    alphabet_case = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    transformed = ""
    map_dict = {}
    
    for i in range(len(alphabet_case)):
        map_dict[k[i]] = alphabet_case[i] # map each letter in the key to the alphabet
    
    for char in t:
        if ('A' <= char <= 'Z') or ('a' <= char <= 'z'):
            transformed += map_dict[char] if char in map_dict else char
        else:
            transformed += char

    return transformed

def main():
    t = "<blob>" # main blob to transform
    k = "lQwSYRxgfBHqNucMsVonkpaTiteDhbXzLPyEWImKAdjZFCOvJGrU" # likely key
    
    result = transform_text(t, k)
    print(result)

if __name__ == "__main__":
    main()

```

Taking the new output, which is proper base64 format, I converted it in CyberChef which revealed a binary file. Running `strings` and `grep` on the file finds the flag:

**`flag{b6cfb6656ea0ac92849a06ead582456c}`**

# Who is Real - Easy

_This is not a technical challenge, but it is a good test of your eye! Now we live in a world of generative AI, for better or for worse. The fact of the matter is, threat actors can scheme up fake personas to lure you into a scam or social engineering... so, can you determine which profile picture is real and which is fake?_

I'm not entirely sure what was up with this challenge, it felt a bit "guessy". Either way, clicked the correct image 5 times to get the flag:

**`flag{10c0e4ed5fcc3259a1b0229264961590}`**

# Indirect Payload - Medium

_We saw this odd technique in a previous malware sample, where it would uncover it's next payload by... well, you'll see._ 

Connect to the instance with Developer Tools open. In the network tab the page keeps trying to redirect. Try using `curl` to follow the redirects and find out that it has a 50 redirect limit by default. Try raising to 100 but this also hits the limit. Double the redirect follow limit again to 200 and this seems to work as I now have a **sorry.php** but with no useable data to note.

Run wireshark and submit request again then view http objects. Spot a trend in 302 responses that they are providing single characters to build the flag! Extract these HTTP Objects, though unfortunately the order is not kept. Write a python script to read each file and extract the flag in order:

```python
import os

def get_files():
    redir_txt = []

    for file in os.listdir('.'):
        if file.endswith('.php'):
            with open(file, 'r') as f:
                content = f.read().strip()
                redir_txt.append(content)
    return redir_txt

def sort_order(content):
    words = content.split()
    for word in words:
        if word.isdigit():
            return int(word)
    return 0

def get_flag(content):
    flag_chars = []
    for item in content:
        flag_chars.append(item.split()[-1])

    print(''.join(flag_chars))

def main():
    content = get_files()
    ordered = sorted(content, key=sort_order)
    get_flag([item for item in ordered if item != '']) # drop any '' values in list that cause errors

if __name__ == '__main__':
    main()
```

**`flag{448c05ab3e3a7d68e3509eb85e87206f}`**

# Welcome to the Park - Easy

_The creator of Jurassic Park is in hiding... amongst Mach-O files, apparently. Can you find him?_

Unzip the provided file. Inside the _welcome_ dir there is a **.hidden** dir with a file. Run `strings` to get a base64 string.

![park1](/assets/img/huntress_ctf23/park1.png)

Decoded this is an XML/plist file with some string obfuscation. Piece together via regex (recipe below) to get GitHub gist with a picture (and some trolling). 

```json
[
  { "op": "Regular expression",
    "args": ["User defined", "'([^';]*)", true, true, false, false, false, false, "List matches"] },
  { "op": "Find / Replace",
    "args": [{ "option": "Regex", "string": "['\"\\n]" }, "", true, false, true, false] }
]
```

Tried the hash in URL but incorrect so I downloaded the image, and ran `strings` and `grep` to find the actual flag:

**`flag{680b736565c76941a364775f06383466}`**

# Operation Eradication - Medium

_Oh no! A ransomware operator encrypted an environment, and exfiltrated data that they will soon use for blackmail and extortion if they don't receive payment! They stole our data! Luckily, we found what looks like a configuration file, that seems to have credentials to the actor's storage server... but it doesn't seem to work. Can you get onto their server and delete all the data they stole!?_

After researching, it appeared that `rclone` was the likely candidate for the tool the config file came from. I also found links on how to unobfuscate the password but did not try this method. Eventually get rclone to work having failed recreating a new config file, I just copied the provided one and gave the connection a name:

```bash
cat ~/.config/rclone/rclone.conf 
    [ctf]
    type = webdav
    url = http://chal.ctf.games:30691/webdav
    vendor = other
    user = VAHycYhK2aw9TNFGSpMf1b_2ZNnZuANcI8-26awGLYkwRzJwP_buNsZ1eQwRkmjQmVzxMe5r
    pass = HOUg3Z2KV2xlQpUfj6CYLLqCspvexpRXU9v8EGBFHq543ySEoZE9YSdH7t8je5rWfBIIMS-5
```

Check connection and list files: `rclone ls ctf:` this returns the fill directory listings. Try to purge everything but do not have the permissions to do so. Seen from discord chat that upload functionality worked, so read up on how to copy files to a webdav directory via `copyto`. Knowing this works, I decided to try and "wipe" the files by utilising an empty file in their place. Some additional prep was to run the list files command again and output to _files.txt_ then created an empty.txt file via `touch`. 

Now file "wipe" can be achieved in a bash one-liner:

`for f in $(cat files.txt); do rclone copyto empty.txt ctf:$f; done`

Refreshing the page shows the number of files going down, until eventually...:

**`flag{564607375b731174f2c08c5bf16e82b4}`**

# Discord Snowflake Scramble - Easy

_Someone sent message on a Discord server which contains a flag! They did mention something about being able to embed a list of online users on their own website... Can you figure out how to join that Discord server and see the message? Connect here: https://discord.com/channels/1156647699362361364/1156648139516817519/1156648284237074552_

Do some research around Discord and snowflakes. Find links to timestamp converter online and waste some time getting nowhere with it. Lookup Discord link formats and find this very useful site [discordlookup.com](https://discordlookup.com/) which refers to guildID. Unsure what this actually is, though research suggests that the first number is the guildID. Using the lookup tool from this site, it produces an invite link to **BABYSHARK** server. Join it and find the flag:

**`flag{bb1dcf163212c54317daa7d1d5d0ce35}`**

# MFAatigue - Medium

_We got our hands on an NTDS file, and we might be able to break into the Azure Admin account! Can you track it down and try to log in? They might have MFA set up though..._ 

Having done my fair share of password cracking with NTDS.dit files, I at least knew how to do the first part of this challenge. I used `secretsdump` from **Impacket** to extract the hashes from the ntds.dit. Then I ran them through hashcat with **rockyou.txt**.

Get a hit for: JILLIAN_DOTSON - so I started the instance and try to login. Rather helpfully, the page provides the domain to append to the username (huntressctf). Once the MFA button appears I just spammed my mouse button until flag appears:

**`flag{9b896a677de35d7dfa715a05c25ef89e} `**