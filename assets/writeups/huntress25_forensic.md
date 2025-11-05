---
layout: page
title: Huntress CTF 2025 Forensics
tags: [CTF, Learning, Forensics]
---

# Tabby's Date

> Ohhhh, Tab, Tab, Tab.... what has she done.
> My friend Tabby just got a new laptop and she's been using it to take notes. She says she puts her whole life on there!
> She was so excited to finally have a date with a boy she liked, but she completely forgot the details of where and when. She told me she remembers writing it in a note... but she doesn't think she saved it!!
> She shared with us an export of her laptop files.

Extract the notepad TabState folder at:

`D:\CTF\Huntress\2025\day9\tabbys_date.zip\C\Users\Tabby\AppData\Local\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState\`

Took a peak at the format of the files, then ran the following command to extract the flag:

```bash
find . -type f | xargs strings -ael | grep flag
```

**`flag{165d19b610c02b283fc1a6b4a54c4a58}`**

# Beyblade

> Sheesh! Some threat actor sure did let it rip on this host! We've been able to uncover a file that may help with incident response.

So we got a NTUSER registry file for this challenge.

"Let it rip" with `RegRipper` and reviewed the output. Search for **flag** and note the reference to part 1 of 8 with a snippet of the flag. Ran a regex which found 7 snippets:

```python
.*8[\.,\-_:;=]{1}[a-f0-9]{4}
```

I was missing part 6, which was a sneaky format change (**(6/8)-**)to the rest which is why my regex didn't pick it up - either way, got the flag:

**`flag{47cb5cd46d7bb34a0d9c315a99bb58de}`**

# Darcy

> Darcy has apparently been having a lot of fun with a unique version control system.
> She told me she hid a flag somewhere with her new tool and wants me to find it... I can't make any sense of it, can you?

For a day 20 challenge this one seemed a bit straightforward...

Unpacked the files, tried running `grep 'flag'` which just so happened to return the flag:

**`flag{a0c1e852e1281d134f0ac2b8615183a3}`**

# Webshellz

> The sysadmin reported that some unexpected files were being uploaded to the file system of their IIS servers.
> As a security analyst, you have been tasked with reviewing the Sysmon, HTTP, and network traffic logs to help us identify the flags!

## Flag 1 - Sysmon.extx

Quick review of the event log finds the 'net user' command being utilised. The password on first glance looks to be base64 but it doesn't decode to anything. Tried base32 and base85 as well. Asked ChatGPT which suggested base62 - got flag:

**`flag{03638631595684f0c8c461c24b0879e6}`**

## Flag 2 - revshell.aspx

Dumped all the HTTP objects from the pcap file to review. From looking at the Sysmon.evtx, a random looking binary in Program Data - **frpc.exe** was making a connection to `117.72.105.10:7000`. 

Ran grep for the **frpc** with the -C flag to show 5 lines before and after - spotted the network connection with an encoded string comment:

![webshellz2](/assets/img/huntress_ctf25/webshellz2.png)

Chucked this into CyberChef to decode via base32 for the flag:

**`flag{c7ba76c0a4484fe8c135a1195e8d94ed}`**

## Flag 3 - revshell.aspx

A review on some of the extracted webshell files revealed a lot of base64 type encoded strings. Decoding some of these helped correlate that the webshell commands use the format `Bin_<cmd>`. Done some statistics on the files using:

```bash
grep -Eho 'Bin_[a-zA-Z]{3,}' *.aspx | sort | uniq 
```

Checked a few of the results further and noted that some commands had an additional bit not captured in the previous grep. Updated it to:

```bash
grep -Eho 'Bin_[a-zA-Z]{3,}_?[a-zA-Z]{3,}' *.aspx | sort | uniq
```

This gave a better view of the commands. Final flag suggested how the webshell would be accessed, so focussed on any values referencing login or password - spotted **Bin_Div_Login**, so ran grep for this plus 5 lines either side. This identified a base64 encoded string which decoded to the final flag:

![webshellz3](/assets/img/huntress_ctf25/webshellz3.png)

**`flag{fb4e078a739ac4ce687eb78c2e51aafe}`**

# Puzzle Pieces Redux

> Well, I accidentally put my important data into a bunch of executables... just don't ask, okay?
> It was fine... until my cat Sasha stepped on my keyboard and messed everything up! OH NOoOoO00!!!!!111
> Can you help me recover my important data?

Unpacking the provided archive contains 16 PE32 files; all with same number of bytes. Try the old trusty `grep` for **flag{** and find it in a891a220.bin. Good start, so I used `xxd` to establish offset in the file, then extended this for all the files:

```bash
find . -type f -exec xxd -s 0x189b0 -l 16 {} \;

000189b0: 3561 6266 610a 0000 b0a3 0140 0100 0000  5abfa......@....
000189b0: 6639 6637 330a 0000 b0a3 0140 0100 0000  f9f73......@....
000189b0: 6438 3564 350a 0000 b0a3 0140 0100 0000  d85d5......@....
000189b0: 3136 6637 330a 0000 b0a3 0140 0100 0000  16f73......@....
000189b0: 3439 6638 620a 0000 b0a3 0140 0100 0000  49f8b......@....
000189b0: 6536 3831 370a 0000 b0a3 0140 0100 0000  e6817......@....
000189b0: 3032 7d0a 0000 0000 b0a3 0140 0100 0000  02}........@....
000189b0: 6439 6331 610a 0000 b0a3 0140 0100 0000  d9c1a......@....
000189b0: 3233 630a 0000 0000 b0a3 0140 0100 0000  23c........@....
000189b0: 3838 6132 640a 0000 b0a3 0140 0100 0000  88a2d......@....
000189b0: 666c 6167 7b0a 0000 b0a3 0140 0100 0000  flag{......@....
000189b0: 3438 3937 390a 0000 b0a3 0140 0100 0000  48979......@....
000189b0: 3566 3933 660a 0000 b0a3 0140 0100 0000  5f93f......@....
000189b0: 3962 6663 320a 0000 b0a3 0140 0100 0000  9bfc2......@....
000189b0: 6265 3761 310a 0000 b0a3 0140 0100 0000  be7a1......@....
000189b0: 6631 3862 610a 0000 b0a3 0140 0100 0000  f18ba......@....

# alternate including file names find . -type f -exec sh -c 'echo "--- {} ---"; xxd -s 0x189b0 -l 16 "{}"' \;
```

Clearly, within these files we have the relevant components to make the flag. However, there are too many possibilities so lets cut out the known bits to begin:

- a891a220 = flag{
- 6676585 = 02}

With the flag format being standard, that left 30 characters required to complete the hash, so 6 of the remaining files after immediately ruling out **99fa27fd897.bin** for only having 3 characters.

The challenge itself seemed to give a hint based on the cat name Sa**sha** alongside the **OH NOoOoO00!!!!!111** string. SHA1 didn't provide a pattern of use, but SHA256 did, the first flag file ended with a single 0, while the final piece ended with 8 of them. And we need 8 pieces to build the flag. Retrieval and concat of pieces can be achieved with:

```bash
RESULT=""
while read -r filename; do
    OFFSET=0x189b0

    FRAGMENT_HEX=$(xxd -s $OFFSET -l 5 -p "$filename")
    CLEAN_FRAGMENT_TEXT=$(echo "$FRAGMENT_HEX" | xxd -r -p | tr -d '\000')

    echo "[+] Extracted from: $filename -> $CLEAN_FRAGMENT_TEXT" >&2

    RESULT="${RESULT}${CLEAN_FRAGMENT_TEXT}"
done < <((find . -type f -print0 | xargs -0 sha256sum) | awk '
    {
        match($1, /0*$/);
        if (RLENGTH > 0) {
            print RLENGTH, $2, $1
        }
    }' | sort -k1,1n -k3 | awk '{print $2}')

echo "$RESULT"
```