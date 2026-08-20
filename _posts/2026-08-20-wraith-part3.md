---
layout: post
title: WRAITH — Part 3
subtitle: Triage, IoC Correlation, and the Audit Trail
cover-img: /assets/img/ai/wraith.png
thumbnail-img: /assets/img/ai/wraith_p3.jpg
share-img: /assets/img/ai/wraith_p3.jpg
tags: [dfir, ai, homelab, wraith]
---

## Overview

Part 2 covered single-session assessment: parsing, deterministic ATT&CK enrichment, and a guardrailed LLM call per session. This post covers what sits either side of that — filtering out sessions before they reach the model at all, correlating flagged sessions across the dataset afterward, and logging every decision to an audit trail. 

**If there’s a typo lurking in the homepage image thumbnail, blame the AI. Turns out spell-checking pixels requires a different model than spell-checking code.**

---

## Trivial Session Filtering

Most Cowrie sessions are just connect/disconnect noise: no login attempt, no commands, gone in under a second. Sending those to the LLM adds nothing and just creates hallucination surface for no benefit. 

`is_trivial_session()` filters them out before assessment:

```python
def is_trivial_session(summary) -> bool:
	return (
		summary.login_attempts == 0
		and len(summary.commands) == 0
		and len(summary.files_downloaded) == 0
		and (summary.duration_seconds or 0) < 1.0
	)
```

Trivial sessions get an automatic benign result with no model call. `triage_batch()` checks this first for every session, before anything reaches `analyze_session()`.

---

## IoC Correlation

Once a session is independently classified suspicious or malicious, `correlate_ioc()` looks up every other session sharing its source IP:

```python
def correlate_ioc(target, all_summaries) -> IoCHistory:
	related = [
		s for s in all_summaries
		if s.src_ip == target.src_ip and s.session_id != target.session_id
	]

	return IoCHistory(
		indicator=target.src_ip,
		related_session_ids=[s.session_id for s in related],
		any_login_success=any(s.login_success for s in related),
		total_commands=sum(len(s.commands) for s in related),
		total_downloads=sum(len(s.files_downloaded) for s in related),
	)
```

This replaces an earlier approach of asking the LLM to reason about correlation inside the single-session prompt. That proved unreliable — multi-fact reasoning across sessions is exactly where these models are weakest, and it's not really a judgment call to begin with, just a lookup. Python does it deterministically and _correctly_ every time.

Correlation only runs after a session earns a suspicious/malicious classification on its own. It's not run on every session, and it doesn't feed back into that session's own classification — it's context attached after the fact, for a human reviewing the flag.

---

## The Audit Trail

`audit_log.py` writes one JSONL record per session per run, trivial skips and LLM assessments alike. Each record captures the classification, every technique decision (including excluded candidates and their justification), the IoC history if correlation ran, and the model/temperature/seed for reproducibility.
 
Records are never edited or overwritten. Re-running a session through an updated prompt produces a new record, not a replacement, since the history of how an assessment changed across iterations is itself useful.
 
The more interesting part is a cheap heuristic that flags a specific pattern for review: an excluded technique whose justification uses isolation-type language ("in isolation", "on its own", "alone", "by itself") on a session that also has other included techniques.
 
```python
ISOLATION_LANGUAGE = ["in isolation", "on its own", "alone", "by itself"]
```
 
This exists because of a real finding while testing. A session had five candidate techniques offered. The model correctly excluded T1078 on the reasoning that a single successful login wasn't significant in isolation. Taken alone, that's correct; the T1078 threshold logic from Part 2 exists for exactly this reason. But the same session had four other techniques included. In context, that login wasn't isolated at all. It was one part of a broader session that had already earned a suspicious classification on other grounds. Right reasoning, wrong scope.
 
The heuristic doesn't fix that — it's not a solved problem, and it won't catch every case of contextually-blind exclusion. It just surfaces the pattern for a human to look at, which is what an audit trail is for. 

---

## Design Notes

- Trivial-session filtering happens before the LLM call, not after — cheaper and removes hallucination surface entirely rather than catching it downstream
- IoC correlation is deterministic lookup, not LLM reasoning — cross-session correlation stays in Python
- The audit log is append-only; nothing is ever overwritten
- The contextually-blind heuristic is a starting point, not a general solution — it catches one specific pattern (isolation-language exclusion alongside other inclusions)

---

## Next Steps

The pipeline is now end-to-end and verified against synthetic data: parse → enrich → assess → guardrail → triage → correlate → log. Everything so far has been tested against realistic but fabricated Cowrie logs. Next is standing up an actual honeypot to generate real attacker traffic for the pipeline to process.
