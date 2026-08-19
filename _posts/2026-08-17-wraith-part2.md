---
layout: post
title: WRAITH — Part 2
subtitle: Parsing, Enrichment, and a First Guardrailed Assessment
cover-img: /assets/img/ai/wraith.png
thumbnail-img: /assets/img/ai/wraith_p2.jpg
share-img: /assets/img/ai/wraith_p2.jpg
tags: [dfir, ai, homelab, wraith]
---

## Overview

Part 1 covered environment setup only. This post covers the first working slice of the pipeline: turning raw Cowrie events into a structured session summary, generating candidate ATT&CK techniques deterministically, and getting a first guardrailed response out of the LLM layer.

Everything here is tested against realistic synthetic Cowrie data, not live traffic.

---

## The Parser

`cowrie_parser.py` is the deterministic layer. No LLM calls happen here. It takes Cowrie's flat JSON event stream and groups it into one summary per session:

```python
class SessionSummary(BaseModel):
	session_id: str
	src_ip: str
	start_time: Optional[str] = None
	end_time: Optional[str] = None
	duration_seconds: Optional[float] = None
	login_attempts: int = 0
	login_success: bool = False
	successful_credentials: Optional[str] = None
	commands: list[str] = []
	files_downloaded: list[str] = []
	event_count: int = 0
```

`SessionSummary` is a Pydantic model rather than a plain dataclass. It's the object every downstream layer receives, so validating shape here means malformed parsing fails at the source instead of turning into a confusing type error two or three layers down.

---

## Deterministic ATT&CK Enrichment

Before anything reaches the LLM, `attack_mapping.py` generates a candidate list of MITRE ATT&CK techniques using regex against commands and session metadata. No model involved. Technique names aren't hardcoded — they're resolved from a local lookup (`attack_lookup.py`) built by downloading and indexing the MITRE ATT&CK Enterprise STIX dataset.

Thresholds are named constants rather than magic numbers, following the pattern used in [Panther's](https://github.com/panther-labs/panther-analysis) detection rules:

```python
BRUTE_FORCE_MIN_ATTEMPTS = 3      # >= this many login attempts before T1110.001 applies
VALID_ACCOUNTS_MAX_ATTEMPTS = 2   # T1078 only applies if success came within this many attempts
```

The second constant exists because of a mistake in the first pass. Any successful login was treated as T1078 (Valid Accounts) on its own. But a login that succeeds after many failed attempts isn't a valid/leaked credential — it's the culmination of brute force, which is T1110. The fix narrows T1078 to only apply when success follows a low attempt count, and states that attempt count explicitly in `matched_on` rather than leaving the model to infer it. Worth doing — an earlier version had the model speculating about "possible brute-force" on a session where `login_attempts` was 1, because the number wasn't in front of it plainly enough.

---

## LLM Assessment

`session_assessment.py` is where candidates get handed to the model for judgment.

Early on, one low-signal session came back with a fabricated technique — T1210, invented from nothing, never offered as a candidate. Asking for JSON in a fixed shape doesn't stop a model filling a `technique_id` field with something plausible instead of something real.

The fix was constraining the output schema itself, built fresh per call:

```python
def build_dynamic_schema(candidate_ids: list[str]) -> type[BaseModel]:
	n = len(candidate_ids)

	if candidate_ids:
		id_type = Literal[tuple(candidate_ids)]
	else:
		id_type = str

	dynamic_technique_decision = create_model(
		"DynamicTechniqueDecision",
		technique_id=(id_type, ...),
		included=(bool, ...),
		justification=(str, ...),
	)

	dynamic_session_assessment = create_model(
		"DynamicSessionAssessment",
		summary=(str, ...),
		classification=(Literal["benign", "suspicious", "malicious"], ...),
		confidence=(Literal["low", "medium", "high"], ...),
		techniques=(list[dynamic_technique_decision], Field(..., min_length=n, max_length=n)),
	)
	return dynamic_session_assessment
```

`Literal` (from `typing`) restricts a field to a fixed set of values instead of accepting any string — Pydantic rejects anything outside that set at validation time. So `technique_id` can only ever be one of the candidates offered for this session. There's no slot for an invented ID.

That closed the hallucination itself, but testing surfaced a second problem: the model could return the same candidate twice with contradictory `included` values. `Field(..., min_length=n, max_length=n)` closes that by forcing the array to exactly the number of offered candidates — no listing one twice, no skipping one.

Empty-candidate sessions fall back to `id_type = str` rather than an empty `Literal` — the array length constraint already forces `techniques` to length 0 in that case, so nothing can be added regardless of what the type allows.

### Guardrails

Even with the schema doing the work at generation time, `analyze_session()` runs three checks after the fact:

1. Structural validation against the dynamic schema
2. No duplicate technique IDs, and every returned ID is in the offered candidate set
3. Every offered candidate was addressed — no silent omissions

These should be structurally impossible given the schema above, but grammar-constrained decoding isn't a hard guarantee across every model/runtime combination, so they stay as defense-in-depth. A guardrail failure returns `None` rather than a best-effort guess — triage treats that as its own outcome, which I'll cover in the next post.

---

## Design Notes

Decisions carried forward from this stage:

- Pydantic used only at genuine validation boundaries — the parser's output object and the LLM's output schema, not elsewhere
- Constraining the output schema at generation time closed a hallucination mode that after-the-fact checking hadn't
- Numeric facts the model needs (attempt counts, thresholds) are stated explicitly rather than left for it to infer
- Deterministic enrichment and LLM judgment stay separate — the model decides whether a candidate applies, it never generates the candidate list

---

## Next Steps

Single-session assessment is reliable and guardrailed now. It still can't reason across sessions — correlating a flagged session against other activity from the same source IP, or filtering out sessions with no signal before they reach the model at all. That's triage and the audit trail, both deterministic Python either side of the LLM layer.