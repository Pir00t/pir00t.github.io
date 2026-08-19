---
layout: post
title: WRAITH — Part 1
subtitle: Building the Foundations
cover-img: /assets/img/ai/wraith.png
thumbnail-img: /assets/img/ai/foundations.png
share-img: /assets/img/ai/foundations.png
tags: [dfir, ai, homelab, wraith]
---

## Overview

This post documents the initial setup of my AI-driven DFIR homelab project, WRAITH — Workbench for Rapid Analysis, Intelligence & Triage Hunts.

The goal is a local, auditable pipeline that processes real attacker data — sourced from a home honeypot — and applies controlled AI reasoning on top of deterministic parsing. Nothing here is production tooling. It's a portfolio and learning project, built to understand where AI genuinely helps in DFIR work and where it doesn't.

This first post covers environment setup only: getting Python, uv, and a local LLM running, and laying out a repo structure that separates experimentation from anything more durable.

---

## Environment Setup

System:
- Windows
- Python 3.13
- Ollama

### Installing uv

First attempt was `pip install uv`, which technically works but doesn't reliably add itself to PATH — it installs into the active Python's `Scripts` folder, which may or may not be on your system PATH depending on how that Python was set up. After hitting exactly that problem, I uninstalled and switched to the standalone installer:

```powershell
pip uninstall uv

powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Close and reopen the terminal afterward — PATH changes don't apply to an already-open session.

### Creating the environment

```powershell
uv venv
.venv\Scripts\activate
```

`uv` expects `venv` by default, editors auto-detect it, and it's already covered by a standard Python `.gitignore`.

### Installing dependencies

```powershell
uv pip install pandas pydantic langgraph ollama notebook ipykernel rich python-dotenv requests
```

For now, I've deliberately left LangChain out. LangGraph handles orchestration; pulling in full LangChain on top adds abstraction and dependency weight I don't need yet, and would hide mechanics I'd rather understand by building manually first (prompt templates, output parsing) before reaching for a library that does it for me.

### Registering a Jupyter kernel

```powershell
python -m ipykernel install --user --name wraith
```

Registers a named kernel pointing at this specific venv, so Jupyter doesn't default to whatever global Python it finds first.

---

## Repository Structure

```
notebooks/          # exploratory / Jupyter work
src/
  parsers/           # deterministic log parsing (no LLM calls)
  enrichment/         # rule-based enrichment (e.g. ATT&CK technique matching)
  llm/                 # LLM interaction layer
  graph/                # LangGraph orchestration
  guardrails/            # output validation before anything reaches memory
  memory/                  # per-case context and history
  audit/                     # append-only decision logging
data/
  raw/                # unprocessed source logs
  processed/           # parser output
logs/
scripts/
```

The `notebooks/` vs `src/` split exists on purpose: notebooks are a scratchpad for testing ideas against sample data, and anything that proves stable graduates into a proper module under `src/`. 

---

## Local LLM Setup

I've opted for Ollama to keep inference local — no data leaving the environment, no API cost, and one less variable to reason about when the input data is untrusted (more on that below).

```powershell
ollama pull llama3.1:8b
ollama run llama3.1:8b
```

### Model choice

`llama3.1:8b` was chosen to fit my hardware. My GPU has 8GB VRAM — sitting at roughly 4.7GB, comfortably within that budget with headroom for context.

---

## Design Notes

Decisions carried forward from this stage:

- No LangChain for now — build the underlying mechanics manually first
- LangGraph reserved for orchestration once the pipeline has more than one linear path
- Parsing and validation stay outside the LLM entirely — deterministic Python does the extraction, the LLM only reasons over already-structured data
- All attacker-sourced data is treated as untrusted input, not as instructions — this applies to command text, filenames, and anything else pulled from honeypot sessions

That last point matters more than it might read at first glance. Attacker data is the one input in this pipeline that's actively hostile by design — it's the reason the parsing and guardrails layers exist in the first place.

---

## Next Steps

Building the first parser against real (well — realistic synthetic) session data, and getting a first structured response out of the LLM layer.
