# Pattern-Guard

**Behavior anomaly guard for applications.**

Pattern-Guard is a Rust-native behavior anomaly guard that detects and controls unusual application behavior before it becomes a problem.

- **Repository:** `pattern-guard`  
- **Crate:** `pattern-guard`

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [Solution Overview](#solution-overview)
- [Core Concept](#core-concept)
- [Event Model](#event-model)
- [Responsibilities & Scope](#responsibilities--scope)
- [System Architecture](#system-architecture)
- [Integration Model](#integration-model)
- [Configuration Philosophy](#configuration-philosophy)
- [Why Rust](#why-rust)
- [Who it's for](#who-its-for)
- [Long-Term Vision](#long-term-vision)
- [More docs](#more-docs)
- [Quick start](#quick-start)
- [One-Sentence Definition](#one-sentence-definition)

---

## Problem Statement

Modern backends, scripts, and services are protected mostly by **rate limiters** and **static rules**.

These protections fail when:

- Abuse happens **under** rate limits
- Bots mimic human-like request counts
- Internal scripts or cron jobs misbehave
- Bugs cause repeated or looping behavior
- Systems waste CPU, DB, or money before alarms trigger

Today, developers repeatedly re-implement:

- Burst checks
- Strange pattern detection
- Ad-hoc guards in handlers
- Custom logic per project

**There isn’t a general, reusable behavior-level guard in the Rust ecosystem yet. I built this as a small contribution, hoping it might help someone or spark further ideas. If even one person finds it useful, I’d consider that a success.**

---

## Solution Overview

Pattern-Guard is a **behavior anomaly detection and decision engine** that sits inside or in front of application logic and answers:

> **Is this behavior normal right now?**

It does not inspect payloads, authenticate users, or replace firewalls. You feed it events; it returns a decision (allow, warn, delay, block). Your code decides what to do with that.

---

## Core Concept

```
Event → Observe → Analyze Pattern → Risk Score → Decision (allow / warn / delay / block)
```

- Pattern-Guard is **stateless from the outside**, but **stateful internally**.
- It maintains **short-lived behavioral memory**, not permanent logs at least for now.
- It **recommends** a decision; it does **not** enforce. Callers act on the decision.

---

## Event Model

An **Event** is a normalized description of something happening.

| Field       | Required | Description                              |
|------------|----------|------------------------------------------|
| `actor`    | Yes      | Who caused it (user, IP, service, script) |
| `action`   | Yes      | What was done (GET, POST, run, query)     |
| `target`   | Yes      | What was affected (endpoint, command, resource) |
| `timestamp`| Yes      | When it happened                         |
| `weight`   | No       | Cost/impact of the event                 |
| `metadata` | No       | Tags or context                          |

Pattern-Guard is **framework-agnostic** because everything becomes an event.

---

## Responsibilities & Scope

| It does | It does not |
|--------|-------------|
| Observe events, model behavior, score risk, map to decisions (allow / warn / delay / block) | Authenticate, authorize, inspect payloads, enforce blocks, coordinate across nodes |
| Time-bounded in-memory patterns, config-driven | Persistent storage, distributed coordination, WAF/firewall replacement |

---

## System Architecture

High-level modules:

```
pattern-guard
├── Event Tracker
├── Pattern Analyzer
├── Decision Engine
├── Policy & Config
└── Output / Enforcement
```

### 1. Event Tracker

- Stores recent events in memory  
- Organizes by actor and target  
- Uses sliding time windows  
- Automatically expires old data (TTL)  

### 2. Pattern Analyzer

- Computes statistics over windows  
- Detects: bursts, repetition, intervals, switching patterns  
- Produces a **risk score** (e.g. 0.0 → 1.0), not a verdict  

### 3. Decision Engine

- Converts risk into decisions  
- Applies configured thresholds  
- Supports escalation (warn → delay → block)  

### 4. Policy & Config

- Declarative rules (TOML)  
- Global defaults  
- Per-actor overrides  

### 5. Output

- Returns a **recommended decision** to the caller  
- **CLI:** can control execution (e.g. wrap a command)  
- **Library:** caller enforces (HTTP 429, sleep, etc.). Pattern-Guard does not enforce.  

---

## Integration Model

### Inside a backend

```
Request arrives
    ↓
Create Event
    ↓
Pattern-Guard.check(event)
    ↓
Decision
    ↓
Either: continue | delay | block
```

**Pattern-Guard never touches business logic.**

### CLI usage

```bash
pattern-guard --config guard.toml -- my_script.sh
```

- Observes command behavior  
- Helps prevent runaway scripts  
- Logs suspicious execution  

---

## Configuration Philosophy

- **Human-readable** (TOML)  
- **Explicit** (no hidden magic)  
- **Safe defaults**  
- **Override-friendly**  

Example concepts: time windows, thresholds, risk-to-decision mapping, pattern definitions.

---

## Why Rust

Pattern-Guard requires:

- High-frequency event handling  
- Shared mutable state  
- Precise timing  
- Long-running safety  

Rust provides:

- Thread safety without runtime overhead  
- Predictable memory usage  
- Deterministic performance  
- Strong ecosystem for systems tooling  

This project would be harder and less reliable in GC-based runtimes.

---

## Who it's for

Backend and platform teams, CLI authors, anyone who’s wired up burst checks or “too many requests” logic by hand. Rust didn’t have a shared behavior-level guard; this is one.

---

## Long-Term Vision

The core design (event → observe → risk score → decision) stays. Future work could add:

- Optional ML or richer scoring models (same risk interface)  
- Persistent storage or distributed coordination  
- Metrics, dashboards, alerting  
- WASM / plugin system  

The engine remains a **signal generator**, not a gatekeeper.

---

## More docs

- [Config schema](docs/CONFIG.md) — TOML keys and defaults.
- [Use cases](docs/USE-CASES.md) — when to use it; mapping requests to events.

Example configs: [guard.toml.example](guard.toml.example), [guard.toml.demo](guard.toml.demo). API: `cargo doc --open`.

---

## Quick start

Load a config, build an event, call the guard. You get back a decision and (optionally) a risk score.

```rust
use pattern_guard::{Guard, Event};
use std::time::SystemTime;

let guard = Guard::from_config_path("guard.toml")?;
let event = Event::new("user:123", "GET", "/api/foo", SystemTime::now());
let (decision, risk) = guard.check_with_risk(&event);
// decision: Allow | Warn | Delay(_) | Block
```

From the repo you can run the CLI or the examples:

```bash
# One run, one event
cargo run -- --config guard.toml.demo -- true

# Same process, N runs (burst accumulates)
cargo run -- --config guard.toml.demo --repeat 5 -- true

# Burst demo: one process, 8 events → Allow → Warn → Delay → Block
cargo run --example burst_demo

# Repetition demo: same action/target repeated
cargo run --example repetition_demo
```

`RUST_LOG=info` turns on log output for warn/delay/block.

---

## One-Sentence Definition

Use this everywhere (docs, crates.io, talks):

> **Pattern-Guard is a Rust-native behavior anomaly guard that detects and controls unusual application behavior before it becomes a problem.**
