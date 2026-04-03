# 👻 Ghost Protocol — GraySentinel CTF Challenge 4

**Category:** Network | **Difficulty:** Medium | **Points:** 300

> *"We intercepted an encrypted UDP stream from a covert C2 channel. The flag is in there — somewhere. Reverse the protocol and extract it."*

---

## 📦 Challenge Files

| File | Description |
|------|-------------|
| `code/capture.hex` | Packet capture of a suspicious UDP session |
| `code/challenge_server.py` | Live server (optional — for dynamic interaction) |

Players receive **only `capture.hex`**. The server is optional for teams that want live interaction.

---

## 🚀 Setup

### Static (Offline) Mode — Recommended
No setup needed. Just hand out `capture.hex`.

### Live Server Mode
```bash
pip install -r requirements.txt   # no external deps needed
python3 code/challenge_server.py
# Server listens on UDP 0.0.0.0:9999
```

---

## 🎯 Objective

Analyse the packet capture. Reverse-engineer the custom binary protocol. Decrypt the flag payload.

---

## 🔒 Flag Format

```
GRAYSENTINEL{...}
```

---

## 📁 Repo Structure

```
graysentinel-ctf-protocol-parser/
├── code/
│   ├── challenge_server.py   # Challenge server (host only)
│   ├── generate_capture.py   # Generates capture.hex (run once)
│   ├── capture.hex           # The challenge artifact given to players
│   └── solver.py             # SOLUTION — do not distribute
├── writeup/
│   └── solution.md           # Full write-up with step-by-step walkthrough
├── assets/
│   └── (screenshots)
└── README.md
```

---

*Part of the GraySentinel Cyber Training Programme (GCTPC)*
*Tag @GraySentinel | #GraySentinel #GCTPC #CTF #Python #CyberSecurity*
