# ₿ BIP39 Bitcoin Wallet Recovery Tool

> Open source GUI tool to recover Bitcoin wallets from incomplete BIP39 seeds. Built in pure Python, runs 100% offline.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Bitcoin](https://img.shields.io/badge/Bitcoin-BIP39%20%7C%20BIP84%20%7C%20BIP44%20%7C%20BIP49-orange?logo=bitcoin)
![License](https://img.shields.io/badge/License-MIT-green)
![Offline](https://img.shields.io/badge/Runs-100%25%20Offline-brightgreen)

---

## 📋 Table of Contents

- [About](#about)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [How to Use](#how-to-use)
- [Feasibility Analysis](#feasibility-analysis)
- [Security](#security)
- [License](#license)

---

## About

Built to help users who lost part of their BIP39 seed phrase, this tool performs an exhaustive search for the missing word(s) by comparing generated addresses against the user's known public address.

Everything runs **locally on your machine** — no data is ever sent to the internet.

---

## Features

| Mode | Description |
|---|---|
| 1 missing word — unknown position | Tests all positions automatically |
| 1 missing word — known position | Searches only the given position |
| 2 missing words — known positions | Tests all combinations for both positions |
| Partial with `?` | Mark unknown words with `?` |

- ✅ Support for **BIP84** (bc1q...), **BIP44** (1...) and **BIP49** (3...)
- ✅ Support for **passphrase** (extra password)
- ✅ **Smart feasibility analysis** with time estimates
- ✅ **Dark mode** graphical interface
- ✅ Real-time exportable log
- ✅ Automatic BIP39 wordlist validation

---

## Requirements

- **Python 3.8 or higher**
  - Download at: https://python.org/downloads
  - ⚠️ During installation, check **"Add Python to PATH"**

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/bitcoin-recovery.git
cd bitcoin-recovery
```

Or download the ZIP from GitHub and extract it to a folder.

### 2. Install dependencies

**Windows:**
```bash
python -m pip install mnemonic bip32utils bech32 base58
```

**Mac/Linux:**
```bash
pip3 install mnemonic bip32utils bech32 base58
```

Wait for `Successfully installed...` to appear in the terminal.

---

## How to Use

### Opening the program

**Windows — option 1 (CMD):**
```bash
cd "C:\path\to\bitcoin_recovery"
python bitcoin_recovery.py
```

**Windows — option 2 (drag & drop):**
1. Open CMD (`Win + R` → type `cmd` → Enter)
2. Type `python ` (with a space)
3. Drag `bitcoin_recovery.py` from File Explorer into the CMD window
4. Press Enter

**Mac/Linux:**
```bash
cd ~/path/to/bitcoin_recovery
python3 bitcoin_recovery.py
```

The graphical interface will open automatically.

---

### Step by step inside the program

#### 🔑 Recovery Tab

**1. Choose the mode:**
- Don't know where the missing word is → *unknown position*
- Know the position → *known position* (much faster)
- Missing 2 words and know both positions → *2 missing words*
- Have some words scattered and don't know others → *partial mode with `?`*

**2. Paste your seed words into the field:**
- Separate by space
- In partial mode, use `?` for unknown positions
- Example: `abandon legal ? market bright ? sun ...`

**3. Fill in your credentials:**
- **Passphrase:** extra password used when creating the wallet (leave empty if none)
- **Bitcoin address:** the public address you know (e.g. `bc1q...`)
- **Type:** BIP84 for `bc1q...`, BIP44 for `1...`, BIP49 for `3...`

**4. Click ▶ START RECOVERY**

The log will show real-time progress. When found, the complete seed phrase will be displayed.

---

### 📊 Feasibility Analysis Tab

Use this tab before starting to know if recovery is realistic:

1. Enter your seed size (12 or 24 words)
2. Enter how many words you have
3. Check what you have (password, address, derivation path, position)
4. Click **CALCULATE ANALYSIS**

The tool will show:
- Realistic time estimate
- Difficulty level (Easy / Moderate / Hard / Infeasible)
- Tips on what else could help

---

## Feasibility Analysis Summary

| Situation | Estimated Time |
|---|---|
| 1 word missing — known position | Seconds |
| 1 word missing — unknown position | 5 to 20 minutes |
| 2 words missing | Hours |
| 3 words missing | Days to weeks |
| 4+ words missing | Months to eternity |

> Every additional word you remember divides the search time by 2048.

---

## Security

> ⚠️ **IMPORTANT — read before using**

- Always run **offline** — disconnect from the internet before running
- **Never** enter your seed phrase on websites or online services
- **Never** share your seed words with anyone
- This program does not send any data over the internet
- All processing happens locally on your machine
- After finding your seed, write all 24 words on paper and transfer your Bitcoin to a new wallet

---

## Dependencies

```
mnemonic>=0.21
bip32utils>=0.3
bech32>=1.2
base58>=2.1
```

---

## License

MIT License — © 2026 your-username

You are free to use, copy, modify and distribute this software **with attribution to the original author**.  
See the [LICENSE](LICENSE) file for full details.
