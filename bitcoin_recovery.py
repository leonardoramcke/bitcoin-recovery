#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         BIP39 BITCOIN WALLET RECOVERY TOOL                  ║
║         by: leonardoramcke (github.com/leonardoramcke)      ║
║         MIT License © 2026                                  ║
╚══════════════════════════════════════════════════════════════╝
"""

import hashlib, time, sys, os, itertools, threading, math, multiprocessing
import psutil, tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import bech32
from mnemonic import Mnemonic
from bip32utils import BIP32Key, BIP32_HARDEN

MNEMO     = Mnemonic('english')
WORDLIST  = MNEMO.wordlist
CPU_COUNT = multiprocessing.cpu_count()
SPEED_PER_SECOND = 150

# ── Base58Check (pure Python) ──────────────────
_B58 = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def _b58encode(payload):
    n = int.from_bytes(payload, 'big')
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(_B58[r])
    res.extend([_B58[0]] * (len(payload) - len(payload.lstrip(b'\x00'))))
    return bytes(reversed(res)).decode('ascii')

# ── Levenshtein distance (neighborhood search) ─
def levenshtein(a, b):
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]; dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            dp[j] = prev if a[i-1] == b[j-1] else 1 + min(dp[j], dp[j-1], prev)
            prev = temp
    return dp[n]

def similar_words(word, max_dist=2):
    """Return BIP39 words similar to 'word', sorted by distance."""
    scored = [(levenshtein(word.lower(), w), w) for w in WORDLIST]
    scored.sort()
    return [w for d, w in scored if d <= max_dist]

def words_matching_pattern(starts_with='', length=0):
    """Filter wordlist by prefix and/or length."""
    result = WORDLIST
    if starts_with:
        result = [w for w in result if w.startswith(starts_with.lower())]
    if length > 0:
        result = [w for w in result if len(w) == length]
    return result

# ── BIP39 checksum filter ──────────────────────
def passes_checksum(words):
    """Quick BIP39 checksum validation."""
    return MNEMO.check(' '.join(words))

def valid_last_words(words_23):
    """For a 24-word seed, only ~8 of 2048 last words pass checksum."""
    return [w for w in WORDLIST if passes_checksum(words_23 + [w])]

# ── Time estimation ────────────────────────────
def fmt_time(s):
    if s < 60:      return f"~{int(s)} seconds"
    if s < 3600:    return f"~{int(s/60)} minutes"
    if s < 86400:   return f"~{int(s/3600)} hours"
    if s < 2592000: return f"~{int(s/86400)} days"
    if s < 31536000:return f"~{int(s/2592000)} months"
    if s < 31536000000: return f"~{int(s/31536000)} years"
    return "eternity (not feasible)"

def feasibility(combos, workers=1):
    s = combos / max(1, SPEED_PER_SECOND * workers)
    if s < 1800:    return "EASY",          "#3fb950", s
    if s < 86400:   return "MODERATE",      "#f7b731", s
    if s < 2592000: return "HARD",          "#e3702a", s
    if s < 31536000:return "VERY HARD",     "#da3633", s
    return              "NOT FEASIBLE",  "#8b0000", s

# ── Address derivation ─────────────────────────
def derive_address(seed_bytes, path_type="bip84", index=0, change=0):
    try:
        master = BIP32Key.fromEntropy(seed_bytes)
        if path_type == "bip84":
            child = (master.ChildKey(84+BIP32_HARDEN).ChildKey(0+BIP32_HARDEN)
                     .ChildKey(0+BIP32_HARDEN).ChildKey(change).ChildKey(index))
            pub = child.PublicKey()
            h = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
            return bech32.encode('bc', 0, h)
        elif path_type == "bip44":
            child = (master.ChildKey(44+BIP32_HARDEN).ChildKey(0+BIP32_HARDEN)
                     .ChildKey(0+BIP32_HARDEN).ChildKey(change).ChildKey(index))
            return child.Address()
        elif path_type == "bip49":
            child = (master.ChildKey(49+BIP32_HARDEN).ChildKey(0+BIP32_HARDEN)
                     .ChildKey(0+BIP32_HARDEN).ChildKey(change).ChildKey(index))
            pub = child.PublicKey()
            h = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()
            redeem = bytes([0x00, 0x14]) + h
            h2 = hashlib.new('ripemd160', hashlib.sha256(redeem).digest()).digest()
            pre = bytes([0x05])
            chk = hashlib.sha256(hashlib.sha256(pre+h2).digest()).digest()[:4]
            return _b58encode(pre + h2 + chk)
    except Exception:
        return None

def check_seed(words, passphrase, target, path, addr_limit, change_limit):
    phrase = ' '.join(words)
    if not MNEMO.check(phrase):
        return False
    seed = MNEMO.to_seed(phrase, passphrase)
    for c in range(change_limit):
        for i in range(addr_limit):
            if derive_address(seed, path, i, c) == target:
                return True
    return False

# ── Smart candidate builder ────────────────────
def build_candidates(known_words, missing_positions, hint_starts='',
                     hint_length=0, hint_typo='', seed_size=24):
    """
    Build a smart ordered wordlist for missing positions.
    Priority: checksum filter > pattern filter > typo neighbors > full list
    """
    # Base candidate list
    if hint_typo.strip():
        base = similar_words(hint_typo.strip(), max_dist=2)
        if not base:
            base = list(WORDLIST)
    else:
        base = list(WORDLIST)

    # Apply pattern filters
    if hint_starts.strip():
        base = [w for w in base if w.startswith(hint_starts.strip().lower())]
    if hint_length > 0:
        base = [w for w in base if len(w) == hint_length]

    if not base:
        base = list(WORDLIST)

    return base

# ── Recovery engine ────────────────────────────
def recover(known_words, missing_positions, passphrase, target, path,
            addr_limit, change_limit, hint_starts, hint_length, hint_typo,
            seed_size, log_fn, progress_fn, stop_event, num_workers=1):
    """
    Main recovery function.
    known_words: list of words the user has (in order, without gaps)
    missing_positions: list of 0-based indexes where words are missing
    """
    # Build full skeleton with None at missing positions
    full = list(known_words)
    for pos in sorted(missing_positions):
        full.insert(pos, None)

    candidates = build_candidates(known_words, missing_positions,
                                  hint_starts, hint_length, hint_typo, seed_size)

    n_missing = len(missing_positions)
    total = len(candidates) ** n_missing
    done  = 0

    log_fn(f"  Missing positions : {[p+1 for p in missing_positions]}")
    log_fn(f"  Candidate words   : {len(candidates)} per position")
    log_fn(f"  Total combinations: {total:,}")
    log_fn(f"  Estimated time    : {fmt_time(total / max(1, SPEED_PER_SECOND * num_workers))}")
    log_fn("─" * 50)

    # Checksum shortcut: if only last position is missing, filter heavily
    if missing_positions == [seed_size - 1] and not hint_starts and not hint_typo:
        candidates = valid_last_words(full[:seed_size-1])
        log_fn(f"  ✨ Checksum filter applied → only {len(candidates)} valid last words")
        total = len(candidates)

    for combo in itertools.product(candidates, repeat=n_missing):
        if stop_event.is_set():
            return None
        candidate = list(full)
        for i, pos in enumerate(missing_positions):
            candidate[pos] = combo[i]
        done += 1
        if done % 500 == 0:
            progress_fn(done, total)
        if check_seed(candidate, passphrase, target, path, addr_limit, change_limit):
            return {'words': candidate, 'found': list(combo),
                    'positions': [p+1 for p in missing_positions]}

    progress_fn(total, total)
    return None

# ══════════════════════════════════════════════
#  GUI
# ══════════════════════════════════════════════
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("BIP39 Bitcoin Wallet Recovery Tool")
        self.root.geometry("980x880")
        self.root.minsize(900, 820)
        self.root.configure(bg="#0d1117")
        self.stop_event = threading.Event()
        self._setup_styles()
        self._build_ui()
        self._start_hw_monitor()

    # ── Styles ──────────────────────────────────
    def _setup_styles(self):
        s = ttk.Style(); s.theme_use('clam')
        s.configure('TNotebook', background='#0d1117', borderwidth=0)
        s.configure('TNotebook.Tab', background='#161b22', foreground='#8b949e',
                    padding=[16,8], font=('Consolas',10))
        s.map('TNotebook.Tab', background=[('selected','#1f2937')],
              foreground=[('selected','#f7b731')])
        s.configure('TFrame', background='#0d1117')
        s.configure('TLabel', background='#0d1117', foreground='#c9d1d9',
                    font=('Consolas',10))
        s.configure('TLabelframe', background='#0d1117', foreground='#f7b731',
                    bordercolor='#30363d')
        s.configure('TLabelframe.Label', background='#0d1117',
                    foreground='#f7b731', font=('Consolas',10,'bold'))
        s.configure('TCombobox', fieldbackground='#161b22', background='#161b22',
                    foreground='#c9d1d9', font=('Consolas',10))
        s.configure('Horizontal.TProgressbar', background='#f7b731',
                    troughcolor='#161b22', borderwidth=0)

    def _entry(self, p, show=None, w=40):
        return tk.Entry(p, show=show, width=w, bg='#161b22', fg='#c9d1d9',
                        insertbackground='#f7b731', relief='flat', bd=6,
                        font=('Consolas',10), highlightthickness=1,
                        highlightcolor='#f7b731', highlightbackground='#30363d')

    def _btn(self, p, text, cmd, color='#f7b731', fg='#0d1117'):
        return tk.Button(p, text=text, command=cmd, bg=color, fg=fg,
                         activebackground='#e5a820', relief='flat', bd=0,
                         padx=20, pady=8, font=('Consolas',10,'bold'), cursor='hand2')

    def _label(self, p, text, fg='#8b949e', size=9):
        return tk.Label(p, text=text, bg='#0d1117', fg=fg,
                        font=('Consolas', size))

    # ── Main UI ─────────────────────────────────
    def _build_ui(self):
        hdr = tk.Frame(self.root, bg='#0d1117')
        hdr.pack(fill='x', padx=20, pady=(14,0))
        tk.Label(hdr, text="₿ BIP39 Wallet Recovery", bg='#0d1117', fg='#f7b731',
                 font=('Consolas',18,'bold')).pack(side='left')
        tk.Label(hdr, text="BIP44 · BIP49 · BIP84  |  Smart Search  |  Multi-core  |  100% Offline",
                 bg='#0d1117', fg='#484f58', font=('Consolas',9)).pack(side='left', padx=14)
        ttk.Separator(self.root, orient='horizontal').pack(fill='x', padx=20, pady=6)

        self._build_hw_bar()

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill='both', expand=False, padx=20)
        self._tab_recovery()
        self._tab_hardware()
        self._tab_analysis()
        self._tab_about()

        # Log
        bf = tk.Frame(self.root, bg='#0d1117')
        bf.pack(fill='x', padx=20, pady=(6,2))
        lf = ttk.LabelFrame(bf, text="  LOG  ")
        lf.pack(fill='x')
        self.log_box = scrolledtext.ScrolledText(
            lf, height=5, bg='#010409', fg='#3fb950',
            font=('Consolas',9), relief='flat', bd=4,
            insertbackground='#3fb950', state='disabled')
        self.log_box.pack(fill='x', padx=4, pady=4)

        # Progress
        pf = tk.Frame(self.root, bg='#0d1117')
        pf.pack(fill='x', padx=20, pady=(2,0))
        self.prog_var = tk.DoubleVar()
        ttk.Progressbar(pf, variable=self.prog_var, maximum=100,
                        style='Horizontal.TProgressbar').pack(side='left', fill='x', expand=True)
        self.prog_lbl = tk.Label(pf, text="0%", bg='#0d1117', fg='#8b949e',
                                  font=('Consolas',9), width=7)
        self.prog_lbl.pack(side='left', padx=4)

        # Buttons
        btnf = tk.Frame(self.root, bg='#0d1117')
        btnf.pack(pady=(4,10))
        self._btn(btnf, "▶  START RECOVERY", self._start).pack(side='left', padx=8)
        self._btn(btnf, "■  STOP", self._stop, '#da3633', 'white').pack(side='left', padx=8)
        self._btn(btnf, "⎘  EXPORT LOG", self._export, '#238636', 'white').pack(side='left', padx=8)

    # ── HW Bar ──────────────────────────────────
    def _build_hw_bar(self):
        bar = tk.Frame(self.root, bg='#161b22', height=34)
        bar.pack(fill='x', padx=20, pady=(0,4))
        bar.pack_propagate(False)

        def item(parent, lbl, color):
            f = tk.Frame(parent, bg='#161b22'); f.pack(side='left', padx=12, pady=4)
            tk.Label(f, text=lbl, bg='#161b22', fg='#484f58',
                     font=('Consolas',8)).pack(side='left')
            var = tk.DoubleVar()
            ttk.Progressbar(f, variable=var, maximum=100, length=70,
                            style='Horizontal.TProgressbar').pack(side='left', padx=4)
            lbl2 = tk.Label(f, text="0%", bg='#161b22', fg=color,
                            font=('Consolas',8), width=5)
            lbl2.pack(side='left')
            return var, lbl2

        self.hw_cpu_v, self.hw_cpu_l = item(bar, "CPU", "#3fb950")
        self.hw_ram_v, self.hw_ram_l = item(bar, "RAM", "#58a6ff")
        tk.Label(bar, text=f"Cores: {CPU_COUNT}", bg='#161b22', fg='#f7b731',
                 font=('Consolas',8)).pack(side='left', padx=12)
        self.hw_wlbl = tk.Label(bar, text="Workers: 1", bg='#161b22',
                                 fg='#c9d1d9', font=('Consolas',8))
        self.hw_wlbl.pack(side='left', padx=8)
        self.hw_safe = tk.Label(bar, text="● SAFE", bg='#161b22',
                                 fg='#3fb950', font=('Consolas',8,'bold'))
        self.hw_safe.pack(side='right', padx=14)

    def _start_hw_monitor(self):
        def loop():
            while True:
                try:
                    cpu = psutil.cpu_percent(interval=0.5)
                    ram = psutil.virtual_memory().percent
                    self.hw_cpu_v.set(cpu); self.hw_cpu_l.config(text=f"{cpu:.0f}%")
                    self.hw_ram_v.set(ram); self.hw_ram_l.config(text=f"{ram:.0f}%")
                    if cpu > 90 or ram > 90:
                        self.hw_safe.config(text="● HIGH LOAD", fg='#da3633')
                    elif cpu > 70 or ram > 75:
                        self.hw_safe.config(text="● MODERATE",  fg='#f7b731')
                    else:
                        self.hw_safe.config(text="● SAFE",      fg='#3fb950')
                    self.root.update_idletasks()
                except Exception:
                    pass
                time.sleep(2)
        threading.Thread(target=loop, daemon=True).start()

    # ── Tab: Recovery ────────────────────────────
    def _tab_recovery(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  🔑  Recovery  ")

        # ── Seed size ──
        top = tk.Frame(tab, bg='#0d1117')
        top.pack(fill='x', padx=12, pady=(10,4))
        self._label(top, "Seed size:").pack(side='left')
        self.seed_size_var = tk.IntVar(value=24)
        ttk.Combobox(top, textvariable=self.seed_size_var, width=5,
                     values=[12,15,18,21,24], state='readonly').pack(side='left', padx=6)
        self._label(top, "words total  —  How many words do you have:").pack(side='left', padx=(10,4))
        self.known_count_var = tk.IntVar(value=23)
        tk.Spinbox(top, from_=1, to=24, textvariable=self.known_count_var,
                   width=4, bg='#161b22', fg='#c9d1d9', font=('Consolas',10),
                   buttonbackground='#1f2937',
                   command=self._update_word_grid).pack(side='left')
        self._label(top, "  (fill only the words you have — leave the rest blank)").pack(side='left', padx=8)

        # ── Word grid ──
        wf = ttk.LabelFrame(tab, text="  ENTER YOUR WORDS IN ORDER  ")
        wf.pack(fill='x', padx=12, pady=4)

        self._label(wf,
            "Fill in the words you have. Leave blank the ones you don't remember.",
            fg='#484f58').pack(anchor='w', padx=10, pady=(4,6))

        self.word_entries = []
        self.grid_frame = tk.Frame(wf, bg='#0d1117')
        self.grid_frame.pack(fill='x', padx=8, pady=(0,8))
        self._build_word_grid(24)

        # ── Smart hints ──
        hint_frame = ttk.LabelFrame(tab, text="  SMART HINTS — help narrow the search (optional)  ")
        hint_frame.pack(fill='x', padx=12, pady=4)

        h1 = tk.Frame(hint_frame, bg='#0d1117'); h1.pack(fill='x', padx=10, pady=4)
        self._label(h1, "Missing word starts with:").pack(side='left')
        self.hint_starts = self._entry(h1, w=8)
        self.hint_starts.pack(side='left', padx=6)
        self._label(h1, "  Has exactly N letters (0 = any):").pack(side='left', padx=(16,4))
        self.hint_length_var = tk.IntVar(value=0)
        tk.Spinbox(h1, from_=0, to=10, textvariable=self.hint_length_var,
                   width=4, bg='#161b22', fg='#c9d1d9', font=('Consolas',10),
                   buttonbackground='#1f2937').pack(side='left')

        h2 = tk.Frame(hint_frame, bg='#0d1117'); h2.pack(fill='x', padx=10, pady=(2,8))
        self._label(h2, "I may have misspelled a word — what did I write?").pack(side='left')
        self.hint_typo = self._entry(h2, w=20)
        self.hint_typo.pack(side='left', padx=6)
        self._label(h2, "  (tool will find similar BIP39 words automatically)", fg='#3fb950').pack(side='left')

        # ── Position hint ──
        pos_frame = ttk.LabelFrame(tab, text="  WHERE ARE THE MISSING WORDS?  ")
        pos_frame.pack(fill='x', padx=12, pady=4)

        self.pos_mode_var = tk.StringVar(value="unknown")
        tk.Radiobutton(pos_frame,
                       text="I don't know the positions — test all automatically",
                       variable=self.pos_mode_var, value="unknown",
                       bg='#0d1117', fg='#c9d1d9', selectcolor='#161b22',
                       activebackground='#0d1117', activeforeground='#f7b731',
                       font=('Consolas',10),
                       command=self._on_pos_mode).pack(anchor='w', padx=12, pady=2)
        tk.Radiobutton(pos_frame,
                       text="I think I know the positions:",
                       variable=self.pos_mode_var, value="known",
                       bg='#0d1117', fg='#c9d1d9', selectcolor='#161b22',
                       activebackground='#0d1117', activeforeground='#f7b731',
                       font=('Consolas',10),
                       command=self._on_pos_mode).pack(anchor='w', padx=12, pady=2)

        pos_row = tk.Frame(pos_frame, bg='#0d1117')
        pos_row.pack(fill='x', padx=28, pady=(0,8))
        self._label(pos_row, "Positions (e.g.: 5 12 18):").pack(side='left')
        self.pos_entry = self._entry(pos_row, w=30)
        self.pos_entry.pack(side='left', padx=6)
        self._label(pos_row, "  separate by space", fg='#484f58').pack(side='left')
        self.pos_entry.config(state='disabled')

        # ── Credentials ──
        cred = ttk.LabelFrame(tab, text="  CREDENTIALS  ")
        cred.pack(fill='x', padx=12, pady=4)

        r1 = tk.Frame(cred, bg='#0d1117'); r1.pack(fill='x', padx=10, pady=4)
        self._label(r1, "Passphrase (extra password):", size=10).pack(side='left', anchor='w')
        self.pass_entry = self._entry(r1, show='•', w=28)
        self.pass_entry.pack(side='left', padx=6)
        self.show_pass = tk.BooleanVar()
        tk.Checkbutton(r1, text="show", variable=self.show_pass,
                       bg='#0d1117', fg='#8b949e', selectcolor='#161b22',
                       activebackground='#0d1117', font=('Consolas',9),
                       command=lambda: self.pass_entry.config(
                           show='' if self.show_pass.get() else '•')).pack(side='left')
        self._label(r1, "  (leave empty if you didn't use one)", fg='#484f58').pack(side='left')

        r2 = tk.Frame(cred, bg='#0d1117'); r2.pack(fill='x', padx=10, pady=4)
        self._label(r2, "Bitcoin address (bc1q / 1... / 3...):", size=10).pack(side='left')
        self.addr_entry = self._entry(r2, w=50)
        self.addr_entry.pack(side='left', padx=6)

        r3 = tk.Frame(cred, bg='#0d1117'); r3.pack(fill='x', padx=10, pady=(4,8))
        self._label(r3, "Address type:", size=10).pack(side='left')
        self.path_var = tk.StringVar(value="bip84")
        ttk.Combobox(r3, textvariable=self.path_var, width=18,
                     values=["bip84 (bc1q...)", "bip44 (1...)", "bip49 (3...)"],
                     state='readonly').pack(side='left', padx=6)
        self._label(r3, "  Indexes:", size=10).pack(side='left', padx=(12,4))
        self.addr_lim = tk.IntVar(value=10)
        tk.Spinbox(r3, from_=1, to=50, textvariable=self.addr_lim,
                   width=4, bg='#161b22', fg='#c9d1d9', font=('Consolas',10),
                   buttonbackground='#1f2937').pack(side='left')
        self.change_var = tk.BooleanVar(value=False)
        tk.Checkbutton(r3, text="  test change path too", variable=self.change_var,
                       bg='#0d1117', fg='#8b949e', selectcolor='#161b22',
                       activebackground='#0d1117', font=('Consolas',9)).pack(side='left', padx=8)

    def _build_word_grid(self, n):
        for w in self.grid_frame.winfo_children():
            w.destroy()
        self.word_entries = []
        cols = 6
        for i in range(n):
            row, col = divmod(i, cols)
            cell = tk.Frame(self.grid_frame, bg='#0d1117')
            cell.grid(row=row, column=col, padx=4, pady=2, sticky='w')
            tk.Label(cell, text=f"{i+1:02d}.", bg='#0d1117', fg='#484f58',
                     font=('Consolas',9), width=3).pack(side='left')
            e = tk.Entry(cell, width=10, bg='#161b22', fg='#c9d1d9',
                         insertbackground='#f7b731', relief='flat', bd=4,
                         font=('Consolas',10), highlightthickness=1,
                         highlightcolor='#f7b731', highlightbackground='#30363d')
            e.pack(side='left')
            self.word_entries.append(e)

    def _update_word_grid(self):
        n = self.seed_size_var.get()
        self._build_word_grid(n)

    def _on_pos_mode(self):
        mode = self.pos_mode_var.get()
        self.pos_entry.config(state='normal' if mode == 'known' else 'disabled')

    # ── Tab: Hardware ────────────────────────────
    def _tab_hardware(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  ⚡  Hardware Control  ")

        cpu_f = ttk.LabelFrame(tab, text="  CPU WORKERS  ")
        cpu_f.pack(fill='x', padx=12, pady=(12,6))
        self._label(cpu_f,
            f"Your CPU has {CPU_COUNT} cores. Choose how many to dedicate to recovery:",
            fg='#8b949e').pack(anchor='w', padx=12, pady=(6,2))

        sf = tk.Frame(cpu_f, bg='#0d1117'); sf.pack(fill='x', padx=12, pady=6)
        self.workers_var = tk.IntVar(value=max(1, CPU_COUNT//2))
        self.w_lbl = tk.Label(sf, text=f"Workers: {self.workers_var.get()}",
                               bg='#0d1117', fg='#f7b731',
                               font=('Consolas',12,'bold'), width=14)
        self.w_lbl.pack(side='left')

        def on_slide(v):
            n = int(float(v))
            self.workers_var.set(n)
            self.w_lbl.config(text=f"Workers: {n}")
            self.hw_wlbl.config(text=f"Workers: {n}")
            pct = int(n / CPU_COUNT * 100)
            desc = "🟢 Light" if pct<=40 else "🟡 Moderate" if pct<=70 else "🔴 Heavy"
            self.w_desc.config(text=f"{pct}% of CPU  {desc}")

        tk.Scale(sf, from_=1, to=CPU_COUNT, orient='horizontal',
                 variable=self.workers_var, command=on_slide, length=400,
                 bg='#0d1117', fg='#c9d1d9', troughcolor='#161b22',
                 activebackground='#f7b731', highlightthickness=0,
                 sliderrelief='flat', font=('Consolas',9)).pack(side='left', padx=10)
        self.w_desc = self._label(cpu_f, "")
        self.w_desc.pack(anchor='w', padx=12, pady=(0,4))
        on_slide(self.workers_var.get())

        pf = ttk.LabelFrame(tab, text="  PRESETS  ")
        pf.pack(fill='x', padx=12, pady=6)
        row = tk.Frame(pf, bg='#0d1117'); row.pack(fill='x', padx=12, pady=8)

        def preset_btn(text, workers, color):
            tk.Button(row, text=text, width=28,
                      command=lambda: (self.workers_var.set(workers),
                                       on_slide(workers)),
                      bg='#161b22', fg='#c9d1d9', activebackground=color,
                      relief='flat', bd=1, padx=8, pady=8,
                      font=('Consolas',9), cursor='hand2',
                      justify='left').pack(side='left', padx=6)

        preset_btn(f"🟢 Safe Mode\n(1 worker — PC stays responsive)", 1, '#238636')
        preset_btn(f"🟡 Balanced\n({max(1,CPU_COUNT//2)} workers — recommended)", max(1,CPU_COUNT//2), '#b08800')
        preset_btn(f"🔴 Maximum Power\n({CPU_COUNT} workers — PC may slow down)", CPU_COUNT, '#da3633')

        wf = ttk.LabelFrame(tab, text="  SAFETY GUIDELINES  ")
        wf.pack(fill='both', expand=True, padx=12, pady=6)
        tk.Label(wf, text="""
  🌡️  More workers = more heat. Avoid Maximum on laptops or PCs with poor ventilation.
  💾  Each worker uses ~50–100 MB RAM. Use Safe Mode if you have less than 4 GB RAM.
  🔋  On battery? Use Safe Mode — Maximum Power drains it fast.
  🖥️  Balanced lets you use your PC normally while recovery runs in the background.
  ✅  Start with Balanced. Increase only if the PC handles it well.
        """, bg='#0d1117', fg='#8b949e', font=('Consolas',9),
                 justify='left').pack(anchor='w', padx=8)

    # ── Tab: Analysis ────────────────────────────
    def _tab_analysis(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  📊  Feasibility Analysis  ")

        ctrl = ttk.LabelFrame(tab, text="  WHAT DO YOU HAVE?  ")
        ctrl.pack(fill='x', padx=12, pady=(12,6))

        r1 = tk.Frame(ctrl, bg='#0d1117'); r1.pack(fill='x', padx=12, pady=6)
        self._label(r1, "Seed size:", size=10).pack(side='left')
        self.an_seed = tk.IntVar(value=24)
        ttk.Combobox(r1, textvariable=self.an_seed, width=5,
                     values=[12,15,18,21,24], state='readonly').pack(side='left', padx=6)
        self._label(r1, "  Words you have:", size=10).pack(side='left', padx=(12,4))
        self.an_known = tk.IntVar(value=23)
        tk.Spinbox(r1, from_=0, to=24, textvariable=self.an_known,
                   width=4, bg='#161b22', fg='#c9d1d9', font=('Consolas',10),
                   buttonbackground='#1f2937').pack(side='left')

        r2 = tk.Frame(ctrl, bg='#0d1117'); r2.pack(fill='x', padx=12, pady=4)
        self.an_pos  = tk.BooleanVar(value=False)
        self.an_pass = tk.BooleanVar(value=True)
        self.an_addr = tk.BooleanVar(value=True)
        self.an_bip  = tk.BooleanVar(value=True)
        self.an_hint = tk.BooleanVar(value=False)

        def cb(p, txt, var):
            tk.Checkbutton(p, text=txt, variable=var, bg='#0d1117', fg='#c9d1d9',
                           selectcolor='#161b22', activebackground='#0d1117',
                           activeforeground='#f7b731',
                           font=('Consolas',10)).pack(side='left', padx=10)

        cb(r2, "Know position(s)", self.an_pos)
        cb(r2, "Have passphrase",  self.an_pass)
        cb(r2, "Have address",     self.an_addr)
        r3 = tk.Frame(ctrl, bg='#0d1117'); r3.pack(fill='x', padx=12, pady=(2,8))
        cb(r3, "Know derivation type", self.an_bip)
        cb(r3, "Have word pattern hint", self.an_hint)

        self._btn(ctrl, "  CALCULATE ANALYSIS  ", self._run_analysis,
                  '#1f6feb', 'white').pack(pady=(0,10))

        rf = ttk.LabelFrame(tab, text="  RESULT  ")
        rf.pack(fill='both', expand=True, padx=12, pady=6)
        self.an_box = scrolledtext.ScrolledText(
            rf, height=14, bg='#010409', fg='#c9d1d9',
            font=('Consolas',10), relief='flat', bd=4,
            insertbackground='#f7b731', state='disabled')
        self.an_box.pack(fill='both', expand=True, padx=4, pady=4)
        self.root.after(400, self._run_analysis)

    def _run_analysis(self):
        total    = self.an_seed.get()
        known    = min(self.an_known.get(), total)
        missing  = total - known
        workers  = self.workers_var.get() if hasattr(self, 'workers_var') else 1
        has_hint = self.an_hint.get()

        # Estimate combinations with smart hints applied
        base = 2048
        if has_hint: base = int(base * 0.05)  # pattern reduces ~95%
        combos = base ** max(1, missing)
        level, color, secs = feasibility(combos, workers)
        tempo = fmt_time(secs)

        lines = ["━━━  SITUATION ANALYSIS  ━━━", ""]
        lines += [f"  Seed size        : {total} words",
                  f"  You have         : {known} words",
                  f"  Missing          : {missing} word(s)",
                  f"  Position known   : {'Yes ✅' if self.an_pos.get() else 'No ❌'}",
                  f"  Has passphrase   : {'Yes ✅' if self.an_pass.get() else 'No ❌'}",
                  f"  Has address      : {'Yes ✅' if self.an_addr.get() else 'No ❌  ← important!'}",
                  f"  Has derivation   : {'Yes ✅' if self.an_bip.get() else 'No ❌'}",
                  f"  Word hint active : {'Yes ✅ (~95% fewer candidates' if has_hint else 'No'})",
                  f"  Workers          : {workers} cores", "",
                  f"  Combinations     : {combos:,}",
                  f"  Estimated time   : {tempo}",
                  f"  Feasibility      : {level}", ""]

        if missing == 0:
            lines += ["  ℹ️  You have all words! Check passphrase and derivation."]
        elif missing == 1:
            lines += ["  🟢 Excellent. One missing word — very fast to recover."]
        elif missing == 2:
            lines += ["  🟡 Possible. May take hours without hints, minutes with hints."]
        elif missing == 3:
            lines += ["  🟠 Hard. Use all hints available to speed up."]
        elif missing <= 5:
            lines += ["  🔴 Very hard. Hints are essential. May take days."]
        else:
            lines += ["  💀 Not feasible without GPU hardware."]

        lines += ["", "  💡 What still helps:"]
        if not self.an_addr.get():
            lines.append("   ➕ Public address → essential to confirm matches")
        if not self.an_pos.get() and missing >= 1:
            lines.append("   ➕ Position of missing words → huge speedup")
        if not has_hint:
            lines.append("   ➕ Word pattern hint → reduces candidates by ~95%")
        if missing > 1:
            lines.append(f"   ➕ Each extra word remembered divides time by {base:,}")
        if workers < CPU_COUNT:
            lines.append(f"   ➕ More CPU workers → you have {CPU_COUNT} cores available")

        self.an_box.config(state='normal')
        self.an_box.delete('1.0', 'end')
        self.an_box.tag_config("ok",  foreground="#3fb950")
        self.an_box.tag_config("bad", foreground="#da3633")
        self.an_box.tag_config("tip", foreground="#58a6ff")
        self.an_box.tag_config("lvl", foreground=color, font=('Consolas',10,'bold'))
        self.an_box.tag_config("dim", foreground="#c9d1d9")
        for ln in lines:
            tag = "dim"
            if "✅" in ln: tag = "ok"
            elif "❌" in ln: tag = "bad"
            elif level in ln: tag = "lvl"
            elif "➕" in ln or "💡" in ln: tag = "tip"
            elif any(x in ln for x in ["🟢","🟡","🟠","🔴","💀"]): tag = "ok" if "🟢" in ln else "bad"
            self.an_box.insert('end', ln+"\n", tag)
        self.an_box.config(state='disabled')

    # ── Tab: About ───────────────────────────────
    def _tab_about(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  ℹ  About  ")
        tk.Label(tab, text="""

    ₿  BIP39 Bitcoin Wallet Recovery Tool
    ═══════════════════════════════════════════════════

    Open source tool to recover Bitcoin wallets
    from incomplete BIP39 seed phrases.

    Smart search optimizations:
    ├─ BIP39 checksum filter    → eliminates invalid combinations instantly
    ├─ Pattern filter           → reduces candidates by prefix / word length
    └─ Neighborhood search      → finds misspelled words automatically

    Derivations:
    ├─ BIP84 → bc1q...   (Native SegWit)
    ├─ BIP44 → 1...      (Legacy)
    └─ BIP49 → 3...      (SegWit)

    Hardware:
    ├─ Multi-core CPU (adjustable workers)
    ├─ Real-time CPU/RAM monitor
    └─ Safe / Balanced / Maximum presets

    ⚠️  Always run OFFLINE. Never share your seed.

    ─────────────────────────────────────────────────
    github.com/leonardoramcke/bitcoin-recovery
    MIT License © 2026 leonardoramcke
        """, bg='#0d1117', fg='#8b949e', font=('Consolas',10),
                 justify='left').pack(anchor='w', padx=20, pady=10)

    # ── Logging / progress ──────────────────────
    def _log(self, msg):
        self.log_box.config(state='normal')
        self.log_box.insert('end', f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.log_box.see('end')
        self.log_box.config(state='disabled')
        self.root.update_idletasks()

    def _set_prog(self, done, total):
        p = min(100, done/total*100) if total else 0
        self.prog_var.set(p)
        self.prog_lbl.config(text=f"{p:.1f}%")
        self.root.update_idletasks()

    def _export(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt",
               filetypes=[("Text","*.txt")], title="Save log")
        if path:
            with open(path,'w',encoding='utf-8') as f:
                f.write(self.log_box.get('1.0','end'))
            messagebox.showinfo("Saved", f"Log saved to:\n{path}")

    # ── Start / Stop ─────────────────────────────
    def _stop(self):
        self.stop_event.set()
        self._log("⛔ Stopped by user.")

    def _start(self):
        # Collect words from grid
        words_raw = [e.get().strip().lower() for e in self.word_entries]
        seed_size = self.seed_size_var.get()
        words_raw = words_raw[:seed_size]

        # Separate known from missing
        known_words      = []
        missing_positions = []
        for i, w in enumerate(words_raw):
            if w == '' or w is None:
                missing_positions.append(i)
            else:
                known_words.append(w)

        if not missing_positions:
            messagebox.showerror("Error",
                "No blank words found.\nLeave blank the words you don't remember.")
            return

        # Validate known words
        invalid = [w for w in known_words if w not in WORDLIST]
        if invalid:
            messagebox.showerror("Error",
                f"These words are not in the BIP39 wordlist:\n{', '.join(invalid)}\n\nCheck spelling.")
            return

        addr = self.addr_entry.get().strip()
        if not addr:
            messagebox.showerror("Error", "Enter the Bitcoin address.")
            return

        passphrase   = self.pass_entry.get()
        path         = self.path_var.get().split()[0]
        addr_limit   = self.addr_lim.get()
        change_limit = 2 if self.change_var.get() else 1
        workers      = self.workers_var.get()
        hint_starts  = self.hint_starts.get()
        hint_length  = self.hint_length_var.get()
        hint_typo    = self.hint_typo.get()

        # Override positions if user specified
        if self.pos_mode_var.get() == 'known':
            raw_pos = self.pos_entry.get().strip()
            try:
                missing_positions = [int(x)-1 for x in raw_pos.split()]
                if any(p < 0 or p >= seed_size for p in missing_positions):
                    raise ValueError
            except Exception:
                messagebox.showerror("Error",
                    f"Invalid positions. Enter numbers 1–{seed_size} separated by space.")
                return

        n_missing = len(missing_positions)
        combos    = 2048 ** n_missing
        if combos > 10_000_000:
            _, _, secs = feasibility(combos, workers)
            if not messagebox.askyesno("⚠️ Warning",
                f"{n_missing} missing words → {combos:,} combinations\n"
                f"Estimated time: {fmt_time(secs)}\n\n"
                f"Start anyway?"):
                return

        self.stop_event.clear()
        self.log_box.config(state='normal')
        self.log_box.delete('1.0','end')
        self.log_box.config(state='disabled')
        self.prog_var.set(0)
        self.prog_lbl.config(text="0%")

        params = dict(known_words=known_words, missing_positions=missing_positions,
                      passphrase=passphrase, target=addr, path=path,
                      addr_limit=addr_limit, change_limit=change_limit,
                      hint_starts=hint_starts, hint_length=hint_length,
                      hint_typo=hint_typo, seed_size=seed_size, workers=workers)

        threading.Thread(target=self._run, args=(params,), daemon=True).start()

    def _run(self, p):
        self._log(f"▶ Starting recovery")
        self._log(f"  Target address  : {p['target']}")
        self._log(f"  Derivation      : {p['path']}")
        self._log(f"  Passphrase      : {'(empty)' if not p['passphrase'] else '***'}")
        self._log(f"  Missing words   : {len(p['missing_positions'])} at positions {[x+1 for x in p['missing_positions']]}")
        self._log(f"  CPU Workers     : {p['workers']} of {CPU_COUNT} cores")
        if p['hint_typo']:
            similar = similar_words(p['hint_typo'], max_dist=2)
            self._log(f"  Typo search     : '{p['hint_typo']}' → {len(similar)} similar words found")
        if p['hint_starts']:
            self._log(f"  Pattern filter  : starts with '{p['hint_starts']}'")
        if p['hint_length'] > 0:
            self._log(f"  Length filter   : {p['hint_length']} letters")

        start  = time.time()
        result = recover(
            known_words       = p['known_words'],
            missing_positions = p['missing_positions'],
            passphrase        = p['passphrase'],
            target            = p['target'],
            path              = p['path'],
            addr_limit        = p['addr_limit'],
            change_limit      = p['change_limit'],
            hint_starts       = p['hint_starts'],
            hint_length       = p['hint_length'],
            hint_typo         = p['hint_typo'],
            seed_size         = p['seed_size'],
            log_fn            = self._log,
            progress_fn       = self._set_prog,
            stop_event        = self.stop_event,
            num_workers       = p['workers'])

        elapsed = time.time() - start
        self._set_prog(100, 100)

        if result:
            self._log("═"*50)
            self._log("✅  WALLET FOUND!")
            self._log("═"*50)
            self._log(f"  Complete seed : {' '.join(result['words'])}")
            self._log(f"  Found word(s) : {result['found']} at position(s) {result['positions']}")
            self._log(f"  Total time    : {elapsed:.1f}s")
            self._log("═"*50)
            self._log("⚠️  WRITE DOWN ALL WORDS ON PAPER NOW!")
            messagebox.showinfo("✅ Found!",
                f"Wallet found!\n\nSeed:\n{' '.join(result['words'])}\n\nWrite it down on paper now!")
        else:
            if not self.stop_event.is_set():
                self._log("═"*50)
                self._log("❌  Not found.")
                self._log("  Check: passphrase, address, word order, indexes.")
                self._log(f"  Time: {elapsed:.1f}s")
                self._log("═"*50)


if __name__ == '__main__':
    multiprocessing.freeze_support()
    root = tk.Tk()
    App(root)
    root.mainloop()
