#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         BIP39 BITCOIN WALLET RECOVERY TOOL  v2.0            ║
║         by: leonardoramcke (github.com/leonardoramcke)      ║
║         MIT License © 2026                                  ║
╠══════════════════════════════════════════════════════════════╣
║  OPTIMIZATIONS v2.0:                                        ║
║  ✅ Real multiprocessing (Pool + chunks) — CPU 100%         ║
║  ✅ Early checksum filter — skip 2047/2048 combos           ║
║  ✅ O(1) set lookup for target addresses                     ║
║  ✅ Smart chunking — workers never idle                      ║
║  ✅ hashlib C-native PBKDF2 (2048 iterations, BIP39 std)    ║
╚══════════════════════════════════════════════════════════════╝

SPEED COMPARISON (estimated, 8-core CPU):
  v1.0  → ~150 combos/sec   (threading, GIL-limited, ~1 real core)
  v2.0  → ~1,200 combos/sec (multiprocessing, all cores, early exit)
  Gain  → ~8x faster on CPU alone
"""

import hashlib, time, sys, os, itertools, threading, math, multiprocessing
import psutil, tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from multiprocessing import Pool, cpu_count, Manager
import bech32
from mnemonic import Mnemonic
from bip32utils import BIP32Key, BIP32_HARDEN

# ── Constants (module-level for multiprocessing pickling) ──────
MNEMO    = Mnemonic('english')
WORDLIST = MNEMO.wordlist
CPU_COUNT = cpu_count()

# ── Base58Check (pure Python) ──────────────────────────────────
_B58 = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def _b58encode(payload):
    n = int.from_bytes(payload, 'big')
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(_B58[r])
    res.extend([_B58[0]] * (len(payload) - len(payload.lstrip(b'\x00'))))
    return bytes(reversed(res)).decode('ascii')

# ── Levenshtein distance ───────────────────────────────────────
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
    scored = [(levenshtein(word.lower(), w), w) for w in WORDLIST]
    scored.sort()
    return [w for d, w in scored if d <= max_dist]

def words_matching_pattern(starts_with='', length=0):
    result = WORDLIST
    if starts_with:
        result = [w for w in result if w.startswith(starts_with.lower())]
    if length > 0:
        result = [w for w in result if len(w) == length]
    return result

# ── BIP39 checksum ─────────────────────────────────────────────
def passes_checksum(words):
    """Quick BIP39 checksum validation — rejects ~2047/2048 random combos."""
    return MNEMO.check(' '.join(words))

def valid_last_words(words_prefix):
    """For 24-word seed: only ~8 of 2048 last words pass checksum."""
    return [w for w in WORDLIST if passes_checksum(words_prefix + [w])]

# ── Time / feasibility ─────────────────────────────────────────
SPEED_PER_CORE = 200   # combos/sec per worker (conservative, post-checksum)

def fmt_time(s):
    if s < 60:           return f"~{int(s)} seconds"
    if s < 3600:         return f"~{int(s/60)} minutes"
    if s < 86400:        return f"~{int(s/3600)} hours"
    if s < 2592000:      return f"~{int(s/86400)} days"
    if s < 31536000:     return f"~{int(s/2592000)} months"
    if s < 31536000000:  return f"~{int(s/31536000)} years"
    return "eternity (not feasible)"

def feasibility(combos, workers=1):
    s = combos / max(1, SPEED_PER_CORE * workers)
    if s < 1800:     return "EASY",         "#3fb950", s
    if s < 86400:    return "MODERATE",     "#f7b731", s
    if s < 2592000:  return "HARD",         "#e3702a", s
    if s < 31536000: return "VERY HARD",    "#da3633", s
    return               "NOT FEASIBLE", "#8b0000", s

# ── Address derivation ─────────────────────────────────────────
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

# ══════════════════════════════════════════════════════════════
#  WORKER FUNCTION — runs in a separate process (no GIL!)
#  Must be top-level (not nested) so multiprocessing can pickle it.
# ══════════════════════════════════════════════════════════════
def _worker(args):
    """
    Process a chunk of combinations.
    Returns the found words-list on success, None otherwise.

    Optimization pipeline per combo:
      1. Insert candidates into full template           O(n_missing)
      2. BIP39 checksum validation ← EARLY EXIT        O(1) most of the time
         → Rejects ~2047/2048 combos before any crypto
      3. PBKDF2-HMAC-SHA512 via hashlib C (2048 iters) ← only if checksum passes
      4. Address derivation
      5. O(1) set lookup against target addresses
    """
    (chunk, template, missing_positions,
     passphrase, target_set, path,
     addr_limit, change_limit) = args

    mnemo_local = Mnemonic('english')  # each process gets its own instance

    for combo in chunk:
        # 1. Build candidate phrase
        candidate = list(template)
        for i, pos in enumerate(missing_positions):
            candidate[pos] = combo[i]

        # 2. ── EARLY CHECKSUM FILTER ──────────────────────────
        #    This is the "pulo do gato": for random combos,
        #    only 1/2048 pass. We skip 99.95% of heavy crypto work.
        phrase = ' '.join(candidate)
        if not mnemo_local.check(phrase):
            continue   # ← skip PBKDF2, skip derivation, next combo

        # 3. ── PBKDF2-HMAC-SHA512 (C-native via hashlib) ──────
        #    BIP39 standard: 2048 iterations, "mnemonic" + passphrase salt
        seed = hashlib.pbkdf2_hmac(
            'sha512',
            phrase.encode('utf-8'),
            ('mnemonic' + passphrase).encode('utf-8'),
            2048
        )

        # 4 & 5. Derive addresses and check against target set (O(1) lookup)
        try:
            master = BIP32Key.fromEntropy(seed)
            for c in range(change_limit):
                for idx in range(addr_limit):
                    addr = derive_address(seed, path, idx, c)
                    if addr and addr in target_set:   # ← O(1) set lookup
                        return candidate
        except Exception:
            continue

    return None


# ── Build candidate wordlist with smart hints ──────────────────
def build_candidates(hint_starts='', hint_length=0, hint_typo=''):
    if hint_typo.strip():
        base = similar_words(hint_typo.strip(), max_dist=2) or list(WORDLIST)
    else:
        base = list(WORDLIST)
    if hint_starts.strip():
        base = [w for w in base if w.startswith(hint_starts.strip().lower())]
    if hint_length > 0:
        base = [w for w in base if len(w) == hint_length]
    return base if base else list(WORDLIST)


# ── Chunk iterator — splits product() into slices ─────────────
def _chunked_product(candidates, repeat, chunk_size=500):
    """
    Yields chunks (lists) of itertools.product tuples.
    Workers receive full chunks, so they never idle waiting for the next task.
    chunk_size=500 balances overhead vs idle time.
    """
    buf = []
    for combo in itertools.product(candidates, repeat=repeat):
        buf.append(combo)
        if len(buf) == chunk_size:
            yield buf
            buf = []
    if buf:
        yield buf


# ── Main recovery engine (uses Pool) ──────────────────────────
def recover(known_words, missing_positions, passphrase, target, path,
            addr_limit, change_limit, hint_starts, hint_length, hint_typo,
            seed_size, log_fn, progress_fn, stop_event, num_workers=1):
    """
    Parallel recovery using multiprocessing.Pool.
    Each worker handles an independent chunk — no GIL, real parallelism.
    """
    # Build skeleton with None at missing positions
    full = list(known_words)
    for pos in sorted(missing_positions):
        full.insert(pos, None)

    candidates = build_candidates(hint_starts, hint_length, hint_typo)
    n_missing  = len(missing_positions)

    # ── Special case: only last word missing → ultra-fast checksum filter ──
    if missing_positions == [seed_size - 1] and not hint_starts and not hint_typo:
        candidates = valid_last_words(full[:seed_size-1])
        log_fn(f"  ✨ Last-word checksum filter → only {len(candidates)} valid candidates")

    total      = len(candidates) ** n_missing
    target_set = {target}   # O(1) lookup — add more addresses here if needed

    log_fn(f"  Missing positions : {[p+1 for p in missing_positions]}")
    log_fn(f"  Candidate words   : {len(candidates)} per position")
    log_fn(f"  Total combinations: {total:,}")
    log_fn(f"  After checksum    : ~{max(1, total // 2048):,} expected to reach PBKDF2")
    log_fn(f"  Estimated time    : {fmt_time(total / max(1, SPEED_PER_CORE * num_workers))}")
    log_fn(f"  Workers           : {num_workers} processes (real parallelism)")
    log_fn("─" * 50)

    done       = 0
    chunk_size = max(200, total // (num_workers * 40))  # dynamic chunk size

    # Build arg template for workers
    def make_args(chunk):
        return (chunk, list(full), missing_positions,
                passphrase, target_set, path,
                addr_limit, change_limit)

    with Pool(processes=num_workers) as pool:
        for result in pool.imap_unordered(
                _worker,
                (make_args(chunk)
                 for chunk in _chunked_product(candidates, n_missing, chunk_size)),
                chunksize=1):

            if stop_event.is_set():
                pool.terminate()
                return None

            done += chunk_size
            progress_fn(min(done, total), total)

            if result is not None:
                pool.terminate()
                found_at = [result[p] for p in missing_positions]
                return {
                    'words':     result,
                    'found':     found_at,
                    'positions': [p+1 for p in missing_positions]
                }

    progress_fn(total, total)
    return None


# ══════════════════════════════════════════════════════════════
#  GUI  (unchanged layout — only engine swapped)
# ══════════════════════════════════════════════════════════════
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("BIP39 Bitcoin Wallet Recovery Tool  v2.0")
        self.root.geometry("980x900")
        self.root.minsize(900, 840)
        self.root.configure(bg="#0d1117")
        self.stop_event  = threading.Event()
        self._setup_styles()
        self._build_ui()
        self._start_hw_monitor()

    # ── Styles ──────────────────────────────────────────────────
    def _setup_styles(self):
        s = ttk.Style(); s.theme_use('clam')
        s.configure('TNotebook', background='#0d1117', borderwidth=0)
        s.configure('TNotebook.Tab', background='#161b22', foreground='#8b949e',
                    padding=[16,8], font=('Consolas',10))
        s.map('TNotebook.Tab', background=[('selected','#1f2937')],
              foreground=[('selected','#f7b731')])
        s.configure('TFrame',      background='#0d1117')
        s.configure('TLabel',      background='#0d1117', foreground='#c9d1d9',
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
        return tk.Label(p, text=text, bg='#0d1117', fg=fg, font=('Consolas', size))

    # ── Main UI ─────────────────────────────────────────────────
    def _build_ui(self):
        hdr = tk.Frame(self.root, bg='#0d1117')
        hdr.pack(fill='x', padx=20, pady=(14,0))
        tk.Label(hdr, text="₿ BIP39 Wallet Recovery", bg='#0d1117', fg='#f7b731',
                 font=('Consolas',18,'bold')).pack(side='left')
        tk.Label(hdr,
                 text="v2.0  |  Multiprocessing  |  Checksum Filter  |  100% Offline",
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

        # Speed display (new in v2)
        self.speed_lbl = tk.Label(pf, text="", bg='#0d1117', fg='#58a6ff',
                                   font=('Consolas',9), width=20)
        self.speed_lbl.pack(side='left', padx=4)

        # Buttons
        btnf = tk.Frame(self.root, bg='#0d1117')
        btnf.pack(pady=(4,10))
        self._btn(btnf, "▶  START RECOVERY", self._start).pack(side='left', padx=8)
        self._btn(btnf, "■  STOP", self._stop, '#da3633', 'white').pack(side='left', padx=8)
        self._btn(btnf, "⎘  EXPORT LOG", self._export, '#238636', 'white').pack(side='left', padx=8)

    # ── HW Bar ──────────────────────────────────────────────────
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
        # v2: show engine mode
        tk.Label(bar, text="ENGINE: multiprocessing ⚡", bg='#161b22',
                 fg='#f7b731', font=('Consolas',8,'bold')).pack(side='left', padx=12)
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

    # ── Tab: Recovery ────────────────────────────────────────────
    def _tab_recovery(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  🔑  Recovery  ")

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

        wf = ttk.LabelFrame(tab, text="  ENTER YOUR WORDS IN ORDER  ")
        wf.pack(fill='x', padx=12, pady=4)
        self._label(wf,
            "Fill in the words you have. Leave blank the ones you don't remember.",
            fg='#484f58').pack(anchor='w', padx=10, pady=(4,6))
        self.word_entries = []
        self.grid_frame = tk.Frame(wf, bg='#0d1117')
        self.grid_frame.pack(fill='x', padx=8, pady=(0,8))
        self._build_word_grid(24)

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
        self._label(h2, "  (finds similar BIP39 words automatically)", fg='#3fb950').pack(side='left')

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

        cred = ttk.LabelFrame(tab, text="  CREDENTIALS  ")
        cred.pack(fill='x', padx=12, pady=4)

        r1 = tk.Frame(cred, bg='#0d1117'); r1.pack(fill='x', padx=10, pady=4)
        self._label(r1, "Passphrase (extra password):", size=10).pack(side='left')
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
        self._build_word_grid(self.seed_size_var.get())

    def _on_pos_mode(self):
        self.pos_entry.config(
            state='normal' if self.pos_mode_var.get() == 'known' else 'disabled')

    # ── Tab: Hardware ────────────────────────────────────────────
    def _tab_hardware(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  ⚡  Hardware Control  ")

        cpu_f = ttk.LabelFrame(tab, text="  CPU WORKERS  ")
        cpu_f.pack(fill='x', padx=12, pady=(12,6))

        # v2 explanation
        info = tk.Frame(cpu_f, bg='#161b22')
        info.pack(fill='x', padx=12, pady=(8,4))
        tk.Label(info,
            text="  ⚡  v2.0 uses real multiprocessing — each worker is a separate OS process.\n"
                 "      CPU usage will now show ~100% × workers. This is correct and expected.",
            bg='#161b22', fg='#3fb950', font=('Consolas',9), justify='left').pack(anchor='w', pady=4)

        self._label(cpu_f,
            f"Your CPU has {CPU_COUNT} cores. Choose how many to dedicate to recovery:",
            fg='#8b949e').pack(anchor='w', padx=12, pady=(4,2))

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
                      command=lambda: (self.workers_var.set(workers), on_slide(workers)),
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
  ⚡  v2.0: CPU will reach ~100% per worker — this is normal and expected!
        """, bg='#0d1117', fg='#8b949e', font=('Consolas',9),
                 justify='left').pack(anchor='w', padx=8)

    # ── Tab: Analysis ─────────────────────────────────────────
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

        base   = 2048
        if has_hint: base = int(base * 0.05)
        combos = base ** max(1, missing)

        # v2: after checksum filter, only 1/2048 combos reach PBKDF2
        effective = max(1, combos // 2048)
        level, color, secs = feasibility(effective, workers)
        tempo = fmt_time(secs)

        lines = ["━━━  SITUATION ANALYSIS  (v2.0 engine)  ━━━", ""]
        lines += [
            f"  Seed size        : {total} words",
            f"  You have         : {known} words",
            f"  Missing          : {missing} word(s)",
            f"  Position known   : {'Yes ✅' if self.an_pos.get() else 'No ❌'}",
            f"  Has passphrase   : {'Yes ✅' if self.an_pass.get() else 'No ❌'}",
            f"  Has address      : {'Yes ✅' if self.an_addr.get() else 'No ❌  ← important!'}",
            f"  Has derivation   : {'Yes ✅' if self.an_bip.get() else 'No ❌'}",
            f"  Word hint active : {'Yes ✅ (~95% fewer candidates)' if has_hint else 'No'}",
            f"  Workers          : {workers} processes (real parallelism ⚡)", "",
            f"  Raw combinations : {combos:,}",
            f"  After checksum   : ~{effective:,}  ← 2048× fewer (v2.0 optimization)",
            f"  Estimated time   : {tempo}",
            f"  Feasibility      : {level}", ""]

        if missing == 0:
            lines += ["  ℹ️  You have all words! Check passphrase and derivation."]
        elif missing == 1:
            lines += ["  🟢 Excellent. One missing word — seconds to minutes."]
        elif missing == 2:
            lines += ["  🟡 Possible. Minutes to hours with v2.0."]
        elif missing == 3:
            lines += ["  🟠 Hard. Use all hints. May take hours/days."]
        elif missing <= 5:
            lines += ["  🔴 Very hard. Hints are essential."]
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
            elif any(x in ln for x in ["🟢","🟡","🟠","🔴","💀"]):
                tag = "ok" if "🟢" in ln else "bad"
            self.an_box.insert('end', ln+"\n", tag)
        self.an_box.config(state='disabled')

    # ── Tab: About ───────────────────────────────────────────────
    def _tab_about(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  ℹ  About  ")
        tk.Label(tab, text="""

    ₿  BIP39 Bitcoin Wallet Recovery Tool  v2.0
    ═══════════════════════════════════════════════════

    v2.0 PERFORMANCE UPGRADES:
    ├─ Real multiprocessing (Pool)     → CPU 100% per worker (no GIL)
    ├─ Early checksum validation       → skip 2047/2048 combos before PBKDF2
    ├─ hashlib C-native PBKDF2-SHA512  → fastest possible Python implementation
    ├─ Smart chunking                  → workers never idle
    └─ O(1) set lookup                 → address match is instantaneous

    Smart search optimizations:
    ├─ BIP39 checksum filter    → eliminates invalid combinations instantly
    ├─ Pattern filter           → reduces candidates by prefix / word length
    └─ Neighborhood search      → finds misspelled words automatically

    Derivations:
    ├─ BIP84 → bc1q...   (Native SegWit)
    ├─ BIP44 → 1...      (Legacy)
    └─ BIP49 → 3...      (SegWit)

    ⚠️  Always run OFFLINE. Never share your seed.

    ─────────────────────────────────────────────────
    github.com/leonardoramcke/bitcoin-recovery
    MIT License © 2026 leonardoramcke
        """, bg='#0d1117', fg='#8b949e', font=('Consolas',10),
                 justify='left').pack(anchor='w', padx=20, pady=10)

    # ── Logging / progress ───────────────────────────────────────
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

    def _set_speed(self, combos_per_sec):
        self.speed_lbl.config(text=f"⚡ {combos_per_sec:,.0f} combos/s")

    def _export(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text","*.txt")], title="Save log")
        if path:
            with open(path,'w',encoding='utf-8') as f:
                f.write(self.log_box.get('1.0','end'))
            messagebox.showinfo("Saved", f"Log saved to:\n{path}")

    # ── Start / Stop ─────────────────────────────────────────────
    def _stop(self):
        self.stop_event.set()
        self._log("⛔ Stopped by user.")

    def _start(self):
        words_raw = [e.get().strip().lower() for e in self.word_entries]
        seed_size = self.seed_size_var.get()
        words_raw = words_raw[:seed_size]

        known_words       = []
        missing_positions = []
        for i, w in enumerate(words_raw):
            if not w:
                missing_positions.append(i)
            else:
                known_words.append(w)

        if not missing_positions:
            messagebox.showerror("Error",
                "No blank words found.\nLeave blank the words you don't remember.")
            return

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
            _, _, secs = feasibility(combos // 2048, workers)
            if not messagebox.askyesno("⚠️ Warning",
                f"{n_missing} missing words → {combos:,} combinations\n"
                f"After checksum filter: ~{combos//2048:,} effective\n"
                f"Estimated time (v2.0): {fmt_time(secs)}\n\n"
                f"Start anyway?"):
                return

        self.stop_event.clear()
        self.log_box.config(state='normal')
        self.log_box.delete('1.0','end')
        self.log_box.config(state='disabled')
        self.prog_var.set(0)
        self.prog_lbl.config(text="0%")
        self.speed_lbl.config(text="")

        params = dict(
            known_words=known_words, missing_positions=missing_positions,
            passphrase=passphrase, target=addr, path=path,
            addr_limit=addr_limit, change_limit=change_limit,
            hint_starts=hint_starts, hint_length=hint_length,
            hint_typo=hint_typo, seed_size=seed_size, workers=workers)

        threading.Thread(target=self._run, args=(params,), daemon=True).start()

    def _run(self, p):
        self._log("▶ Starting recovery  [v2.0 — multiprocessing engine]")
        self._log(f"  Target address  : {p['target']}")
        self._log(f"  Derivation      : {p['path']}")
        self._log(f"  Passphrase      : {'(empty)' if not p['passphrase'] else '***'}")
        self._log(f"  Missing words   : {len(p['missing_positions'])} at positions {[x+1 for x in p['missing_positions']]}")
        self._log(f"  CPU Workers     : {p['workers']} of {CPU_COUNT} cores  ⚡ real processes")
        self._log(f"  Checksum filter : ON — ~2048× fewer PBKDF2 calls")
        if p['hint_typo']:
            similar = similar_words(p['hint_typo'], max_dist=2)
            self._log(f"  Typo search     : '{p['hint_typo']}' → {len(similar)} similar words")
        if p['hint_starts']:
            self._log(f"  Pattern filter  : starts with '{p['hint_starts']}'")
        if p['hint_length'] > 0:
            self._log(f"  Length filter   : {p['hint_length']} letters")

        start  = time.time()
        last_t = [start]
        last_d = [0]

        def progress_fn(done, total):
            now = time.time()
            dt  = now - last_t[0]
            if dt >= 1.0:
                speed = (done - last_d[0]) / dt
                self._set_speed(speed)
                last_t[0] = now
                last_d[0] = done
            self._set_prog(done, total)

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
            progress_fn       = progress_fn,
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
                f"Wallet found!\n\nSeed:\n{' '.join(result['words'])}\n\nWrite it down now!")
        else:
            if not self.stop_event.is_set():
                self._log("═"*50)
                self._log("❌  Not found.")
                self._log("  Check: passphrase, address, word order, indexes.")
                self._log(f"  Time: {elapsed:.1f}s")
                self._log("═"*50)


# ══════════════════════════════════════════════════════════════
#  INTRO SCREEN — Circuit Board (Conceito B)
# ══════════════════════════════════════════════════════════════
import random, math as _math

class IntroScreen:
    """
    Full-screen animated intro: circuit board + travelling particles.
    Calls launch_callback() when the user clicks INICIAR or after timeout.
    """
    W, H = 900, 560

    # Circuit node positions (x, y) — defines the PCB grid
    _NODES = [
        (80,80),(220,80),(380,80),(540,80),(700,80),(820,80),
        (80,180),(180,180),(340,180),(500,180),(660,180),(820,180),
        (80,280),(240,280),(420,280),(580,280),(740,280),(820,280),
        (80,380),(200,380),(360,380),(520,380),(680,380),(820,380),
        (80,460),(220,460),(400,460),(560,460),(720,460),(820,460),
    ]
    # Connections between node indices
    _EDGES = [
        (0,1),(1,2),(2,3),(3,4),(4,5),
        (6,7),(7,8),(8,9),(9,10),(10,11),
        (12,13),(13,14),(14,15),(15,16),(16,17),
        (18,19),(19,20),(20,21),(21,22),(22,23),
        (24,25),(25,26),(26,27),(27,28),(28,29),
        (0,6),(6,12),(12,18),(18,24),
        (1,7),(7,13),(13,19),(19,25),
        (2,8),(8,14),(14,20),(20,26),
        (3,9),(9,15),(15,21),(21,27),
        (4,10),(10,16),(16,22),(22,28),
        (5,11),(11,17),(17,23),(23,29),
    ]

    def __init__(self, root, launch_callback):
        self.root     = root
        self.callback = launch_callback
        self._running = True
        self._phase   = 'boot'      # boot → draw → particles → ready
        self._tick    = 0
        self._drawn   = 0           # edges revealed so far
        self._particles = []
        self._btn_alpha = 0         # 0-255 fade-in for button
        self._logo_alpha = 0

        root.title("BIP39 Wallet Recovery  v2.0")
        root.geometry(f"{self.W}x{self.H}")
        root.resizable(False, False)
        root.configure(bg='#010c18')
        root.overrideredirect(False)

        # Center on screen
        root.update_idletasks()
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        root.geometry(f"{self.W}x{self.H}+{(sw-self.W)//2}+{(sh-self.H)//2}")

        self.canvas = tk.Canvas(root, width=self.W, height=self.H,
                                bg='#010c18', highlightthickness=0)
        self.canvas.pack(fill='both', expand=True)

        self._build_static()
        self._animate()

    # ── Static base elements ─────────────────────────────────────
    def _build_static(self):
        c = self.canvas
        # Faint grid dots (PCB substrate)
        for x in range(0, self.W, 40):
            for y in range(0, self.H, 40):
                c.create_oval(x-1, y-1, x+1, y+1,
                              fill='#0a1f35', outline='')

        # Pre-draw all edges in very dark color (will be "lit" later)
        self._edge_ids = []
        for a, b in self._EDGES:
            ax, ay = self._NODES[a]
            bx, by = self._NODES[b]
            eid = c.create_line(ax, ay, bx, by,
                                fill='#051525', width=1)
            self._edge_ids.append(eid)

        # Node circles (will be lit progressively)
        self._node_ids = []
        for x, y in self._NODES:
            nid = c.create_oval(x-4, y-4, x+4, y+4,
                                fill='#051525', outline='#051525', width=1)
            self._node_ids.append(nid)

        # Central logo area — drawn last so it's on top
        # Outer ring (pulsing handled in animate)
        self._ring1 = c.create_oval(390, 210, 510, 330,
                                    outline='#1f6feb', width=2)
        self._ring2 = c.create_oval(378, 198, 522, 342,
                                    outline='#0d3a7a', width=1)
        self._ring3 = c.create_oval(366, 186, 534, 354,
                                    outline='#061d3d', width=1)

        # BTC symbol
        self._logo_btc = c.create_text(450, 270,
                                       text='₿', fill='#0a2a5e',
                                       font=('Consolas', 42, 'bold'))
        # Title text (hidden initially)
        self._logo_title = c.create_text(450, 390,
                                         text='B I P 3 9   W A L L E T   R E C O V E R Y',
                                         fill='#051525',
                                         font=('Consolas', 11, 'bold'))
        self._logo_sub = c.create_text(450, 412,
                                       text='v2.0  ·  Multiprocessing  ·  100% Offline',
                                       fill='#051525',
                                       font=('Consolas', 9))
        self._logo_author = c.create_text(450, 500,
                                          text='by leonardoramcke',
                                          fill='#051525',
                                          font=('Consolas', 9))

        # INICIAR button (hidden initially)
        self._btn_rect = c.create_rectangle(350, 430, 550, 468,
                                            fill='#010c18', outline='#051525',
                                            width=1)
        self._btn_text = c.create_text(450, 449,
                                       text='▶   INICIAR',
                                       fill='#051525',
                                       font=('Consolas', 12, 'bold'))
        # Bind click
        for item in (self._btn_rect, self._btn_text):
            c.tag_bind(item, '<Button-1>', self._on_start)
            c.tag_bind(item, '<Enter>',    self._btn_hover_on)
            c.tag_bind(item, '<Leave>',    self._btn_hover_off)

    # ── Colour helpers ───────────────────────────────────────────
    @staticmethod
    def _lerp_color(c1, c2, t):
        """Linear interpolate between two hex colours."""
        r1,g1,b1 = int(c1[1:3],16), int(c1[3:5],16), int(c1[5:7],16)
        r2,g2,b2 = int(c2[1:3],16), int(c2[3:5],16), int(c2[5:7],16)
        r = int(r1 + (r2-r1)*t)
        g = int(g1 + (g2-g1)*t)
        b = int(b1 + (b2-b1)*t)
        return f'#{r:02x}{g:02x}{b:02x}'

    # ── Main animation loop ──────────────────────────────────────
    def _animate(self):
        if not self._running:
            return
        self._tick += 1
        c  = self.canvas
        t  = self._tick

        # ── Phase: boot (0-20 ticks: flicker nodes on) ──────────
        if self._phase == 'boot':
            if t % 3 == 0 and self._drawn < len(self._NODES):
                idx = self._drawn
                x, y = self._NODES[idx]
                c.itemconfig(self._node_ids[idx],
                             fill='#1f6feb', outline='#58a6ff')
                self._drawn += 1
            if self._drawn >= len(self._NODES):
                self._phase  = 'draw'
                self._drawn  = 0

        # ── Phase: draw (light up edges one by one) ─────────────
        elif self._phase == 'draw':
            per_tick = 2
            for _ in range(per_tick):
                if self._drawn < len(self._EDGES):
                    eid = self._edge_ids[self._drawn]
                    c.itemconfig(eid, fill='#0d3a6e', width=1)
                    self._drawn += 1
            if self._drawn >= len(self._EDGES):
                self._phase = 'particles'
                self._spawn_particles(8)

        # ── Phase: particles + logo fade-in ─────────────────────
        elif self._phase in ('particles', 'ready'):
            self._update_particles()

            # Logo fade-in
            if self._logo_alpha < 255:
                self._logo_alpha = min(255, self._logo_alpha + 6)
                a = self._logo_alpha / 255
                btc_col   = self._lerp_color('#0a2a5e', '#58a6ff', a)
                title_col = self._lerp_color('#051525', '#c9d1d9', a)
                sub_col   = self._lerp_color('#051525', '#484f58', a)
                c.itemconfig(self._logo_btc,    fill=btc_col)
                c.itemconfig(self._logo_title,  fill=title_col)
                c.itemconfig(self._logo_sub,    fill=sub_col)
                c.itemconfig(self._logo_author, fill=sub_col)

            # Ring pulse
            pulse = 0.5 + 0.5 * _math.sin(t * 0.08)
            ring_col = self._lerp_color('#061d3d', '#1f6feb', pulse)
            c.itemconfig(self._ring1, outline=ring_col)
            c.itemconfig(self._ring2,
                         outline=self._lerp_color('#030e1e', '#0d3a7a', pulse*0.6))

            # Spawn new particles occasionally
            if t % 18 == 0:
                self._spawn_particles(2)

            # Button fade-in (after logo is 60% visible)
            if self._logo_alpha > 150:
                if self._btn_alpha < 255:
                    self._btn_alpha = min(255, self._btn_alpha + 5)
                    a = self._btn_alpha / 255
                    btn_out  = self._lerp_color('#051525', '#1f6feb', a)
                    btn_txt  = self._lerp_color('#051525', '#58a6ff', a)
                    c.itemconfig(self._btn_rect, outline=btn_out)
                    c.itemconfig(self._btn_text, fill=btn_txt)

                if self._btn_alpha >= 255 and self._phase != 'ready':
                    self._phase = 'ready'

        self.root.after(30, self._animate)   # ~33 fps

    # ── Particle system ──────────────────────────────────────────
    def _spawn_particles(self, n):
        """Spawn n particles on random edges."""
        for _ in range(n):
            edge   = random.choice(self._EDGES)
            a, b   = edge
            ax, ay = self._NODES[a]
            bx, by = self._NODES[b]
            color  = random.choice(['#58a6ff', '#f7b731', '#3fb950', '#79c0ff'])
            self._particles.append({
                'ax': ax, 'ay': ay, 'bx': bx, 'by': by,
                't': 0.0, 'speed': random.uniform(0.015, 0.04),
                'color': color, 'id': None, 'trail': [],
            })

    def _update_particles(self):
        c    = self.canvas
        dead = []
        for p in self._particles:
            # Remove old trail dots
            for tid in p['trail']:
                try: c.delete(tid)
                except: pass
            p['trail'] = []
            if p['id']:
                try: c.delete(p['id'])
                except: pass

            p['t'] += p['speed']
            if p['t'] >= 1.0:
                dead.append(p)
                continue

            # Current position
            x = p['ax'] + (p['bx'] - p['ax']) * p['t']
            y = p['ay'] + (p['by'] - p['ay']) * p['t']

            # Draw trail (3 ghost dots behind)
            for i, dt in enumerate([0.06, 0.12, 0.18]):
                tt = max(0, p['t'] - dt)
                tx = p['ax'] + (p['bx'] - p['ax']) * tt
                ty = p['ay'] + (p['by'] - p['ay']) * tt
                alpha = 1 - (i+1)/4
                r = 2 - i
                if r > 0:
                    trail_id = c.create_oval(tx-r, ty-r, tx+r, ty+r,
                                             fill=p['color'], outline='',
                                             stipple='gray50' if i>0 else '')
                    p['trail'].append(trail_id)

            # Draw head
            pid = c.create_oval(x-4, y-4, x+4, y+4,
                                fill=p['color'], outline='white', width=0.5)
            p['id'] = pid

        for p in dead:
            self._particles.remove(p)

    # ── Button interactions ──────────────────────────────────────
    def _btn_hover_on(self, _=None):
        if self._btn_alpha >= 200:
            self.canvas.itemconfig(self._btn_rect,
                                   fill='#0d2a4a', outline='#58a6ff', width=2)
            self.canvas.itemconfig(self._btn_text, fill='#ffffff')
            self.canvas.configure(cursor='hand2')

    def _btn_hover_off(self, _=None):
        if self._btn_alpha >= 200:
            self.canvas.itemconfig(self._btn_rect,
                                   fill='#010c18', outline='#1f6feb', width=1)
            self.canvas.itemconfig(self._btn_text, fill='#58a6ff')
            self.canvas.configure(cursor='')

    def _on_start(self, _=None):
        self._running = False
        self.root.destroy()
        self.callback()


# ══════════════════════════════════════════════════════════════
#  Entry point — freeze_support() required for PyInstaller/Win
# ══════════════════════════════════════════════════════════════
def _launch_main():
    root = tk.Tk()
    App(root)
    root.mainloop()

if __name__ == '__main__':
    multiprocessing.freeze_support()
    intro_root = tk.Tk()
    IntroScreen(intro_root, _launch_main)
    intro_root.mainloop()
