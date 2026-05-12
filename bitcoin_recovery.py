#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         BIP39 BITCOIN WALLET RECOVERY TOOL                  ║
║         by: leonardoramcke (github.com/leonardoramcke)      ║
║         MIT License © 2026                                  ║
╚══════════════════════════════════════════════════════════════╝

Recovery tool for Bitcoin BIP39 wallets.
Supports CPU multicore processing with full hardware control.
Derivations: BIP44, BIP49, BIP84
"""

import hashlib
import time
import sys
import os
import itertools
import threading
import math
import multiprocessing
import psutil
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import bech32
from mnemonic import Mnemonic
from bip32utils import BIP32Key, BIP32_HARDEN

# ──────────────────────────────────────────────
#  GLOBALS
# ──────────────────────────────────────────────

MNEMO    = Mnemonic('english')
WORDLIST = MNEMO.wordlist
CPU_COUNT = multiprocessing.cpu_count()

# ──────────────────────────────────────────────
#  BASE58CHECK — pure Python (no external lib)
# ──────────────────────────────────────────────

_B58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def _b58encode(payload: bytes) -> str:
    """Base58Check encoding — pure Python, no library needed."""
    n = int.from_bytes(payload, 'big')
    result = []
    while n > 0:
        n, remainder = divmod(n, 58)
        result.append(_B58_ALPHABET[remainder])
    leading_zeros = len(payload) - len(payload.lstrip(b'\x00'))
    result.extend([_B58_ALPHABET[0]] * leading_zeros)
    return bytes(reversed(result)).decode('ascii')


# ──────────────────────────────────────────────
#  HARDWARE MONITOR
# ──────────────────────────────────────────────

def get_cpu_usage():
    return psutil.cpu_percent(interval=0.1)

def get_ram_usage():
    return psutil.virtual_memory().percent

def get_cpu_temp():
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            for name, entries in temps.items():
                if entries:
                    return entries[0].current
    except Exception:
        pass
    return None

def get_ram_available_gb():
    return psutil.virtual_memory().available / (1024**3)

# ──────────────────────────────────────────────
#  ESTIMATIVA DE TEMPO
# ──────────────────────────────────────────────

SPEED_PER_SECOND = 150

def calcular_combinacoes(total_palavras, palavras_conhecidas, posicao_conhecida=False):
    faltando = total_palavras - palavras_conhecidas
    if faltando <= 0:
        return 1
    if faltando == 1 and posicao_conhecida:
        return 2048
    if faltando == 1:
        return total_palavras * 2048
    return 2048 ** faltando

def formatar_tempo(segundos):
    if segundos < 60:
        return f"~{int(segundos)} seconds"
    elif segundos < 3600:
        return f"~{int(segundos/60)} minutes"
    elif segundos < 86400:
        return f"~{int(segundos/3600)} hours"
    elif segundos < 86400 * 30:
        return f"~{int(segundos/86400)} days"
    elif segundos < 86400 * 365:
        return f"~{int(segundos/86400/30)} months"
    elif segundos < 86400 * 365 * 1000:
        return f"~{int(segundos/86400/365)} years"
    else:
        return "eternity (not feasible)"

def avaliar_viabilidade(combinacoes, workers=1):
    speed = SPEED_PER_SECOND * workers
    segundos = combinacoes / speed
    if segundos < 1800:
        return "EASY", "#3fb950", segundos
    elif segundos < 86400:
        return "MODERATE", "#f7b731", segundos
    elif segundos < 86400*30:
        return "HARD", "#e3702a", segundos
    elif segundos < 86400*365:
        return "VERY HARD", "#da3633", segundos
    else:
        return "NOT FEASIBLE", "#8b0000", segundos

def gerar_analise(palavras_conhecidas, total_palavras, tem_senha,
                  tem_endereco, tem_derivacao, posicao_conhecida, workers=1):
    faltando = total_palavras - palavras_conhecidas
    combinacoes = calcular_combinacoes(total_palavras, palavras_conhecidas, posicao_conhecida)
    nivel, cor, segundos = avaliar_viabilidade(combinacoes, workers)
    tempo = formatar_tempo(segundos)

    linhas = []
    linhas.append("━━━  SITUATION ANALYSIS  ━━━")
    linhas.append("")
    linhas.append(f"  Seed size         : {total_palavras} words")
    linhas.append(f"  You have          : {palavras_conhecidas} words")
    linhas.append(f"  Missing           : {faltando} word(s)")
    linhas.append(f"  Position known    : {'Yes ✅' if posicao_conhecida else 'No ❌'}")
    linhas.append(f"  Has passphrase    : {'Yes ✅' if tem_senha else 'No ❌'}")
    linhas.append(f"  Has address       : {'Yes ✅' if tem_endereco else 'No ❌  ← important!'}")
    linhas.append(f"  Has derivation    : {'Yes ✅' if tem_derivacao else 'No ❌'}")
    linhas.append(f"  Workers (cores)   : {workers}")
    linhas.append("")
    linhas.append(f"  Combinations      : {combinacoes:,}")
    linhas.append(f"  Estimated time    : {tempo}")
    linhas.append(f"  Feasibility       : {nivel}")
    linhas.append("")

    if faltando == 0:
        linhas.append("  ℹ️  You have all words!")
        linhas.append("  Check passphrase and derivation type.")
    elif faltando == 1 and posicao_conhecida:
        linhas.append("  🟢 Ideal situation. Seconds to solve.")
    elif faltando == 1:
        linhas.append("  🟢 Great. One missing word is totally feasible.")
        linhas.append("  Knowing the position makes it even faster.")
    elif faltando == 2:
        linhas.append("  🟡 Possible. May take hours.")
        linhas.append("  If you know the positions, provide them.")
    elif faltando == 3:
        linhas.append("  🟠 Hard. May take days or weeks.")
    elif faltando <= 5:
        linhas.append("  🔴 Very hard on a regular PC.")
        linhas.append("  Specialized hardware (GPUs) would be needed.")
    else:
        linhas.append("  💀 Not feasible with common hardware.")

    linhas.append("")
    linhas.append("  💡 What can still help:")
    if not tem_endereco:
        linhas.append("   ➕ Public address → essential to confirm a match")
    if not posicao_conhecida and faltando >= 1:
        linhas.append("   ➕ Word position → drastically reduces combinations")
    if not tem_derivacao:
        linhas.append("   ➕ BIP type (84/44/49) → avoids testing wrong paths")
    if not tem_senha:
        linhas.append("   ➕ Confirm no passphrase was used → eliminates a variable")
    if faltando > 2:
        linhas.append("   ➕ Each extra word you remember divides time by 2048")
    if workers < CPU_COUNT:
        linhas.append(f"   ➕ More CPU workers → you have {CPU_COUNT} cores available")

    return "\n".join(linhas), cor, nivel

# ──────────────────────────────────────────────
#  CORE: Address derivation
# ──────────────────────────────────────────────

def derive_address(seed_bytes, path_type="bip84", index=0, change=0):
    try:
        master = BIP32Key.fromEntropy(seed_bytes)
        if path_type == "bip84":
            child = (master
                     .ChildKey(84 + BIP32_HARDEN)
                     .ChildKey(0 + BIP32_HARDEN)
                     .ChildKey(0 + BIP32_HARDEN)
                     .ChildKey(change)
                     .ChildKey(index))
            pubkey = child.PublicKey()
            sha256 = hashlib.sha256(pubkey).digest()
            ripemd = hashlib.new('ripemd160', sha256).digest()
            return bech32.encode('bc', 0, ripemd)
        elif path_type == "bip44":
            child = (master
                     .ChildKey(44 + BIP32_HARDEN)
                     .ChildKey(0 + BIP32_HARDEN)
                     .ChildKey(0 + BIP32_HARDEN)
                     .ChildKey(change)
                     .ChildKey(index))
            return child.Address()
        elif path_type == "bip49":
            child = (master
                     .ChildKey(49 + BIP32_HARDEN)
                     .ChildKey(0 + BIP32_HARDEN)
                     .ChildKey(0 + BIP32_HARDEN)
                     .ChildKey(change)
                     .ChildKey(index))
            pubkey = child.PublicKey()
            sha256 = hashlib.sha256(pubkey).digest()
            ripemd = hashlib.new('ripemd160', sha256).digest()
            redeem = bytes([0x00, 0x14]) + ripemd
            sha256b = hashlib.sha256(redeem).digest()
            ripemd2 = hashlib.new('ripemd160', sha256b).digest()
            prefix = bytes([0x05])
            checksum = hashlib.sha256(hashlib.sha256(prefix + ripemd2).digest()).digest()[:4]
            return _b58encode(prefix + ripemd2 + checksum)
    except Exception:
        return None

def check_mnemonic(words, passphrase, target_address, path_type, addr_limit, change_limit):
    phrase = ' '.join(words)
    if not MNEMO.check(phrase):
        return False
    seed = MNEMO.to_seed(phrase, passphrase)
    for c in range(change_limit):
        for i in range(addr_limit):
            addr = derive_address(seed, path_type, i, c)
            if addr and addr == target_address:
                return True
    return False

# ──────────────────────────────────────────────
#  WORKER FUNCTION (runs in separate process)
# ──────────────────────────────────────────────

def worker_search(task_queue, result_queue, passphrase, target,
                  path_type, addr_limit, change_limit):
    """Worker process: pulls word chunks from queue and searches."""
    while True:
        try:
            task = task_queue.get(timeout=2)
            if task is None:
                break
            pos, words_base, word_chunk = task
            for word in word_chunk:
                candidate = words_base[:pos] + [word] + words_base[pos:]
                if check_mnemonic(candidate, passphrase, target, path_type,
                                  addr_limit, change_limit):
                    result_queue.put({'words': candidate, 'found_word': word,
                                      'position': pos + 1})
                    return
            result_queue.put(('progress', len(word_chunk)))
        except Exception:
            break

# ──────────────────────────────────────────────
#  RECOVERY MODES
# ──────────────────────────────────────────────

def mode_one_missing(words_23, passphrase, target, path, addr_limit, change_limit,
                     known_position, log_fn, progress_fn, stop_event, num_workers=1):
    positions = [known_position - 1] if known_position > 0 else list(range(24))
    total = len(positions) * 2048
    done = 0

    for pos in positions:
        if stop_event.is_set():
            return None
        log_fn(f"⟳ Testing position {pos + 1}/24 with {num_workers} worker(s)...")

        if num_workers <= 1:
            # Single-threaded
            for word in WORDLIST:
                if stop_event.is_set():
                    return None
                candidate = words_23[:pos] + [word] + words_23[pos:]
                done += 1
                progress_fn(done, total)
                if check_mnemonic(candidate, passphrase, target, path,
                                  addr_limit, change_limit):
                    return {'words': candidate, 'found_word': word, 'position': pos + 1}
        else:
            # Multi-process
            chunk_size = max(1, len(WORDLIST) // num_workers)
            chunks = [WORDLIST[i:i+chunk_size]
                      for i in range(0, len(WORDLIST), chunk_size)]

            task_q   = multiprocessing.Queue()
            result_q = multiprocessing.Queue()

            for chunk in chunks:
                task_q.put((pos, words_23, chunk))
            for _ in range(num_workers):
                task_q.put(None)

            procs = []
            for _ in range(num_workers):
                p = multiprocessing.Process(
                    target=worker_search,
                    args=(task_q, result_q, passphrase, target,
                          path, addr_limit, change_limit),
                    daemon=True)
                p.start()
                procs.append(p)

            result = None
            finished = 0
            while finished < len(chunks):
                if stop_event.is_set():
                    for p in procs:
                        p.terminate()
                    return None
                try:
                    msg = result_q.get(timeout=0.5)
                    if isinstance(msg, dict):
                        result = msg
                        for p in procs:
                            p.terminate()
                        break
                    elif isinstance(msg, tuple) and msg[0] == 'progress':
                        done += msg[1]
                        progress_fn(done, total)
                        finished += 1
                except Exception:
                    pass

            for p in procs:
                p.join(timeout=1)

            if result:
                return result

    return None


def mode_two_missing(words_22, missing_positions, passphrase, target, path,
                     addr_limit, change_limit, log_fn, progress_fn, stop_event,
                     num_workers=1):
    total = 2048 * 2048
    done = 0
    p1, p2 = missing_positions[0] - 1, missing_positions[1] - 1

    for w1 in WORDLIST:
        if stop_event.is_set():
            return None
        log_fn(f"⟳ First word: '{w1}'...")
        for w2 in WORDLIST:
            if stop_event.is_set():
                return None
            candidate = list(words_22)
            candidate.insert(p1, w1)
            candidate.insert(p2 + 1, w2)
            done += 1
            progress_fn(done, total)
            if check_mnemonic(candidate, passphrase, target, path,
                              addr_limit, change_limit):
                return {'words': candidate, 'found_words': [w1, w2],
                        'positions': [p1+1, p2+1]}
    return None


def mode_partial_known(partial_words, known_mask, passphrase, target, path,
                       addr_limit, change_limit, log_fn, progress_fn, stop_event,
                       num_workers=1):
    unknown_positions = [i for i, known in enumerate(known_mask) if not known]
    n_unknown = len(unknown_positions)
    total = 2048 ** n_unknown
    done = 0

    log_fn(f"⟳ {n_unknown} unknown words → {total:,} combinations")
    if total > 10_000_000:
        log_fn(f"⚠️  Many combinations ({total:,}). May take a long time.")

    for combo in itertools.product(WORDLIST, repeat=n_unknown):
        if stop_event.is_set():
            return None
        candidate = list(partial_words)
        for i, pos in enumerate(unknown_positions):
            candidate[pos] = combo[i]
        done += 1
        if done % 10000 == 0:
            progress_fn(done, total)
            log_fn(f"⟳ {done:,}/{total:,} tested...")
        if check_mnemonic(candidate, passphrase, target, path,
                          addr_limit, change_limit):
            return {'words': candidate, 'found_words': list(combo),
                    'positions': unknown_positions}
    return None

# ──────────────────────────────────────────────
#  GUI
# ──────────────────────────────────────────────

class BitcoinRecoveryApp:
    def __init__(self, root):
        self.root = root
        self.root.title("BIP39 Bitcoin Wallet Recovery Tool")
        self.root.geometry("960x860")
        self.root.resizable(True, True)
        self.root.minsize(900, 800)
        self.root.configure(bg="#0d1117")

        self.stop_event      = threading.Event()
        self.recovery_thread = None

        self._setup_styles()
        self._build_ui()
        self._start_hardware_monitor()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#0d1117', borderwidth=0)
        style.configure('TNotebook.Tab', background='#161b22', foreground='#8b949e',
                        padding=[16, 8], font=('Consolas', 10))
        style.map('TNotebook.Tab',
                  background=[('selected', '#1f2937')],
                  foreground=[('selected', '#f7b731')])
        style.configure('TFrame', background='#0d1117')
        style.configure('TLabel', background='#0d1117', foreground='#c9d1d9',
                        font=('Consolas', 10))
        style.configure('TLabelframe', background='#0d1117', foreground='#f7b731',
                        bordercolor='#30363d')
        style.configure('TLabelframe.Label', background='#0d1117',
                        foreground='#f7b731', font=('Consolas', 10, 'bold'))
        style.configure('TCombobox', fieldbackground='#161b22', background='#161b22',
                        foreground='#c9d1d9', font=('Consolas', 10))
        style.configure('Horizontal.TProgressbar', background='#f7b731',
                        troughcolor='#161b22', borderwidth=0)
        style.configure('CPU.Horizontal.TProgressbar', background='#3fb950',
                        troughcolor='#161b22', borderwidth=0)
        style.configure('RAM.Horizontal.TProgressbar', background='#58a6ff',
                        troughcolor='#161b22', borderwidth=0)
        style.configure('TEMP.Horizontal.TProgressbar', background='#f7b731',
                        troughcolor='#161b22', borderwidth=0)

    def _entry(self, parent, show=None, width=40):
        return tk.Entry(parent, show=show, width=width,
                        bg='#161b22', fg='#c9d1d9',
                        insertbackground='#f7b731', relief='flat', bd=6,
                        font=('Consolas', 10), highlightthickness=1,
                        highlightcolor='#f7b731', highlightbackground='#30363d')

    def _btn(self, parent, text, command, color='#f7b731', fg='#0d1117'):
        return tk.Button(parent, text=text, command=command,
                         bg=color, fg=fg, activebackground='#e5a820',
                         relief='flat', bd=0, padx=20, pady=8,
                         font=('Consolas', 10, 'bold'), cursor='hand2')

    def _build_ui(self):
        # Header
        header = tk.Frame(self.root, bg='#0d1117')
        header.pack(fill='x', padx=20, pady=(16, 0))
        tk.Label(header, text="₿ BIP39 Wallet Recovery",
                 bg='#0d1117', fg='#f7b731',
                 font=('Consolas', 18, 'bold')).pack(side='left')
        tk.Label(header,
                 text="BIP44 · BIP49 · BIP84  |  Multi-core CPU  |  Hardware Monitor",
                 bg='#0d1117', fg='#484f58',
                 font=('Consolas', 9)).pack(side='left', padx=16, pady=4)
        ttk.Separator(self.root, orient='horizontal').pack(fill='x', padx=20, pady=8)

        # Hardware monitor bar
        self._build_hw_bar()

        # Notebook
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill='both', expand=False, padx=20, pady=0)
        self._tab_recovery()
        self._tab_hardware()
        self._tab_analise()
        self._tab_about()

        # Log
        bottom = tk.Frame(self.root, bg='#0d1117')
        bottom.pack(fill='x', padx=20, pady=(8, 4))
        log_frame = ttk.LabelFrame(bottom, text="  LOG  ")
        log_frame.pack(fill='both', expand=True)
        self.log_box = scrolledtext.ScrolledText(
            log_frame, height=5, bg='#010409', fg='#3fb950',
            font=('Consolas', 9), relief='flat', bd=4,
            insertbackground='#3fb950', state='disabled')
        self.log_box.pack(fill='both', expand=True, padx=4, pady=4)

        prog_frame = tk.Frame(bottom, bg='#0d1117')
        prog_frame.pack(fill='x', pady=(4, 0))
        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(prog_frame, variable=self.progress_var, maximum=100,
                        style='Horizontal.TProgressbar').pack(
            side='left', fill='x', expand=True)
        self.progress_label = tk.Label(prog_frame, text="0%",
                                       bg='#0d1117', fg='#8b949e',
                                       font=('Consolas', 9), width=8)
        self.progress_label.pack(side='left', padx=6)

        # Buttons
        btn_frame = tk.Frame(self.root, bg='#0d1117')
        btn_frame.pack(pady=(4, 8))
        self._btn(btn_frame, "▶  START RECOVERY", self._start_recovery).pack(side='left', padx=8)
        self._btn(btn_frame, "■  STOP", self._stop_recovery,
                  color='#da3633', fg='white').pack(side='left', padx=8)
        self._btn(btn_frame, "⎘  EXPORT LOG", self._export_log,
                  color='#238636', fg='white').pack(side='left', padx=8)

    def _build_hw_bar(self):
        """Compact hardware status bar at the top."""
        bar = tk.Frame(self.root, bg='#161b22', height=36)
        bar.pack(fill='x', padx=20, pady=(0, 6))
        bar.pack_propagate(False)

        def hw_item(parent, label, color):
            f = tk.Frame(parent, bg='#161b22')
            f.pack(side='left', padx=16, pady=4)
            tk.Label(f, text=label, bg='#161b22', fg='#484f58',
                     font=('Consolas', 8)).pack(side='left')
            var = tk.DoubleVar()
            pb = ttk.Progressbar(f, variable=var, maximum=100, length=80,
                                 style=f'{color}.Horizontal.TProgressbar')
            pb.pack(side='left', padx=4)
            lbl = tk.Label(f, text="0%", bg='#161b22', fg=color,
                           font=('Consolas', 8), width=5)
            lbl.pack(side='left')
            return var, lbl

        self.hw_cpu_var,  self.hw_cpu_lbl  = hw_item(bar, "CPU", "#3fb950")
        self.hw_ram_var,  self.hw_ram_lbl  = hw_item(bar, "RAM", "#58a6ff")

        # Cores info
        tk.Label(bar, text=f"Cores: {CPU_COUNT}",
                 bg='#161b22', fg='#f7b731',
                 font=('Consolas', 8)).pack(side='left', padx=16)

        # Workers indicator
        self.hw_workers_lbl = tk.Label(bar, text="Workers: 1",
                                       bg='#161b22', fg='#c9d1d9',
                                       font=('Consolas', 8))
        self.hw_workers_lbl.pack(side='left', padx=8)

        # Safety indicator
        self.hw_safety_lbl = tk.Label(bar, text="● SAFE",
                                      bg='#161b22', fg='#3fb950',
                                      font=('Consolas', 8, 'bold'))
        self.hw_safety_lbl.pack(side='right', padx=16)

    def _start_hardware_monitor(self):
        """Updates hardware monitor every 2 seconds."""
        def update():
            while True:
                try:
                    cpu = get_cpu_usage()
                    ram = get_ram_usage()

                    self.hw_cpu_var.set(cpu)
                    self.hw_ram_var.set(ram)
                    self.hw_cpu_lbl.config(text=f"{cpu:.0f}%")
                    self.hw_ram_lbl.config(text=f"{ram:.0f}%")

                    # Safety indicator
                    if cpu > 90 or ram > 90:
                        self.hw_safety_lbl.config(text="● HIGH LOAD", fg='#da3633')
                    elif cpu > 70 or ram > 75:
                        self.hw_safety_lbl.config(text="● MODERATE", fg='#f7b731')
                    else:
                        self.hw_safety_lbl.config(text="● SAFE", fg='#3fb950')

                    self.root.update_idletasks()
                except Exception:
                    pass
                time.sleep(2)

        t = threading.Thread(target=update, daemon=True)
        t.start()

    def _tab_recovery(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  🔑  Recovery  ")

        mode_frame = ttk.LabelFrame(tab, text="  RECOVERY MODE  ")
        mode_frame.pack(fill='x', padx=12, pady=(12, 6))
        self.mode_var = tk.StringVar(value="1_missing_unknown")
        modes = [
            ("1 missing word — UNKNOWN position (tests all)", "1_missing_unknown"),
            ("1 missing word — KNOWN position", "1_missing_known"),
            ("2 missing words — KNOWN positions", "2_missing_known"),
            ("Multiple words with '?' for unknowns", "partial"),
        ]
        for text, val in modes:
            tk.Radiobutton(mode_frame, text=text, variable=self.mode_var, value=val,
                           bg='#0d1117', fg='#c9d1d9', selectcolor='#161b22',
                           activebackground='#0d1117', activeforeground='#f7b731',
                           font=('Consolas', 10),
                           command=self._on_mode_change).pack(anchor='w', padx=12, pady=2)

        words_frame = ttk.LabelFrame(tab, text="  SEED WORDS  ")
        words_frame.pack(fill='x', padx=12, pady=6)
        tk.Label(words_frame,
                 text="Paste your words separated by spaces. Use '?' for unknown positions (partial mode):",
                 bg='#0d1117', fg='#8b949e', font=('Consolas', 9)).pack(anchor='w', padx=8, pady=(4,0))
        self.words_entry = tk.Text(words_frame, height=3, bg='#161b22', fg='#c9d1d9',
                                   font=('Consolas', 11), relief='flat', bd=6,
                                   insertbackground='#f7b731', highlightthickness=1,
                                   highlightcolor='#f7b731', highlightbackground='#30363d')
        self.words_entry.pack(fill='x', padx=8, pady=6)

        pos_frame = tk.Frame(tab, bg='#0d1117')
        pos_frame.pack(fill='x', padx=12, pady=2)
        tk.Label(pos_frame, text="Position of 1st missing word (0 = unknown):",
                 bg='#0d1117', fg='#8b949e', font=('Consolas', 9)).pack(side='left')
        self.pos1_var = tk.IntVar(value=0)
        tk.Spinbox(pos_frame, from_=0, to=24, textvariable=self.pos1_var,
                   width=4, bg='#161b22', fg='#c9d1d9', font=('Consolas', 10),
                   buttonbackground='#1f2937').pack(side='left', padx=6)
        tk.Label(pos_frame, text="Position of 2nd missing word:",
                 bg='#0d1117', fg='#8b949e', font=('Consolas', 9)).pack(side='left', padx=(20,0))
        self.pos2_var = tk.IntVar(value=0)
        self.pos2_spin = tk.Spinbox(pos_frame, from_=0, to=24, textvariable=self.pos2_var,
                                    width=4, bg='#161b22', fg='#c9d1d9', font=('Consolas', 10),
                                    buttonbackground='#1f2937', state='disabled')
        self.pos2_spin.pack(side='left', padx=6)

        cred_frame = ttk.LabelFrame(tab, text="  CREDENTIALS  ")
        cred_frame.pack(fill='x', padx=12, pady=6)

        row1 = tk.Frame(cred_frame, bg='#0d1117')
        row1.pack(fill='x', padx=8, pady=4)
        tk.Label(row1, text="Passphrase:", width=22, anchor='w').pack(side='left')
        self.pass_entry = self._entry(row1, show='•', width=30)
        self.pass_entry.pack(side='left', padx=4)
        self.show_pass = tk.BooleanVar()
        tk.Checkbutton(row1, text="show", variable=self.show_pass,
                       bg='#0d1117', fg='#8b949e', selectcolor='#161b22',
                       activebackground='#0d1117', font=('Consolas', 9),
                       command=lambda: self.pass_entry.config(
                           show='' if self.show_pass.get() else '•')).pack(side='left')

        row2 = tk.Frame(cred_frame, bg='#0d1117')
        row2.pack(fill='x', padx=8, pady=4)
        tk.Label(row2, text="Bitcoin address:", width=22, anchor='w').pack(side='left')
        self.addr_entry = self._entry(row2, width=50)
        self.addr_entry.pack(side='left', padx=4)

        row3 = tk.Frame(cred_frame, bg='#0d1117')
        row3.pack(fill='x', padx=8, pady=4)
        tk.Label(row3, text="Address type:", width=22, anchor='w').pack(side='left')
        self.path_var = tk.StringVar(value="bip84")
        ttk.Combobox(row3, textvariable=self.path_var, width=20,
                     values=["bip84 (bc1q...)", "bip44 (1...)", "bip49 (3...)"],
                     state='readonly').pack(side='left', padx=4)
        tk.Label(row3, text="Address indexes:", padx=12).pack(side='left')
        self.addr_limit_var = tk.IntVar(value=10)
        tk.Spinbox(row3, from_=1, to=50, textvariable=self.addr_limit_var,
                   width=4, bg='#161b22', fg='#c9d1d9', font=('Consolas', 10),
                   buttonbackground='#1f2937').pack(side='left')
        self.change_var = tk.BooleanVar(value=False)
        tk.Checkbutton(row3, text="test change path too",
                       variable=self.change_var, bg='#0d1117', fg='#8b949e',
                       selectcolor='#161b22', activebackground='#0d1117',
                       font=('Consolas', 9)).pack(side='left', padx=8)

    def _tab_hardware(self):
        """Full hardware control tab."""
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  ⚡  Hardware Control  ")

        # CPU Workers
        cpu_frame = ttk.LabelFrame(tab, text="  CPU WORKERS  ")
        cpu_frame.pack(fill='x', padx=12, pady=(12, 6))

        tk.Label(cpu_frame,
                 text=f"Your CPU has {CPU_COUNT} cores available. Choose how many to use for recovery:",
                 bg='#0d1117', fg='#8b949e', font=('Consolas', 9)).pack(anchor='w', padx=12, pady=(6,2))

        slider_frame = tk.Frame(cpu_frame, bg='#0d1117')
        slider_frame.pack(fill='x', padx=12, pady=6)

        self.workers_var = tk.IntVar(value=max(1, CPU_COUNT // 2))
        self.workers_label = tk.Label(slider_frame,
                                      text=f"Workers: {self.workers_var.get()}",
                                      bg='#0d1117', fg='#f7b731',
                                      font=('Consolas', 12, 'bold'), width=14)
        self.workers_label.pack(side='left')

        def on_slider(val):
            v = int(float(val))
            self.workers_var.set(v)
            self.workers_label.config(text=f"Workers: {v}")
            self.hw_workers_lbl.config(text=f"Workers: {v}")
            pct = int((v / CPU_COUNT) * 100)
            desc = "🟢 Light" if pct <= 40 else "🟡 Moderate" if pct <= 70 else "🔴 Heavy"
            self.workers_desc.config(text=f"{pct}% of CPU capacity  {desc}")

        self.workers_slider = tk.Scale(
            slider_frame, from_=1, to=CPU_COUNT,
            orient='horizontal', variable=self.workers_var,
            command=on_slider, length=400,
            bg='#0d1117', fg='#c9d1d9', troughcolor='#161b22',
            activebackground='#f7b731', highlightthickness=0,
            sliderrelief='flat', font=('Consolas', 9))
        self.workers_slider.pack(side='left', padx=12)

        self.workers_desc = tk.Label(cpu_frame, text="",
                                     bg='#0d1117', fg='#8b949e',
                                     font=('Consolas', 9))
        self.workers_desc.pack(anchor='w', padx=12, pady=(0,4))
        on_slider(self.workers_var.get())

        # Presets
        preset_frame = ttk.LabelFrame(tab, text="  PRESETS — Choose based on your situation  ")
        preset_frame.pack(fill='x', padx=12, pady=6)

        presets = [
            ("🟢  Safe Mode\n(1 worker — PC stays responsive)",
             1, '#238636'),
            (f"🟡  Balanced\n({max(1, CPU_COUNT//2)} workers — recommended for most users)",
             max(1, CPU_COUNT//2), '#b08800'),
            (f"🔴  Maximum Power\n({CPU_COUNT} workers — PC may slow down during recovery)",
             CPU_COUNT, '#da3633'),
        ]
        pf = tk.Frame(preset_frame, bg='#0d1117')
        pf.pack(fill='x', padx=12, pady=8)
        for label, workers, color in presets:
            tk.Button(pf, text=label, width=32,
                      command=lambda w=workers: (
                          self.workers_var.set(w),
                          self.workers_slider.set(w),
                          on_slider(w)),
                      bg='#161b22', fg='#c9d1d9',
                      activebackground=color,
                      relief='flat', bd=1, padx=10, pady=8,
                      font=('Consolas', 9), cursor='hand2',
                      justify='left').pack(side='left', padx=8)

        # Safety warnings
        warn_frame = ttk.LabelFrame(tab, text="  SAFETY GUIDELINES  ")
        warn_frame.pack(fill='both', expand=True, padx=12, pady=6)

        warnings = """
  ⚠️  IMPORTANT — Read before choosing Maximum Power:

  🌡️  TEMPERATURE
      More workers = more heat generated by the CPU.
      If your PC has poor ventilation or is a laptop,
      avoid using more than 50% of cores.
      Stop immediately if the machine becomes very hot.

  💾  RAM MEMORY
      Each worker uses approximately 50–100 MB of RAM.
      If your PC has less than 4 GB RAM, use Safe Mode.

  🔋  LAPTOPS
      Running on battery? Use Safe Mode (1–2 workers).
      Maximum Power on battery drains it very fast
      and may cause thermal throttling.

  🖥️  WHILE RECOVERY IS RUNNING
      The more workers you use, the less responsive
      your PC will be for other tasks.
      Balanced mode lets you use your PC normally.

  ✅  RECOMMENDATION FOR MOST USERS
      Start with Balanced mode.
      If PC handles it fine, increase workers.
      Watch the CPU/RAM indicators at the top.
        """
        tk.Label(warn_frame, text=warnings, bg='#0d1117', fg='#8b949e',
                 font=('Consolas', 9), justify='left').pack(anchor='w', padx=8)

    def _tab_analise(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  📊  Feasibility Analysis  ")

        ctrl = ttk.LabelFrame(tab, text="  WHAT DO YOU HAVE?  ")
        ctrl.pack(fill='x', padx=12, pady=(12, 6))

        r1 = tk.Frame(ctrl, bg='#0d1117')
        r1.pack(fill='x', padx=12, pady=6)
        tk.Label(r1, text="Seed size:", width=22, anchor='w').pack(side='left')
        self.seed_size_var = tk.IntVar(value=24)
        ttk.Combobox(r1, textvariable=self.seed_size_var, width=6,
                     values=[12, 15, 18, 21, 24], state='readonly').pack(side='left', padx=4)
        tk.Label(r1, text="total words", bg='#0d1117', fg='#8b949e',
                 font=('Consolas', 9)).pack(side='left', padx=6)

        r2 = tk.Frame(ctrl, bg='#0d1117')
        r2.pack(fill='x', padx=12, pady=4)
        tk.Label(r2, text="Words you have:", width=22, anchor='w').pack(side='left')
        self.known_words_var = tk.IntVar(value=23)
        tk.Spinbox(r2, from_=0, to=24, textvariable=self.known_words_var,
                   width=4, bg='#161b22', fg='#c9d1d9', font=('Consolas', 10),
                   buttonbackground='#1f2937').pack(side='left', padx=4)

        r3 = tk.Frame(ctrl, bg='#0d1117')
        r3.pack(fill='x', padx=12, pady=4)
        self.tem_posicao_var  = tk.BooleanVar(value=False)
        self.tem_senha_var    = tk.BooleanVar(value=True)
        self.tem_endereco_var = tk.BooleanVar(value=True)
        self.tem_deriv_var    = tk.BooleanVar(value=True)

        def cb(parent, text, var):
            tk.Checkbutton(parent, text=text, variable=var,
                           bg='#0d1117', fg='#c9d1d9', selectcolor='#161b22',
                           activebackground='#0d1117', activeforeground='#f7b731',
                           font=('Consolas', 10)).pack(side='left', padx=10)

        cb(r3, "Know word position", self.tem_posicao_var)
        cb(r3, "Have passphrase", self.tem_senha_var)
        r4 = tk.Frame(ctrl, bg='#0d1117')
        r4.pack(fill='x', padx=12, pady=(2, 8))
        cb(r4, "Have public address", self.tem_endereco_var)
        cb(r4, "Know derivation type", self.tem_deriv_var)

        self._btn(ctrl, "  CALCULATE ANALYSIS  ", self._calcular_analise,
                  color='#1f6feb', fg='white').pack(pady=(0, 10))

        result_frame = ttk.LabelFrame(tab, text="  RESULT  ")
        result_frame.pack(fill='both', expand=True, padx=12, pady=6)
        self.analise_box = scrolledtext.ScrolledText(
            result_frame, height=16, bg='#010409', fg='#c9d1d9',
            font=('Consolas', 10), relief='flat', bd=4,
            insertbackground='#f7b731', state='disabled')
        self.analise_box.pack(fill='both', expand=True, padx=4, pady=4)
        self.root.after(300, self._calcular_analise)

    def _calcular_analise(self):
        total       = self.seed_size_var.get()
        conhecidas  = min(self.known_words_var.get(), total)
        workers     = self.workers_var.get() if hasattr(self, 'workers_var') else 1
        texto, cor, nivel = gerar_analise(
            conhecidas, total,
            self.tem_senha_var.get(),
            self.tem_endereco_var.get(),
            self.tem_deriv_var.get(),
            self.tem_posicao_var.get(),
            workers)

        self.analise_box.config(state='normal')
        self.analise_box.delete('1.0', 'end')
        self.analise_box.tag_config("nivel", foreground=cor, font=('Consolas', 10, 'bold'))
        self.analise_box.tag_config("ok",    foreground="#3fb950")
        self.analise_box.tag_config("warn",  foreground="#f7b731")
        self.analise_box.tag_config("bad",   foreground="#da3633")
        self.analise_box.tag_config("tip",   foreground="#58a6ff")
        self.analise_box.tag_config("normal",foreground="#c9d1d9")

        for linha in texto.split("\n"):
            tag = "normal"
            if "✅" in linha: tag = "ok"
            elif "❌" in linha: tag = "bad"
            elif nivel in linha: tag = "nivel"
            elif "➕" in linha or "💡" in linha: tag = "tip"
            elif "🟢" in linha: tag = "ok"
            elif "🟡" in linha or "⚠" in linha: tag = "warn"
            elif "🟠" in linha or "🔴" in linha or "💀" in linha: tag = "bad"
            self.analise_box.insert('end', linha + "\n", tag)
        self.analise_box.config(state='disabled')

    def _tab_about(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  ℹ  About  ")
        about = """


    ₿  BIP39 Bitcoin Wallet Recovery Tool
    ═══════════════════════════════════════════════════

    Open source tool to recover Bitcoin wallets
    from incomplete BIP39 seed phrases.

    Supports:
    ├─ BIP84  →  Native SegWit addresses (bc1q...)
    ├─ BIP44  →  Legacy addresses (1...)
    └─ BIP49  →  SegWit addresses (3...)

    Recovery modes:
    ├─ 1 missing word (unknown position)
    ├─ 1 missing word (known position)
    ├─ 2 missing words (known positions)
    └─ Multiple partially known words

    Hardware Control:
    ├─ Multi-core CPU support
    ├─ Adjustable worker count
    ├─ Real-time CPU/RAM monitoring
    └─ Safety presets (Safe / Balanced / Maximum)

    ⚠️  SECURITY:
    Always run OFFLINE. Never enter your seed
    on websites or share with anyone.

    ─────────────────────────────────────────────────
    github.com/leonardoramcke/bitcoin-recovery
    MIT License © 2026 leonardoramcke
        """
        tk.Label(tab, text=about, bg='#0d1117', fg='#8b949e',
                 font=('Consolas', 10), justify='left').pack(anchor='w', padx=20, pady=10)

    def _on_mode_change(self):
        if self.mode_var.get() == "2_missing_known":
            self.pos2_spin.config(state='normal')
        else:
            self.pos2_spin.config(state='disabled')

    def _log(self, msg):
        self.log_box.config(state='normal')
        ts = time.strftime('%H:%M:%S')
        self.log_box.insert('end', f"[{ts}] {msg}\n")
        self.log_box.see('end')
        self.log_box.config(state='disabled')
        self.root.update_idletasks()

    def _set_progress(self, done, total):
        pct = min(100, (done / total) * 100)
        self.progress_var.set(pct)
        self.progress_label.config(text=f"{pct:.1f}%")
        self.root.update_idletasks()

    def _export_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text files", "*.txt")],
            title="Save log")
        if path:
            content = self.log_box.get('1.0', 'end')
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo("Exported", f"Log saved to:\n{path}")

    def _validate_inputs(self):
        raw      = self.words_entry.get('1.0', 'end').strip()
        words    = raw.split()
        addr     = self.addr_entry.get().strip()
        passphrase = self.pass_entry.get()
        mode     = self.mode_var.get()
        path     = self.path_var.get().split()[0]

        if not words:
            messagebox.showerror("Error", "Enter the seed words.")
            return None
        if not addr:
            messagebox.showerror("Error", "Enter the target Bitcoin address.")
            return None

        invalid = [w for w in words if w != '?' and w not in WORDLIST]
        if invalid:
            messagebox.showerror("Error",
                f"Words not found in BIP39 wordlist:\n{', '.join(invalid)}\n\nCheck spelling.")
            return None

        return {
            'words':        words,
            'passphrase':   passphrase,
            'address':      addr,
            'path':         path,
            'mode':         mode,
            'addr_limit':   self.addr_limit_var.get(),
            'change_limit': 2 if self.change_var.get() else 1,
            'pos1':         self.pos1_var.get(),
            'pos2':         self.pos2_var.get(),
            'num_workers':  self.workers_var.get(),
        }

    def _start_recovery(self):
        params = self._validate_inputs()
        if not params:
            return
        self.stop_event.clear()
        self.log_box.config(state='normal')
        self.log_box.delete('1.0', 'end')
        self.log_box.config(state='disabled')
        self.progress_var.set(0)
        self.progress_label.config(text="0%")
        self.recovery_thread = threading.Thread(
            target=self._run_recovery, args=(params,), daemon=True)
        self.recovery_thread.start()

    def _stop_recovery(self):
        self.stop_event.set()
        self._log("⛔ Recovery stopped by user.")

    def _run_recovery(self, p):
        mode        = p['mode']
        words       = p['words']
        passphrase  = p['passphrase']
        target      = p['address']
        path        = p['path']
        addr_limit  = p['addr_limit']
        change_limit= p['change_limit']
        workers     = p['num_workers']

        self._log(f"▶ Mode: {mode}")
        self._log(f"  Target address : {target}")
        self._log(f"  Derivation     : {path}")
        self._log(f"  Passphrase     : {'(empty)' if not passphrase else '***'}")
        self._log(f"  Indexes        : {addr_limit} addresses × {change_limit} change")
        self._log(f"  CPU Workers    : {workers} of {CPU_COUNT} cores")
        self._log("─" * 50)

        start  = time.time()
        result = None

        try:
            if mode == "1_missing_unknown":
                if len(words) != 23:
                    self._log(f"❌ Expected 23 words, got {len(words)}")
                    return
                result = mode_one_missing(words, passphrase, target, path,
                                          addr_limit, change_limit, -1,
                                          self._log, self._set_progress,
                                          self.stop_event, workers)

            elif mode == "1_missing_known":
                if len(words) != 23:
                    self._log(f"❌ Expected 23 words, got {len(words)}")
                    return
                pos = p['pos1']
                if pos < 1 or pos > 24:
                    self._log("❌ Position must be between 1 and 24")
                    return
                result = mode_one_missing(words, passphrase, target, path,
                                          addr_limit, change_limit, pos,
                                          self._log, self._set_progress,
                                          self.stop_event, workers)

            elif mode == "2_missing_known":
                if len(words) != 22:
                    self._log(f"❌ Expected 22 words, got {len(words)}")
                    return
                pos1, pos2 = p['pos1'], p['pos2']
                if pos1 < 1 or pos2 < 1 or pos1 >= pos2:
                    self._log("❌ Provide valid positions (pos1 < pos2, both 1–24)")
                    return
                result = mode_two_missing(words, [pos1, pos2], passphrase, target, path,
                                          addr_limit, change_limit,
                                          self._log, self._set_progress,
                                          self.stop_event, workers)

            elif mode == "partial":
                known_mask = [w != '?' for w in words]
                n_unknown  = known_mask.count(False)
                if n_unknown == 0:
                    self._log("❌ No '?' found in the words.")
                    return
                if n_unknown > 3:
                    ans = messagebox.askyesno("Warning",
                        f"{n_unknown} unknown words = {2048**n_unknown:,} combinations.\nThis may take a very long time. Continue?")
                    if not ans:
                        return
                result = mode_partial_known(words, known_mask, passphrase, target, path,
                                            addr_limit, change_limit,
                                            self._log, self._set_progress,
                                            self.stop_event, workers)

        except Exception as e:
            self._log(f"❌ Unexpected error: {e}")
            return

        elapsed = time.time() - start
        self._set_progress(100, 100)

        if result:
            self._log("═" * 50)
            self._log("✅  WALLET FOUND!")
            self._log("═" * 50)
            self._log(f"  Full seed: {' '.join(result['words'])}")
            if 'found_word' in result:
                self._log(f"  Found word: '{result['found_word']}' at position {result['position']}")
            elif 'found_words' in result:
                self._log(f"  Found words: {result['found_words']}")
            self._log(f"  Total time: {elapsed:.1f}s")
            self._log("═" * 50)
            self._log("⚠️  WRITE DOWN THE 24 WORDS ON PAPER NOW!")
            messagebox.showinfo("✅ Found!",
                f"Wallet found!\n\nSeed:\n{' '.join(result['words'])}\n\nWrite it down on paper now!")
        else:
            if not self.stop_event.is_set():
                self._log("═" * 50)
                self._log("❌  Not found.")
                self._log("  Check: passphrase, address, word order, indexes.")
                self._log(f"  Time: {elapsed:.1f}s")
                self._log("═" * 50)


if __name__ == '__main__':
    multiprocessing.freeze_support()
    root = tk.Tk()
    app  = BitcoinRecoveryApp(root)
    root.mainloop()
