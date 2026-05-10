#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         BIP39 BITCOIN WALLET RECOVERY TOOL                  ║
║         by: Canal (github.com/seu-usuario)                  ║
╚══════════════════════════════════════════════════════════════╝

Ferramenta de recuperação de carteiras Bitcoin via seed BIP39.
Suporta múltiplos modos: palavra faltando, posição conhecida,
múltiplas palavras faltando, e força bruta com wordlist.

Derivações suportadas: BIP44, BIP49, BIP84
"""

import hashlib
import time
import sys
import itertools
import threading
import math
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import bech32
from mnemonic import Mnemonic
from bip32utils import BIP32Key, BIP32_HARDEN

# ──────────────────────────────────────────────
#  CORE: Derivação de endereços
# ──────────────────────────────────────────────

MNEMO = Mnemonic('english')
WORDLIST = MNEMO.wordlist

# ──────────────────────────────────────────────
#  ESTIMATIVA DE TEMPO E DIFICULDADE
# ──────────────────────────────────────────────

SPEED_PER_SECOND = 150  # combinações testadas por segundo (PC médio)

def calcular_combinacoes(total_palavras, palavras_conhecidas, posicao_conhecida=False):
    faltando = total_palavras - palavras_conhecidas
    if faltando <= 0:
        return 1
    if faltando == 1 and posicao_conhecida:
        return 2048
    if faltando == 1:
        return total_palavras * 2048
    # Para múltiplas palavras faltando
    return 2048 ** faltando

def formatar_tempo(segundos):
    if segundos < 60:
        return f"~{int(segundos)} segundos"
    elif segundos < 3600:
        return f"~{int(segundos/60)} minutos"
    elif segundos < 86400:
        return f"~{int(segundos/3600)} horas"
    elif segundos < 86400 * 30:
        return f"~{int(segundos/86400)} dias"
    elif segundos < 86400 * 365:
        return f"~{int(segundos/86400/30)} meses"
    elif segundos < 86400 * 365 * 1000:
        return f"~{int(segundos/86400/365)} anos"
    else:
        return "eternidades (inviável)"

def avaliar_viabilidade(combinacoes):
    segundos = combinacoes / SPEED_PER_SECOND
    if segundos < 1800:
        return "FÁCIL", "#3fb950", segundos
    elif segundos < 86400:
        return "MODERADO", "#f7b731", segundos
    elif segundos < 86400*30:
        return "DIFÍCIL", "#e3702a", segundos
    elif segundos < 86400*365:
        return "MUITO DIFÍCIL", "#da3633", segundos
    else:
        return "INVIÁVEL", "#8b0000", segundos

def gerar_analise(palavras_conhecidas, total_palavras, tem_senha, tem_endereco, tem_derivacao, posicao_conhecida):
    faltando = total_palavras - palavras_conhecidas
    combinacoes = calcular_combinacoes(total_palavras, palavras_conhecidas, posicao_conhecida)
    nivel, cor, segundos = avaliar_viabilidade(combinacoes)
    tempo = formatar_tempo(segundos)

    linhas = []
    linhas.append("━━━  ANÁLISE DA SUA SITUAÇÃO  ━━━")
    linhas.append("")
    linhas.append(f"  Seed total        : {total_palavras} palavras")
    linhas.append(f"  Você possui       : {palavras_conhecidas} palavras")
    linhas.append(f"  Faltando          : {faltando} palavra(s)")
    linhas.append(f"  Posição sabida    : {'Sim ✅' if posicao_conhecida else 'Não ❌'}")
    linhas.append(f"  Possui senha      : {'Sim ✅' if tem_senha else 'Não / Não sei ❌'}")
    linhas.append(f"  Possui endereço   : {'Sim ✅' if tem_endereco else 'Não ❌  ← importante!'}")
    linhas.append(f"  Possui derivação  : {'Sim ✅' if tem_derivacao else 'Não ❌'}")
    linhas.append("")
    linhas.append(f"  Combinações       : {combinacoes:,}")
    linhas.append(f"  Tempo estimado    : {tempo}")
    linhas.append(f"  Viabilidade       : {nivel}")
    linhas.append("")

    if faltando == 0:
        linhas.append("  ℹ️  Você tem todas as palavras!")
        linhas.append("  Verifique senha e tipo de derivação.")
    elif faltando == 1 and posicao_conhecida:
        linhas.append("  🟢 Situação ideal. Segundos para resolver.")
    elif faltando == 1:
        linhas.append("  🟢 Ótimo. Uma palavra faltando é totalmente viável.")
        linhas.append("  Lembrar da posição torna ainda mais rápido.")
    elif faltando == 2:
        linhas.append("  🟡 Possível. Pode levar horas.")
        linhas.append("  Se souber as posições, informe — acelera muito.")
    elif faltando == 3:
        linhas.append("  🟠 Difícil. Pode levar dias ou semanas.")
        linhas.append("  Tente lembrar ao menos a posição de alguma delas.")
    elif faltando <= 5:
        linhas.append("  🔴 Muito difícil com PC comum.")
        linhas.append("  Seria necessário hardware especializado (GPUs).")
    else:
        linhas.append("  💀 Com essa quantidade de palavras faltando,")
        linhas.append("  nem supercomputadores resolveriam em tempo útil.")

    linhas.append("")
    linhas.append("  💡 O que ainda pode ajudar:")
    if not tem_endereco:
        linhas.append("   ➕ Endereço público → essencial para confirmar o acerto")
    if not posicao_conhecida and faltando >= 1:
        linhas.append("   ➕ Posição da palavra → reduz combinações drasticamente")
    if not tem_derivacao:
        linhas.append("   ➕ Tipo BIP (84/44/49) → evita testar variações erradas")
    if not tem_senha:
        linhas.append("   ➕ Confirmar se usou senha → elimina uma variável")
    if faltando > 2:
        linhas.append("   ➕ Cada palavra a mais que lembrar divide o tempo por 2048")

    return "\n".join(linhas), cor, nivel


def derive_address(seed_bytes, path_type="bip84", index=0, change=0):
    """Deriva endereço Bitcoin a partir do seed."""
    try:
        master = BIP32Key.fromEntropy(seed_bytes)

        if path_type == "bip84":
            # m/84'/0'/0'/change/index  → bc1q...
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
            # m/44'/0'/0'/change/index  → 1...
            child = (master
                     .ChildKey(44 + BIP32_HARDEN)
                     .ChildKey(0 + BIP32_HARDEN)
                     .ChildKey(0 + BIP32_HARDEN)
                     .ChildKey(change)
                     .ChildKey(index))
            return child.Address()

        elif path_type == "bip49":
            # m/49'/0'/0'/change/index  → 3...
            child = (master
                     .ChildKey(49 + BIP32_HARDEN)
                     .ChildKey(0 + BIP32_HARDEN)
                     .ChildKey(0 + BIP32_HARDEN)
                     .ChildKey(change)
                     .ChildKey(index))
            pubkey = child.PublicKey()
            sha256 = hashlib.sha256(pubkey).digest()
            ripemd = hashlib.new('ripemd160', sha256).digest()
            # P2SH-P2WPKH
            redeem = bytes([0x00, 0x14]) + ripemd
            sha256b = hashlib.sha256(redeem).digest()
            ripemd2 = hashlib.new('ripemd160', sha256b).digest()
            prefix = bytes([0x05])
            checksum = hashlib.sha256(hashlib.sha256(prefix + ripemd2).digest()).digest()[:4]
            import base58
            return base58.b58encode(prefix + ripemd2 + checksum).decode()

    except Exception:
        return None


def check_mnemonic(words, passphrase, target_address, path_type, addr_limit, change_limit):
    """Verifica se o mnemonic gera o endereço alvo."""
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
#  MODOS DE RECUPERAÇÃO
# ──────────────────────────────────────────────

def mode_one_missing(words_23, passphrase, target, path, addr_limit, change_limit,
                     known_position, log_fn, progress_fn, stop_event):
    """
    Modo 1: 1 palavra faltando.
    Se known_position == -1, testa todas as 24 posições.
    """
    positions = [known_position - 1] if known_position > 0 else range(24)
    total = len(list(positions)) * 2048
    done = 0
    positions = [known_position - 1] if known_position > 0 else range(24)

    for pos in positions:
        if stop_event.is_set():
            return None
        log_fn(f"⟳ Testando posição {pos + 1}/24...")
        for word in WORDLIST:
            if stop_event.is_set():
                return None
            candidate = words_23[:pos] + [word] + words_23[pos:]
            done += 1
            progress_fn(done, total)
            if check_mnemonic(candidate, passphrase, target, path, addr_limit, change_limit):
                return {'words': candidate, 'found_word': word, 'position': pos + 1}
    return None


def mode_two_missing(words_22, missing_positions, passphrase, target, path,
                     addr_limit, change_limit, log_fn, progress_fn, stop_event):
    """
    Modo 2: 2 palavras faltando em posições conhecidas.
    Testa 2048² = ~4M combinações.
    """
    total = 2048 * 2048
    done = 0
    p1, p2 = missing_positions[0] - 1, missing_positions[1] - 1

    for w1 in WORDLIST:
        if stop_event.is_set():
            return None
        log_fn(f"⟳ Primeira palavra: '{w1}'...")
        for w2 in WORDLIST:
            if stop_event.is_set():
                return None
            candidate = list(words_22)
            candidate.insert(p1, w1)
            candidate.insert(p2 + 1, w2)
            done += 1
            progress_fn(done, total)
            if check_mnemonic(candidate, passphrase, target, path, addr_limit, change_limit):
                return {'words': candidate, 'found_words': [w1, w2], 'positions': [p1+1, p2+1]}
    return None


def mode_partial_known(partial_words, known_mask, passphrase, target, path,
                       addr_limit, change_limit, log_fn, progress_fn, stop_event):
    """
    Modo 3: Algumas palavras conhecidas, outras não (marcadas com '?').
    known_mask: lista de True/False indicando quais posições são conhecidas.
    """
    unknown_positions = [i for i, known in enumerate(known_mask) if not known]
    n_unknown = len(unknown_positions)
    total = 2048 ** n_unknown
    done = 0

    log_fn(f"⟳ {n_unknown} palavras desconhecidas → {total:,} combinações")
    if total > 10_000_000:
        log_fn(f"⚠️  Muitas combinações ({total:,}). Pode demorar muito.")

    for combo in itertools.product(WORDLIST, repeat=n_unknown):
        if stop_event.is_set():
            return None
        candidate = list(partial_words)
        for i, pos in enumerate(unknown_positions):
            candidate[pos] = combo[i]
        done += 1
        if done % 10000 == 0:
            progress_fn(done, total)
            log_fn(f"⟳ {done:,}/{total:,} testadas...")
        if check_mnemonic(candidate, passphrase, target, path, addr_limit, change_limit):
            return {'words': candidate, 'found_words': list(combo), 'positions': unknown_positions}
    return None


# ──────────────────────────────────────────────
#  INTERFACE GRÁFICA
# ──────────────────────────────────────────────

class BitcoinRecoveryApp:
    def __init__(self, root):
        self.root = root
        self.root.title("BIP39 Bitcoin Wallet Recovery Tool")
        self.root.geometry("900x750")
        self.root.resizable(True, True)
        self.root.configure(bg="#0d1117")

        self.stop_event = threading.Event()
        self.recovery_thread = None

        self._setup_styles()
        self._build_ui()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

        style.configure('TNotebook', background='#0d1117', borderwidth=0)
        style.configure('TNotebook.Tab',
                        background='#161b22', foreground='#8b949e',
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

        style.configure('TCombobox',
                        fieldbackground='#161b22', background='#161b22',
                        foreground='#c9d1d9', selectbackground='#1f2937',
                        font=('Consolas', 10))

        style.configure('TCheckbutton', background='#0d1117',
                        foreground='#c9d1d9', font=('Consolas', 10))

        style.configure('Horizontal.TProgressbar',
                        background='#f7b731', troughcolor='#161b22',
                        borderwidth=0, lightcolor='#f7b731', darkcolor='#f7b731')

        style.configure('TSpinbox', fieldbackground='#161b22',
                        foreground='#c9d1d9', font=('Consolas', 10))

    def _entry(self, parent, show=None, width=40):
        e = tk.Entry(parent, show=show, width=width,
                     bg='#161b22', fg='#c9d1d9',
                     insertbackground='#f7b731',
                     relief='flat', bd=6,
                     font=('Consolas', 10),
                     highlightthickness=1,
                     highlightcolor='#f7b731',
                     highlightbackground='#30363d')
        return e

    def _btn(self, parent, text, command, color='#f7b731', fg='#0d1117'):
        return tk.Button(parent, text=text, command=command,
                         bg=color, fg=fg, activebackground='#e5a820',
                         relief='flat', bd=0, padx=20, pady=8,
                         font=('Consolas', 10, 'bold'), cursor='hand2')

    def _build_ui(self):
        # ── Header ──
        header = tk.Frame(self.root, bg='#0d1117')
        header.pack(fill='x', padx=20, pady=(16, 0))

        tk.Label(header, text="₿ BIP39 Wallet Recovery",
                 bg='#0d1117', fg='#f7b731',
                 font=('Consolas', 18, 'bold')).pack(side='left')

        tk.Label(header,
                 text="BIP44 · BIP49 · BIP84  |  1 ou 2 palavras faltando  |  Posição desconhecida",
                 bg='#0d1117', fg='#484f58',
                 font=('Consolas', 9)).pack(side='left', padx=16, pady=4)

        ttk.Separator(self.root, orient='horizontal').pack(fill='x', padx=20, pady=10)

        # ── Notebook ──
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill='both', expand=True, padx=20, pady=0)

        self._tab_recovery()
        self._tab_analise()
        self._tab_about()

        # ── Log / Progress ──
        bottom = tk.Frame(self.root, bg='#0d1117')
        bottom.pack(fill='both', padx=20, pady=(8, 16))

        log_frame = ttk.LabelFrame(bottom, text="  LOG  ")
        log_frame.pack(fill='both', expand=True)

        self.log_box = scrolledtext.ScrolledText(
            log_frame, height=10, bg='#010409', fg='#3fb950',
            font=('Consolas', 9), relief='flat', bd=4,
            insertbackground='#3fb950', state='disabled')
        self.log_box.pack(fill='both', expand=True, padx=4, pady=4)

        prog_frame = tk.Frame(bottom, bg='#0d1117')
        prog_frame.pack(fill='x', pady=(6, 0))

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(prog_frame, variable=self.progress_var,
                                            maximum=100, length=600,
                                            style='Horizontal.TProgressbar')
        self.progress_bar.pack(side='left', fill='x', expand=True)

        self.progress_label = tk.Label(prog_frame, text="0%",
                                       bg='#0d1117', fg='#8b949e',
                                       font=('Consolas', 9), width=8)
        self.progress_label.pack(side='left', padx=6)

        # ── Botões ──
        btn_frame = tk.Frame(self.root, bg='#0d1117')
        btn_frame.pack(pady=(0, 16))

        self._btn(btn_frame, "▶  INICIAR RECUPERAÇÃO", self._start_recovery).pack(side='left', padx=8)
        self._btn(btn_frame, "■  PARAR", self._stop_recovery,
                  color='#da3633', fg='white').pack(side='left', padx=8)
        self._btn(btn_frame, "⎘  EXPORTAR LOG", self._export_log,
                  color='#238636', fg='white').pack(side='left', padx=8)

    def _tab_recovery(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  🔑  Recuperação  ")

        # ── Modo ──
        mode_frame = ttk.LabelFrame(tab, text="  MODO DE RECUPERAÇÃO  ")
        mode_frame.pack(fill='x', padx=12, pady=(12, 6))

        self.mode_var = tk.StringVar(value="1_missing_unknown")
        modes = [
            ("1 palavra faltando — posição DESCONHECIDA (testa todas)", "1_missing_unknown"),
            ("1 palavra faltando — posição CONHECIDA", "1_missing_known"),
            ("2 palavras faltando — posições CONHECIDAS", "2_missing_known"),
            ("Múltiplas palavras com '?' nas desconhecidas", "partial"),
        ]
        for text, val in modes:
            tk.Radiobutton(mode_frame, text=text, variable=self.mode_var, value=val,
                           bg='#0d1117', fg='#c9d1d9', selectcolor='#161b22',
                           activebackground='#0d1117', activeforeground='#f7b731',
                           font=('Consolas', 10),
                           command=self._on_mode_change).pack(anchor='w', padx=12, pady=2)

        # ── Palavras ──
        words_frame = ttk.LabelFrame(tab, text="  PALAVRAS SEED  ")
        words_frame.pack(fill='x', padx=12, pady=6)

        tk.Label(words_frame,
                 text="Cole suas palavras separadas por espaço. Use '?' nas posições desconhecidas (modo parcial):",
                 bg='#0d1117', fg='#8b949e', font=('Consolas', 9)).pack(anchor='w', padx=8, pady=(4, 0))

        self.words_entry = tk.Text(words_frame, height=3, bg='#161b22', fg='#c9d1d9',
                                   font=('Consolas', 11), relief='flat', bd=6,
                                   insertbackground='#f7b731',
                                   highlightthickness=1,
                                   highlightcolor='#f7b731',
                                   highlightbackground='#30363d')
        self.words_entry.pack(fill='x', padx=8, pady=6)

        # ── Posições ──
        pos_frame = tk.Frame(tab, bg='#0d1117')
        pos_frame.pack(fill='x', padx=12, pady=2)

        tk.Label(pos_frame, text="Posição 1ª palavra faltando (0 = desconhecida):",
                 bg='#0d1117', fg='#8b949e', font=('Consolas', 9)).pack(side='left')
        self.pos1_var = tk.IntVar(value=0)
        tk.Spinbox(pos_frame, from_=0, to=24, textvariable=self.pos1_var,
                   width=4, bg='#161b22', fg='#c9d1d9', font=('Consolas', 10),
                   buttonbackground='#1f2937').pack(side='left', padx=6)

        tk.Label(pos_frame, text="Posição 2ª palavra faltando:",
                 bg='#0d1117', fg='#8b949e', font=('Consolas', 9)).pack(side='left', padx=(20, 0))
        self.pos2_var = tk.IntVar(value=0)
        self.pos2_spin = tk.Spinbox(pos_frame, from_=0, to=24, textvariable=self.pos2_var,
                                    width=4, bg='#161b22', fg='#c9d1d9', font=('Consolas', 10),
                                    buttonbackground='#1f2937', state='disabled')
        self.pos2_spin.pack(side='left', padx=6)

        # ── Credenciais ──
        cred_frame = ttk.LabelFrame(tab, text="  CREDENCIAIS  ")
        cred_frame.pack(fill='x', padx=12, pady=6)

        row1 = tk.Frame(cred_frame, bg='#0d1117')
        row1.pack(fill='x', padx=8, pady=4)
        tk.Label(row1, text="Passphrase (senha):", width=22, anchor='w').pack(side='left')
        self.pass_entry = self._entry(row1, show='•', width=30)
        self.pass_entry.pack(side='left', padx=4)

        self.show_pass = tk.BooleanVar()
        tk.Checkbutton(row1, text="mostrar", variable=self.show_pass,
                       bg='#0d1117', fg='#8b949e', selectcolor='#161b22',
                       activebackground='#0d1117', font=('Consolas', 9),
                       command=lambda: self.pass_entry.config(
                           show='' if self.show_pass.get() else '•')).pack(side='left')

        row2 = tk.Frame(cred_frame, bg='#0d1117')
        row2.pack(fill='x', padx=8, pady=4)
        tk.Label(row2, text="Endereço Bitcoin alvo:", width=22, anchor='w').pack(side='left')
        self.addr_entry = self._entry(row2, width=50)
        self.addr_entry.pack(side='left', padx=4)

        row3 = tk.Frame(cred_frame, bg='#0d1117')
        row3.pack(fill='x', padx=8, pady=4)
        tk.Label(row3, text="Tipo de endereço:", width=22, anchor='w').pack(side='left')
        self.path_var = tk.StringVar(value="bip84")
        ttk.Combobox(row3, textvariable=self.path_var, width=20,
                     values=["bip84 (bc1q...)", "bip44 (1...)", "bip49 (3...)"],
                     state='readonly').pack(side='left', padx=4)

        tk.Label(row3, text="Índices (endereços):", padx=12).pack(side='left')
        self.addr_limit_var = tk.IntVar(value=10)
        tk.Spinbox(row3, from_=1, to=50, textvariable=self.addr_limit_var,
                   width=4, bg='#161b22', fg='#c9d1d9', font=('Consolas', 10),
                   buttonbackground='#1f2937').pack(side='left')

        tk.Label(row3, text="Change (0/1):", padx=8).pack(side='left')
        self.change_var = tk.BooleanVar(value=False)
        tk.Checkbutton(row3, text="testar change também",
                       variable=self.change_var,
                       bg='#0d1117', fg='#8b949e', selectcolor='#161b22',
                       activebackground='#0d1117', font=('Consolas', 9)).pack(side='left')

    def _tab_analise(self):
        """Aba de análise inteligente de viabilidade."""
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  📊  Análise de Viabilidade  ")

        top = tk.Frame(tab, bg='#0d1117')
        top.pack(fill='x', padx=12, pady=(12, 6))

        # ── Controles da análise ──
        ctrl = ttk.LabelFrame(top, text="  INFORME O QUE VOCÊ POSSUI  ")
        ctrl.pack(fill='x')

        # Linha 1: tamanho do seed e palavras conhecidas
        r1 = tk.Frame(ctrl, bg='#0d1117')
        r1.pack(fill='x', padx=12, pady=6)

        tk.Label(r1, text="Tamanho do seed:", width=22, anchor='w').pack(side='left')
        self.seed_size_var = tk.IntVar(value=24)
        ttk.Combobox(r1, textvariable=self.seed_size_var, width=6,
                     values=[12, 15, 18, 21, 24], state='readonly').pack(side='left', padx=4)
        tk.Label(r1, text="palavras no total", bg='#0d1117', fg='#8b949e',
                 font=('Consolas', 9)).pack(side='left', padx=6)

        r2 = tk.Frame(ctrl, bg='#0d1117')
        r2.pack(fill='x', padx=12, pady=4)
        tk.Label(r2, text="Quantas você tem:", width=22, anchor='w').pack(side='left')
        self.known_words_var = tk.IntVar(value=23)
        tk.Spinbox(r2, from_=0, to=24, textvariable=self.known_words_var,
                   width=4, bg='#161b22', fg='#c9d1d9', font=('Consolas', 10),
                   buttonbackground='#1f2937').pack(side='left', padx=4)
        tk.Label(r2, text="palavras", bg='#0d1117', fg='#8b949e',
                 font=('Consolas', 9)).pack(side='left', padx=6)

        # Linha 2: checkboxes do que possui
        r3 = tk.Frame(ctrl, bg='#0d1117')
        r3.pack(fill='x', padx=12, pady=4)

        self.tem_posicao_var = tk.BooleanVar(value=False)
        self.tem_senha_var   = tk.BooleanVar(value=True)
        self.tem_endereco_var= tk.BooleanVar(value=True)
        self.tem_deriv_var   = tk.BooleanVar(value=True)

        def cb(parent, text, var):
            tk.Checkbutton(parent, text=text, variable=var,
                           bg='#0d1117', fg='#c9d1d9', selectcolor='#161b22',
                           activebackground='#0d1117', activeforeground='#f7b731',
                           font=('Consolas', 10)).pack(side='left', padx=10)

        cb(r3, "Sei a posição da palavra faltante", self.tem_posicao_var)
        cb(r3, "Tenho a senha (passphrase)", self.tem_senha_var)

        r4 = tk.Frame(ctrl, bg='#0d1117')
        r4.pack(fill='x', padx=12, pady=(2, 8))
        cb(r4, "Tenho o endereço público (bc1q...)", self.tem_endereco_var)
        cb(r4, "Sei o tipo de derivação (BIP)", self.tem_deriv_var)

        self._btn(ctrl, "  CALCULAR ANÁLISE  ", self._calcular_analise,
                  color='#1f6feb', fg='white').pack(pady=(0, 10))

        # ── Resultado ──
        result_frame = ttk.LabelFrame(tab, text="  RESULTADO  ")
        result_frame.pack(fill='both', expand=True, padx=12, pady=6)

        self.analise_box = scrolledtext.ScrolledText(
            result_frame, height=18, bg='#010409', fg='#c9d1d9',
            font=('Consolas', 10), relief='flat', bd=4,
            insertbackground='#f7b731', state='disabled')
        self.analise_box.pack(fill='both', expand=True, padx=4, pady=4)

        # Mostrar análise inicial
        self.root.after(300, self._calcular_analise)

    def _calcular_analise(self):
        total = self.seed_size_var.get()
        conhecidas = self.known_words_var.get()
        tem_posicao = self.tem_posicao_var.get()
        tem_senha   = self.tem_senha_var.get()
        tem_endereco= self.tem_endereco_var.get()
        tem_deriv   = self.tem_deriv_var.get()

        if conhecidas > total:
            conhecidas = total

        texto, cor, nivel = gerar_analise(
            conhecidas, total, tem_senha, tem_endereco, tem_deriv, tem_posicao)

        self.analise_box.config(state='normal')
        self.analise_box.delete('1.0', 'end')

        # Colorir por nível
        cores = {
            "FÁCIL":        "#3fb950",
            "MODERADO":     "#f7b731",
            "DIFÍCIL":      "#e3702a",
            "MUITO DIFÍCIL":"#da3633",
            "INVIÁVEL":     "#ff6b6b",
        }
        self.analise_box.tag_config("nivel", foreground=cor, font=('Consolas', 10, 'bold'))
        self.analise_box.tag_config("ok",    foreground="#3fb950")
        self.analise_box.tag_config("warn",  foreground="#f7b731")
        self.analise_box.tag_config("bad",   foreground="#da3633")
        self.analise_box.tag_config("tip",   foreground="#58a6ff")
        self.analise_box.tag_config("normal",foreground="#c9d1d9")

        for linha in texto.split("\n"):
            tag = "normal"
            if "✅" in linha:
                tag = "ok"
            elif "❌" in linha:
                tag = "bad"
            elif nivel in linha:
                tag = "nivel"
            elif "➕" in linha or "💡" in linha:
                tag = "tip"
            elif "🟢" in linha:
                tag = "ok"
            elif "🟡" in linha or "⚠" in linha:
                tag = "warn"
            elif "🟠" in linha or "🔴" in linha or "💀" in linha:
                tag = "bad"
            self.analise_box.insert('end', linha + "\n", tag)

        self.analise_box.config(state='disabled')

    def _tab_about(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  ℹ  Sobre  ")

        about = """


    ₿  BIP39 Bitcoin Wallet Recovery Tool
    ═══════════════════════════════════════════════════

    Ferramenta open source para recuperação de carteiras
    Bitcoin a partir de seeds BIP39 incompletas.

    Suporta:
    ├─ BIP84  →  Endereços Native SegWit (bc1q...)
    ├─ BIP44  →  Endereços Legacy (1...)
    └─ BIP49  →  Endereços SegWit (3...)

    Modos de recuperação:
    ├─ Qualquer quantidade de palavras faltando
    ├─ Posição conhecida ou desconhecida
    ├─ Com ou sem senha (passphrase)
    └─ Análise inteligente de viabilidade

    ⚠️  SEGURANÇA:
    Execute SEMPRE offline. Nunca insira sua seed
    em sites ou compartilhe com terceiros.

    ─────────────────────────────────────────────────
    Libs: mnemonic · bip32utils · bech32 · tkinter
    Python 3.8+
        """
        tk.Label(tab, text=about, bg='#0d1117', fg='#8b949e',
                 font=('Consolas', 10), justify='left').pack(anchor='w', padx=20, pady=10)

    def _on_mode_change(self):
        mode = self.mode_var.get()
        if mode == "2_missing_known":
            self.pos2_spin.config(state='normal')
        else:
            self.pos2_spin.config(state='disabled')

    # ── Logging ──

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
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            title="Salvar log")
        if path:
            content = self.log_box.get('1.0', 'end')
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo("Exportado", f"Log salvo em:\n{path}")

    # ── Validação ──

    def _validate_inputs(self):
        raw = self.words_entry.get('1.0', 'end').strip()
        words = raw.split()
        addr = self.addr_entry.get().strip()
        passphrase = self.pass_entry.get()
        mode = self.mode_var.get()
        path = self.path_var.get().split()[0]

        if not words:
            messagebox.showerror("Erro", "Insira as palavras seed.")
            return None

        if not addr:
            messagebox.showerror("Erro", "Insira o endereço Bitcoin alvo.")
            return None

        # Valida palavras (exceto '?')
        invalid = [w for w in words if w != '?' and w not in WORDLIST]
        if invalid:
            messagebox.showerror("Erro",
                f"Palavras não encontradas na wordlist BIP39:\n{', '.join(invalid)}\n\nVerifique a grafia.")
            return None

        addr_limit = self.addr_limit_var.get()
        change_limit = 2 if self.change_var.get() else 1

        return {
            'words': words,
            'passphrase': passphrase,
            'address': addr,
            'path': path,
            'mode': mode,
            'addr_limit': addr_limit,
            'change_limit': change_limit,
            'pos1': self.pos1_var.get(),
            'pos2': self.pos2_var.get(),
        }

    # ── Start / Stop ──

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
        self._log("⛔ Recuperação interrompida pelo usuário.")

    def _run_recovery(self, p):
        mode = p['mode']
        words = p['words']
        passphrase = p['passphrase']
        target = p['address']
        path = p['path']
        addr_limit = p['addr_limit']
        change_limit = p['change_limit']

        self._log(f"▶ Iniciando modo: {mode}")
        self._log(f"  Endereço alvo : {target}")
        self._log(f"  Derivação     : {path}")
        self._log(f"  Passphrase    : {'(vazia)' if not passphrase else '***'}")
        self._log(f"  Índices       : {addr_limit} endereços × {change_limit} change")
        self._log("─" * 50)

        start = time.time()
        result = None

        try:
            if mode == "1_missing_unknown":
                if len(words) != 23:
                    self._log(f"❌ Esperado 23 palavras, recebido {len(words)}")
                    return
                result = mode_one_missing(words, passphrase, target, path,
                                          addr_limit, change_limit, -1,
                                          self._log, self._set_progress, self.stop_event)

            elif mode == "1_missing_known":
                if len(words) != 23:
                    self._log(f"❌ Esperado 23 palavras, recebido {len(words)}")
                    return
                pos = p['pos1']
                if pos < 1 or pos > 24:
                    self._log("❌ Posição deve ser entre 1 e 24")
                    return
                result = mode_one_missing(words, passphrase, target, path,
                                          addr_limit, change_limit, pos,
                                          self._log, self._set_progress, self.stop_event)

            elif mode == "2_missing_known":
                if len(words) != 22:
                    self._log(f"❌ Esperado 22 palavras, recebido {len(words)}")
                    return
                pos1, pos2 = p['pos1'], p['pos2']
                if pos1 < 1 or pos2 < 1 or pos1 >= pos2:
                    self._log("❌ Informe posições válidas (pos1 < pos2, ambas entre 1 e 24)")
                    return
                result = mode_two_missing(words, [pos1, pos2], passphrase, target, path,
                                          addr_limit, change_limit,
                                          self._log, self._set_progress, self.stop_event)

            elif mode == "partial":
                known_mask = [w != '?' for w in words]
                n_unknown = known_mask.count(False)
                if n_unknown == 0:
                    self._log("❌ Nenhum '?' encontrado nas palavras.")
                    return
                if n_unknown > 3:
                    ans = messagebox.askyesno("Aviso",
                        f"{n_unknown} palavras desconhecidas = {2048**n_unknown:,} combinações.\nIsso pode demorar muito. Continuar?")
                    if not ans:
                        return
                result = mode_partial_known(words, known_mask, passphrase, target, path,
                                            addr_limit, change_limit,
                                            self._log, self._set_progress, self.stop_event)

        except Exception as e:
            self._log(f"❌ Erro inesperado: {e}")
            return

        elapsed = time.time() - start
        self._set_progress(100, 100)

        if result:
            self._log("═" * 50)
            self._log("✅  CARTEIRA ENCONTRADA!")
            self._log("═" * 50)
            self._log(f"  Seed completo: {' '.join(result['words'])}")
            if 'found_word' in result:
                self._log(f"  Palavra encontrada: '{result['found_word']}' na posição {result['position']}")
            elif 'found_words' in result:
                self._log(f"  Palavras encontradas: {result['found_words']}")
            self._log(f"  Tempo total: {elapsed:.1f}s")
            self._log("═" * 50)
            self._log("⚠️  ANOTE AS 24 PALAVRAS EM PAPEL AGORA!")

            messagebox.showinfo("✅ Encontrado!",
                f"Wallet encontrada!\n\nSeed:\n{' '.join(result['words'])}\n\nAnote agora em papel!")
        else:
            if not self.stop_event.is_set():
                self._log("═" * 50)
                self._log("❌  Não encontrado.")
                self._log("  Verifique: senha, endereço, ordem das palavras, índices.")
                self._log(f"  Tempo: {elapsed:.1f}s")
                self._log("═" * 50)


# ──────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────

if __name__ == '__main__':
    root = tk.Tk()
    app = BitcoinRecoveryApp(root)
    root.mainloop()
