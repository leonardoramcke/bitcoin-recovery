#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         BIP39 BITCOIN WALLET RECOVERY TOOL v4.5             ║
║         by: leonardoramcke (github.com/leonardoramcke)       ║
║         MIT License © 2026                                   ║
╠══════════════════════════════════════════════════════════════╣
║ NOVO v4.5 — controle de prioridade (sugerido por outra IA,   ║
║ avaliado e implementado com ajustes p/ não prejudicar o SO):  ║
║  ✅ Prioridade dos processos configurável (Normal/Baixa/      ║
║     Muito baixa) — via psutil.nice(), aba Controle de HW      ║
║  ✅ Boost automático opcional: sobe pra Normal só quando o    ║
║     PC fica 5min sem input (Windows, via GetLastInputInfo)    ║
║     e volta ao configurado assim que você mexe no PC          ║
║  ✅ Hashrate (combos/s) agora também na barra superior        ║
║  ⚠️  NÃO implementado agora (fora de escopo): reescrita do    ║
║     loop interno em Rust/C — ganho real, mas exige toolchain  ║
║     de build cruzado p/ Windows; hashlib.pbkdf2_hmac já é C   ║
╠══════════════════════════════════════════════════════════════╣
║ FIX v4.5 — RAM e estimativa de tempo:                        ║
║  ✅ chunk_size sem teto virava dezenas de milhões de tuplas   ║
║     por pacote (3 palavras ausentes ≈ 71 milhões!) — RAM      ║
║     estourava. Agora limitado a 500–4000 por chunk.           ║
║  ✅ Divisor de checksum era fixo em 2048 (11 bits) mas o      ║
║     checksum real do BIP39 é seed_size/3 bits — para 24       ║
║     palavras são 8 bits (÷256), não 11 (÷2048). Isso fazia    ║
║     o tempo estimado ficar ~8x menor que o real. Corrigido    ║
║     e validado empiricamente contra mnemo.check().            ║
╠══════════════════════════════════════════════════════════════╣
║ OTIMIZAÇÃO v4.5 — motor de derivação ~11x mais rápido:       ║
║  ✅ bip32utils (Python puro) → coincurve (libsecp256k1 em C) ║
║     ver fast_bip32.py — validado contra vetores BIP32 e      ║
║     contra bip32utils (mesmos endereços bip84/44/49)         ║
║  ✅ Chave de CONTA cacheada 1x por candidato (derive_account)║
║     — antes recalculava m/purpose'/0'/0' a cada índice/change║
║  ✅ hash160 direto via hashlib, sem overhead de objeto Key   ║
║                                                              ║
║ FIX v4.5 — WINDOWS "Não está respondendo":                  ║
║  ✅ Pool criado em processo separado via mp.Process          ║
║     (no Windows, Pool dentro de thread trava a GUI)          ║
║  ✅ Comunicação GUI ↔ motor via mp.Queue (IPC seguro)        ║
║  ✅ Stop via mp.Event compartilhado entre processos          ║
║  ✅ GUI nunca bloqueia — after() para tudo                   ║
║                                                              ║
║ OTIMIZAÇÕES v3.0 mantidas:                                   ║
║  ✅ Globais MNEMO/WORDLIST removidas do topo                 ║
║  ✅ hw_monitor e log via root.after() — thread-safe          ║
║  ✅ islice nos chunks, template como tuple                   ║
║  ✅ rapidfuzz opcional                                       ║
║  ✅ Cola inteligente Ctrl+V com feedback visual              ║
╚══════════════════════════════════════════════════════════════╝
"""

import hashlib, time, sys, os, itertools, threading, math
import multiprocessing as mp
import queue as _queue
import re
import psutil, tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from multiprocessing import Pool, cpu_count
from itertools import islice
import bech32
from mnemonic import Mnemonic
from fast_bip32 import FastBIP32, HARDEN as BIP32_HARDEN

# ── v4.5: Prioridade de processo + detecção de ociosidade ─────
# Objetivo: deixar o USUÁRIO decidir se quer que os workers rodem
# em prioridade baixa (PC continua leve pra outras tarefas) ou
# normal (mais rápido, mas compete por CPU com o resto do sistema).
IS_WINDOWS = sys.platform.startswith('win')

def _apply_process_priority(level: str):
    """Roda DENTRO do processo worker (via initializer do Pool).
    level: 'normal' | 'below' | 'idle' (do mais rápido pro mais leve)."""
    try:
        p = psutil.Process(os.getpid())
        if IS_WINDOWS:
            mapping = {
                'normal': psutil.NORMAL_PRIORITY_CLASS,
                'below':  psutil.BELOW_NORMAL_PRIORITY_CLASS,
                'idle':   psutil.IDLE_PRIORITY_CLASS,
            }
        else:
            # os.nice: 0 = normal, valores maiores = mais gentil com o SO
            mapping = {'normal': 0, 'below': 10, 'idle': 19}
        p.nice(mapping.get(level, mapping['below']))
    except Exception:
        pass  # nunca deixar isso derrubar o worker

def get_idle_seconds():
    """Segundos desde a última interação do usuário (mouse/teclado).
    Só funciona no Windows (via GetLastInputInfo). Retorna None em outros SOs
    — nesse caso o recurso de 'boost automático' fica desabilitado na UI."""
    if not IS_WINDOWS:
        return None
    try:
        import ctypes
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
        info = LASTINPUTINFO()
        info.cbSize = ctypes.sizeof(LASTINPUTINFO)
        ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info))
        millis = ctypes.windll.kernel32.GetTickCount() - info.dwTime
        return millis / 1000.0
    except Exception:
        return None

# ── rapidfuzz opcional ───────────────────────────────────────
try:
    from rapidfuzz.distance import Levenshtein as _lev
    _USE_RAPIDFUZZ = True
except ImportError:
    _USE_RAPIDFUZZ = False

CPU_COUNT = cpu_count()

# ── Base58Check ──────────────────────────────────────────────
_B58 = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def _b58encode(payload):
    n = int.from_bytes(payload, 'big')
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(_B58[r])
    res.extend([_B58[0]] * (len(payload) - len(payload.lstrip(b'\x00'))))
    return bytes(reversed(res)).decode('ascii')

# ── Wordlist sob demanda ─────────────────────────────────────
def _get_wordlist():
    return Mnemonic('english').wordlist

# ── Levenshtein ──────────────────────────────────────────────
def _levenshtein_py(a, b):
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
    wl = _get_wordlist()
    w = word.lower()
    if _USE_RAPIDFUZZ:
        return [x for x in wl if _lev.distance(w, x) <= max_dist]
    scored = [(_levenshtein_py(w, x), x) for x in wl]
    scored.sort()
    return [x for d, x in scored if d <= max_dist]

# ── BIP39 checksum ───────────────────────────────────────────
def valid_last_words(words_prefix):
    mnemo = Mnemonic('english')
    return [w for w in mnemo.wordlist if mnemo.check(' '.join(words_prefix + [w]))]

# ── Tempo / viabilidade ──────────────────────────────────────
# FIX v4.5: um valor fixo (200, depois 3500...) nunca vai bater certo
# pra todo mundo — cada PC tem uma velocidade real diferente. Em vez
# de chutar, o app mede a velocidade REAL do hardware do usuário
# rodando um lote pequeno de PBKDF2+derivação real (~0,3s) na primeira
# vez que é necessário, e reaproveita o resultado depois.
_SPEED_CACHE = None

def calibrate_speed_per_core(n_samples=150):
    """Mede combos/s/núcleo REAIS rodando PBKDF2+derivação de verdade
    no hardware atual. Cacheado após a 1ª chamada (~0,2–0,4s de custo)."""
    global _SPEED_CACHE
    if _SPEED_CACHE is not None:
        return _SPEED_CACHE
    phrase = "abandon " * 23 + "about"
    phrase = phrase.strip()
    t0 = time.time()
    for _ in range(n_samples):
        seed = hashlib.pbkdf2_hmac('sha512', phrase.encode(), b'mnemonic', 2048)
        master = FastBIP32.from_seed(seed)
        account = derive_account(master, 'bip84')
        derive_address_from_account(account, 'bip84', 0, 0)
    elapsed = max(1e-6, time.time() - t0)
    _SPEED_CACHE = max(50, n_samples / elapsed)  # nunca deixa ir a 0
    return _SPEED_CACHE

SPEED_PER_CORE = 500  # fallback só até a 1ª calibração acontecer

def checksum_divisor(seed_size):
    """
    FIX v4.5: o app assumia 1/2048 de aproveitamento após o filtro de
    checksum, mas o checksum do BIP39 tem seed_size/3 bits (4 bits p/
    12 palavras, 8 bits p/ 24 palavras) — não 11 bits (2048) fixos.
    Para 24 palavras o divisor real é 256, não 2048 (subestimava o
    tempo restante em 8x). Validado empiricamente contra mnemo.check().
    """
    checksum_bits = max(1, seed_size // 3)
    return 2 ** checksum_bits

def fmt_time(s):
    if s < 60:          return f"~{int(s)} segundos"
    if s < 3600:        return f"~{int(s/60)} minutos"
    if s < 86400:       return f"~{int(s/3600)} horas"
    if s < 2592000:     return f"~{int(s/86400)} dias"
    if s < 31536000:    return f"~{int(s/2592000)} meses"
    if s < 31536000000: return f"~{int(s/31536000)} anos"
    return "eternidade (inviável)"

def feasibility(combos, workers=1):
    speed = calibrate_speed_per_core()
    s = combos / max(1, speed * workers)
    if s < 1800:     return "FÁCIL",        "#3fb950", s
    if s < 86400:    return "MODERADO",     "#f7b731", s
    if s < 2592000:  return "DIFÍCIL",      "#e3702a", s
    if s < 31536000: return "MUITO DIFÍCIL","#da3633", s
    return "INVIÁVEL", "#8b0000", s

# ── Derivação de endereço (v4 — coincurve) ───────────────────
_PURPOSE = {"bip84": 84, "bip44": 44, "bip49": 49}

def _hash160(b):
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()

def derive_account(master, path_type="bip84"):
    """
    Deriva a chave da CONTA (m/purpose'/0'/0') UMA VEZ por candidato.
    Isso evita recalcular os 3 primeiros níveis hardened (os mais caros,
    pois exigem tweak da chave privada) para cada combinação de
    change/index testada em seguida — grande ganho quando addr_limit
    e change_limit são > 1.
    """
    purpose = _PURPOSE.get(path_type, 84)
    return master.child(purpose + BIP32_HARDEN).child(0 + BIP32_HARDEN).child(0 + BIP32_HARDEN)

def derive_address_from_account(account, path_type="bip84", index=0, change=0):
    try:
        child = account.child(change).child(index)
        pub = child.public_key()  # 33 bytes comprimidos
        if path_type == "bip84":
            h = _hash160(pub)
            return bech32.encode('bc', 0, h)
        elif path_type == "bip44":
            h = _hash160(pub)
            pre = bytes([0x00])
            chk = hashlib.sha256(hashlib.sha256(pre + h).digest()).digest()[:4]
            return _b58encode(pre + h + chk)
        elif path_type == "bip49":
            h = _hash160(pub)
            redeem = bytes([0x00, 0x14]) + h
            h2 = _hash160(redeem)
            pre = bytes([0x05])
            chk = hashlib.sha256(hashlib.sha256(pre + h2).digest()).digest()[:4]
            return _b58encode(pre + h2 + chk)
    except Exception:
        return None

# Mantido por compatibilidade (não é mais usado no hot path do _worker,
# mas outras partes do código podem chamar a assinatura antiga).
def derive_address(master, path_type="bip84", index=0, change=0):
    account = derive_account(master, path_type)
    return derive_address_from_account(account, path_type, index, change)

_WORD_INDEX = None
def _word_index_map():
    """Dict {palavra: índice} — O(1). Construído 1x por processo worker.
    A lib `mnemonic` usa wordlist.index(palavra) internamente, que é O(n)
    (busca linear em 2048 itens) e é chamado 24x por candidato — no pior
    caso (palavra no fim da lista) isso derruba a taxa de ~100k/s pra
    ~2.700/s. Com dict fica O(1) sempre, ~40x mais rápido no pior caso."""
    global _WORD_INDEX
    if _WORD_INDEX is None:
        _WORD_INDEX = {w: i for i, w in enumerate(_get_wordlist())}
    return _WORD_INDEX

def _fast_checksum_ok(word_indices, seed_size):
    """Reimplementação do BIP39 checksum via inteiros/bit-shift — sem
    string ops. Equivalente a mnemo.check(), validado empiricamente."""
    ent_bits = 11 * seed_size * 32 // 33
    cs_bits  = 11 * seed_size - ent_bits
    num = 0
    for idx in word_indices:
        num = (num << 11) | idx
    checksum      = num & ((1 << cs_bits) - 1)
    entropy_bytes = (num >> cs_bits).to_bytes(ent_bits // 8, 'big')
    hash_int      = int.from_bytes(hashlib.sha256(entropy_bytes).digest(), 'big')
    return checksum == (hash_int >> (256 - cs_bits))

# ══════════════════════════════════════════════════════════════
# WORKER — processo separado (sem GIL)
# Top-level obrigatório para pickling no Windows
# ══════════════════════════════════════════════════════════════
def _worker(args):
    (chunk, template, missing_positions, passphrase,
     target_set, path, addr_limit, change_limit) = args
    seed_size = len(template)
    idx_map = _word_index_map()

    # FIX v4.5: os índices das palavras CONHECIDAS (que não mudam entre
    # combinações) são calculados 1x aqui fora do loop — antes eram
    # recalculados (via busca linear) a cada uma das milhões de combos.
    try:
        base_indices = [idx_map[w] if w is not None else None for w in template]
    except KeyError:
        return None  # palavra conhecida digitada não existe na wordlist

    for combo in chunk:
        indices = base_indices.copy()
        for i, pos in enumerate(missing_positions):
            indices[pos] = idx_map.get(combo[i])
        if not _fast_checksum_ok(indices, seed_size):
            continue

        candidate = list(template)
        for i, pos in enumerate(missing_positions):
            candidate[pos] = combo[i]
        phrase = ' '.join(candidate)

        seed = hashlib.pbkdf2_hmac(
            'sha512',
            phrase.encode('utf-8'),
            ('mnemonic' + passphrase).encode('utf-8'),
            2048)
        try:
            master = FastBIP32.from_seed(seed)
            account = derive_account(master, path)  # calculado 1x por candidato
        except Exception:
            continue
        try:
            for c in range(change_limit):
                for idx in range(addr_limit):
                    addr = derive_address_from_account(account, path, idx, c)
                    if addr and addr in target_set:
                        return candidate
        except Exception:
            continue
    return None

def _chunked_product(candidates, repeat, chunk_size=500):
    it = itertools.product(candidates, repeat=repeat)
    while True:
        chunk = list(islice(it, chunk_size))
        if not chunk:
            break
        yield chunk

def build_candidates(hint_starts='', hint_length=0, hint_typo=''):
    wl = _get_wordlist()
    if hint_typo.strip():
        base = similar_words(hint_typo.strip(), max_dist=2) or list(wl)
    else:
        base = list(wl)
    if hint_starts.strip():
        base = [w for w in base if w.startswith(hint_starts.strip().lower())]
    if hint_length > 0:
        base = [w for w in base if len(w) == hint_length]
    return base if base else list(wl)

# ══════════════════════════════════════════════════════════════
# PROCESSO DE RECUPERAÇÃO — roda em mp.Process separado
# Isso é a correção crítica para Windows:
# Pool() NUNCA deve ser criado dentro de threading.Thread no Windows.
# Solução: criar um mp.Process que contém o Pool internamente.
# Comunicação com a GUI é feita via mp.Queue.
# ══════════════════════════════════════════════════════════════
def _recovery_process(params, result_queue, stop_event):
    """
    Função que roda em mp.Process separado.
    Envia mensagens para a GUI via result_queue:
      ('log', texto)
      ('progress', done, total)
      ('done', resultado_ou_None)
      ('error', mensagem)
    """
    try:
        known_words       = params['known_words']
        missing_positions = params['missing_positions']
        passphrase        = params['passphrase']
        target            = params['target']
        path              = params['path']
        addr_limit        = params['addr_limit']
        change_limit      = params['change_limit']
        hint_starts       = params['hint_starts']
        hint_length       = params['hint_length']
        hint_typo         = params['hint_typo']
        seed_size         = params['seed_size']
        num_workers       = params['workers']
        priority          = params.get('priority', 'below')

        def log(msg):
            result_queue.put(('log', msg))

        # Monta template
        template_list = [None] * seed_size
        known_iter = iter(known_words)
        for i in range(seed_size):
            if i not in missing_positions:
                template_list[i] = next(known_iter)

        candidates = build_candidates(hint_starts, hint_length, hint_typo)
        n_missing  = len(missing_positions)

        if missing_positions == [seed_size - 1] and not hint_starts and not hint_typo:
            candidates = valid_last_words(template_list[:seed_size-1])
            log(f"  ✨ Filtro checksum (última palavra) → {len(candidates)} candidatas")

        total      = max(1, len(candidates) ** n_missing)
        target_set = {target}
        template   = tuple(template_list)

        log(f"  Posições ausentes  : {[p+1 for p in missing_positions]}")
        log(f"  Candidatas/posição : {len(candidates)}")
        log(f"  Total combinações  : {total:,}")
        cdiv = checksum_divisor(seed_size)
        effective_total = max(1, total // cdiv)
        log(f"  Após checksum      : ~{effective_total:,} chegam ao PBKDF2 (÷{cdiv})")
        speed = calibrate_speed_per_core()
        log(f"  Tempo estimado     : {fmt_time(effective_total / max(1, speed * num_workers))}")
        log(f"  Workers            : {num_workers} processos reais")
        log("─" * 50)

        # FIX v4.5: chunk_size sem teto virava dezenas de milhões de
        # tuplas por pacote (ex.: 3 palavras ausentes → ~71 milhões),
        # estourando a RAM ao montar/serializar listas gigantes entre
        # processos. Limitamos a uma faixa sensata (500–4000) — grande
        # o bastante pra baixo overhead de IPC, pequeno o bastante pra
        # não empilhar memória nem atrasar o primeiro retorno de progresso.
        chunk_size = min(4000, max(500, total // (num_workers * 200)))

        def make_args(chunk):
            return (chunk, template, missing_positions, passphrase,
                    target_set, path, addr_limit, change_limit)

        done = 0
        found = None

        with Pool(processes=num_workers,
                  initializer=_apply_process_priority,
                  initargs=(priority,)) as pool:
            try:
                result_queue.put(('pids', [w.pid for w in pool._pool]))
            except Exception:
                pass
            for res in pool.imap_unordered(
                    _worker,
                    (make_args(c) for c in _chunked_product(candidates, n_missing, chunk_size)),
                    chunksize=4):

                if stop_event.is_set():
                    pool.terminate()
                    result_queue.put(('done', None))
                    return

                done += chunk_size
                result_queue.put(('progress', min(done, total), total))

                if res is not None:
                    pool.terminate()
                    found = res
                    break

        if found:
            result_queue.put(('done', {
                'words':     found,
                'found':     [found[p] for p in missing_positions],
                'positions': [p + 1 for p in missing_positions]
            }))
        else:
            result_queue.put(('done', None))

    except Exception as e:
        result_queue.put(('error', str(e)))


# ══════════════════════════════════════════════════════════════
# GUI
# ══════════════════════════════════════════════════════════════
class App:
    def __init__(self, root):
        self.root         = root
        self.root.title("BIP39 Bitcoin Wallet Recovery Tool v4.5")
        self.root.geometry("980x900")
        self.root.minsize(900, 840)
        self.root.configure(bg="#0d1117")
        # Controle de parada — mp.Event para cruzar processos
        self._mp_stop     = mp.Event()
        # Processo de recuperação atual
        self._rec_proc    = None
        # Fila IPC processo → GUI
        self._ipc_queue   = mp.Queue()
        # Fila de log thread-safe para a GUI
        self._log_queue   = _queue.SimpleQueue()
        # Métricas de velocidade
        self._last_done   = 0
        self._last_time   = 0
        self._total_combos = 0
        self.worker_pids  = []       # PIDs reais dos workers (p/ boost automático)
        self._is_boosted  = False
        self._setup_styles()
        self._build_ui()
        self.root.after(2000, self._hw_tick)
        self.root.after(150,  self._poll_ipc)
        self.root.after(5000, self._idle_boost_tick)
        # Garante que o processo filho morre ao fechar a janela
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        if self._rec_proc and self._rec_proc.is_alive():
            self._mp_stop.set()
            self._rec_proc.terminate()
            self._rec_proc.join(timeout=2)
        self.root.destroy()

    # ── Estilos ───────────────────────────────────────────────
    def _setup_styles(self):
        s = ttk.Style(); s.theme_use('clam')
        s.configure('TNotebook',         background='#0d1117', borderwidth=0)
        s.configure('TNotebook.Tab',     background='#161b22', foreground='#8b949e',
                                         padding=[16,8], font=('Consolas',10))
        s.map('TNotebook.Tab',
              background=[('selected','#1f2937')],
              foreground=[('selected','#f7b731')])
        s.configure('TFrame',            background='#0d1117')
        s.configure('TLabel',            background='#0d1117', foreground='#c9d1d9',
                                         font=('Consolas',10))
        s.configure('TLabelframe',       background='#0d1117', foreground='#f7b731',
                                         bordercolor='#30363d')
        s.configure('TLabelframe.Label', background='#0d1117', foreground='#f7b731',
                                         font=('Consolas',10,'bold'))
        s.configure('TCombobox',         fieldbackground='#161b22', background='#161b22',
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
        return tk.Label(p, text=text, bg='#0d1117', fg=fg, font=('Consolas',size))

    # ── UI ────────────────────────────────────────────────────
    def _build_ui(self):
        hdr = tk.Frame(self.root, bg='#0d1117')
        hdr.pack(fill='x', padx=20, pady=(14,0))
        tk.Label(hdr, text="₿ BIP39 Wallet Recovery", bg='#0d1117', fg='#f7b731',
                 font=('Consolas',18,'bold')).pack(side='left')
        tk.Label(hdr, text="v4.5 | Multiprocessing | Checksum Filter | 100% Offline",
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
        lf = ttk.LabelFrame(bf, text=" LOG ")
        lf.pack(fill='x')
        self.log_box = scrolledtext.ScrolledText(
            lf, height=5, bg='#010409', fg='#3fb950', font=('Consolas',9),
            relief='flat', bd=4, insertbackground='#3fb950', state='disabled')
        self.log_box.pack(fill='x', padx=4, pady=4)

        # Progresso
        pf = tk.Frame(self.root, bg='#0d1117')
        pf.pack(fill='x', padx=20, pady=(2,0))
        self.prog_var = tk.DoubleVar()
        ttk.Progressbar(pf, variable=self.prog_var, maximum=100,
                        style='Horizontal.TProgressbar').pack(side='left', fill='x', expand=True)
        self.prog_lbl = tk.Label(pf, text="0%", bg='#0d1117', fg='#8b949e',
                                 font=('Consolas',9), width=7)
        self.prog_lbl.pack(side='left', padx=4)
        self.speed_lbl = tk.Label(pf, text="", bg='#0d1117', fg='#58a6ff',
                                  font=('Consolas',9), width=22)
        self.speed_lbl.pack(side='left', padx=4)

        # Botões (Iniciar fica no passo final do assistente — evita duplicidade)
        btnf = tk.Frame(self.root, bg='#0d1117')
        btnf.pack(pady=(4,10))
        self._btn(btnf, "■ PARAR", self._stop, '#da3633', 'white').pack(side='left', padx=8)
        self._btn(btnf, "⎘ EXPORTAR LOG", self._export, '#238636', 'white').pack(side='left', padx=8)

    # ── HW Bar ────────────────────────────────────────────────
    def _build_hw_bar(self):
        bar = tk.Frame(self.root, bg='#161b22', height=34)
        bar.pack(fill='x', padx=20, pady=(0,4))
        bar.pack_propagate(False)

        def item(parent, lbl, color):
            f = tk.Frame(parent, bg='#161b22'); f.pack(side='left', padx=12, pady=4)
            tk.Label(f, text=lbl, bg='#161b22', fg='#484f58', font=('Consolas',8)).pack(side='left')
            var = tk.DoubleVar()
            ttk.Progressbar(f, variable=var, maximum=100, length=70,
                            style='Horizontal.TProgressbar').pack(side='left', padx=4)
            lbl2 = tk.Label(f, text="0%", bg='#161b22', fg=color, font=('Consolas',8), width=5)
            lbl2.pack(side='left')
            return var, lbl2

        self.hw_cpu_v, self.hw_cpu_l = item(bar, "CPU", "#3fb950")
        self.hw_ram_v, self.hw_ram_l = item(bar, "RAM", "#58a6ff")
        tk.Label(bar, text=f"Cores: {CPU_COUNT}", bg='#161b22', fg='#f7b731',
                 font=('Consolas',8)).pack(side='left', padx=12)
        self.hw_wlbl = tk.Label(bar, text="Workers: 1", bg='#161b22', fg='#c9d1d9',
                                font=('Consolas',8))
        self.hw_wlbl.pack(side='left', padx=8)
        self.hw_speed_l = tk.Label(bar, text="", bg='#161b22', fg='#f7b731',
                                   font=('Consolas',8,'bold'))
        self.hw_speed_l.pack(side='left', padx=8)
        tk.Label(bar, text="ENGINE: multiprocessing ⚡", bg='#161b22', fg='#f7b731',
                 font=('Consolas',8,'bold')).pack(side='left', padx=12)
        self.hw_safe = tk.Label(bar, text="● SEGURO", bg='#161b22', fg='#3fb950',
                                font=('Consolas',8,'bold'))
        self.hw_safe.pack(side='right', padx=14)

    def _hw_tick(self):
        try:
            cpu = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory().percent
            self.hw_cpu_v.set(cpu); self.hw_cpu_l.config(text=f"{cpu:.0f}%")
            self.hw_ram_v.set(ram); self.hw_ram_l.config(text=f"{ram:.0f}%")
            if cpu > 90 or ram > 90:
                self.hw_safe.config(text="● CARGA ALTA", fg='#da3633')
            elif cpu > 70 or ram > 75:
                self.hw_safe.config(text="● MODERADO",   fg='#f7b731')
            else:
                self.hw_safe.config(text="● SEGURO",     fg='#3fb950')
        except Exception:
            pass
        self.root.after(2000, self._hw_tick)

    # ── v4.5: Boost automático — só sobe a prioridade quando o PC
    # está realmente parado, e desce assim que o usuário volta a usá-lo.
    # O usuário decide se quer isso ligado (checkbox na aba Hardware).
    def _idle_boost_tick(self):
        try:
            enabled = getattr(self, 'idle_boost_var', None) and self.idle_boost_var.get()
            active  = self._rec_proc and self._rec_proc.is_alive() and self.worker_pids
            if enabled and active:
                idle_s = get_idle_seconds()
                if idle_s is not None and idle_s >= 300 and not self._is_boosted:
                    for pid in self.worker_pids:
                        try:
                            psutil.Process(pid).nice(
                                psutil.NORMAL_PRIORITY_CLASS if IS_WINDOWS else 0)
                        except Exception:
                            pass
                    self._is_boosted = True
                    self.idle_boost_status.config(
                        text="🚀 PC ocioso — prioridade elevada temporariamente.", fg='#3fb950')
                elif (idle_s is None or idle_s < 300) and self._is_boosted:
                    level = self.priority_var.get() if hasattr(self, 'priority_var') else 'below'
                    for pid in self.worker_pids:
                        try:
                            psutil.Process(pid).nice(
                                {'normal':psutil.NORMAL_PRIORITY_CLASS,
                                 'below':psutil.BELOW_NORMAL_PRIORITY_CLASS,
                                 'idle':psutil.IDLE_PRIORITY_CLASS}.get(level, psutil.BELOW_NORMAL_PRIORITY_CLASS)
                                if IS_WINDOWS else {'normal':0,'below':10,'idle':19}.get(level, 10))
                        except Exception:
                            pass
                    self._is_boosted = False
                    self.idle_boost_status.config(
                        text="👤 Você voltou — prioridade normal de volta ao configurado.", fg='#8b949e')
                elif not self._is_boosted:
                    self.idle_boost_status.config(text="⏳ Aguardando 5 min de inatividade...", fg='#484f58')
            elif enabled and not active and hasattr(self, 'idle_boost_status'):
                self.idle_boost_status.config(text="(ativa somente durante uma recuperação em andamento)", fg='#484f58')
                self._is_boosted = False
        except Exception:
            pass
        self.root.after(5000, self._idle_boost_tick)

    # ── Polling da fila IPC (processo → GUI) ─────────────────
    def _poll_ipc(self):
        """Lê mensagens do processo de recuperação e atualiza a GUI. Thread-safe."""
        try:
            while True:
                msg = self._ipc_queue.get_nowait()
                kind = msg[0]

                if kind == 'log':
                    self._flush_log(f"[{time.strftime('%H:%M:%S')}] {msg[1]}")

                elif kind == 'pids':
                    self.worker_pids = msg[1]

                elif kind == 'progress':
                    _, done, total = msg
                    self._total_combos = total
                    p = min(100, done / total * 100) if total else 0
                    self.prog_var.set(p)
                    self.prog_lbl.config(text=f"{p:.1f}%")
                    # Velocidade
                    now = time.time()
                    if self._last_time and (now - self._last_time) >= 0.8:
                        spd = (done - self._last_done) / (now - self._last_time)
                        self.speed_lbl.config(text=f"⚡ {spd:,.0f} combos/s")
                        self.hw_speed_l.config(text=f"⚡ {spd:,.0f} combos/s")
                        self._last_done = done
                        self._last_time = now
                    elif not self._last_time:
                        self._last_done = done
                        self._last_time = now

                elif kind == 'done':
                    result = msg[1]
                    elapsed = time.time() - self._start_time
                    self.prog_var.set(100)
                    self.prog_lbl.config(text="100%")
                    self.speed_lbl.config(text=""); self.hw_speed_l.config(text="")
                    self._rec_proc = None
                    self._wiz_reset_start_button()

                    if result:
                        self._flush_log("═" * 50)
                        self._flush_log("✅ CARTEIRA ENCONTRADA!")
                        self._flush_log("═" * 50)
                        self._flush_log(f"  Seed completa  : {' '.join(result['words'])}")
                        self._flush_log(f"  Palavra(s)     : {result['found']} na(s) posição(ões) {result['positions']}")
                        self._flush_log(f"  Tempo total    : {elapsed:.1f}s")
                        self._flush_log("═" * 50)
                        self._flush_log("⚠️ ANOTE TODAS AS PALAVRAS EM PAPEL AGORA!")
                        messagebox.showinfo("✅ Encontrado!",
                            f"Carteira encontrada!\n\nSeed:\n{' '.join(result['words'])}\n\nAnote agora!")
                    elif not self._mp_stop.is_set():
                        self._flush_log("═" * 50)
                        self._flush_log("❌ Não encontrado.")
                        self._flush_log("  Verifique: passphrase, endereço, ordem das palavras, índices.")
                        self._flush_log(f"  Tempo: {elapsed:.1f}s")
                        self._flush_log("═" * 50)

                elif kind == 'error':
                    self._flush_log(f"❌ ERRO no processo: {msg[1]}")
                    self._rec_proc = None
                    self._wiz_reset_start_button()

        except Exception:
            pass
        self.root.after(150, self._poll_ipc)

    def _wiz_reset_start_button(self):
        """Restaura o botão pro estado normal após terminar/parar a busca."""
        if hasattr(self, 'wiz_next_btn'):
            self.wiz_next_btn.config(text="▶ Iniciar recuperação",
                                     state='normal', bg='#f7b731', fg='#0d1117')
        if hasattr(self, 'wiz_back_btn') and getattr(self, 'wiz_idx', 0) > 0:
            self.wiz_back_btn.config(state='normal')

    def _flush_log(self, msg):
        self.log_box.config(state='normal')
        self.log_box.insert('end', msg + '\n')
        self.log_box.see('end')
        self.log_box.config(state='disabled')

    # ── Tab: Recuperação ──────────────────────────────────────
    # ════════════════════════════════════════════════════════
    # ABA RECUPERAÇÃO — assistente guiado por passos (v4.5)
    # Em vez de um formulário único, o usuário avança passo a
    # passo com validação e resumo em tempo real a cada etapa.
    # ════════════════════════════════════════════════════════
    WIZ_TITLES = [
        "Tamanho da seed",
        "Insira as palavras",
        "Dicas inteligentes",
        "Onde estão as ausentes?",
        "Credenciais",
        "Resumo e início",
    ]

    def _tab_recovery(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text=" 🔑 Recuperação ")

        # ── Indicador de progresso do assistente ───────────────
        prog_bar = tk.Frame(tab, bg='#0d1117')
        prog_bar.pack(fill='x', padx=12, pady=(10,4))
        self.wiz_step_lbl = tk.Label(prog_bar, text="", bg='#0d1117', fg='#484f58',
                                      font=('Consolas',9))
        self.wiz_step_lbl.pack(side='left')
        self.wiz_title_lbl = tk.Label(prog_bar, text="", bg='#0d1117', fg='#f7b731',
                                       font=('Consolas',11,'bold'))
        self.wiz_title_lbl.pack(side='left', padx=10)
        self.wiz_prog_var = tk.DoubleVar()
        ttk.Progressbar(prog_bar, variable=self.wiz_prog_var, maximum=100,
                        style='Horizontal.TProgressbar').pack(side='right', fill='x', expand=True, padx=(20,0))

        # ── Container que troca de conteúdo por passo ──────────
        self.wiz_container = tk.Frame(tab, bg='#0d1117')
        self.wiz_container.pack(fill='both', expand=True, padx=12)

        self.wiz_steps = [
            self._wiz_step_seed_size(self.wiz_container),
            self._wiz_step_words(self.wiz_container),
            self._wiz_step_hints(self.wiz_container),
            self._wiz_step_positions(self.wiz_container),
            self._wiz_step_credentials(self.wiz_container),
            self._wiz_step_summary(self.wiz_container),
        ]

        # ── Navegação ───────────────────────────────────────────
        nav = tk.Frame(tab, bg='#0d1117')
        nav.pack(fill='x', padx=12, pady=(8,10))
        self.wiz_back_btn = tk.Button(
            nav, text="← Voltar", command=self._wiz_back,
            bg='#21262d', fg='#8b949e', activebackground='#30363d',
            relief='flat', bd=0, padx=16, pady=8, font=('Consolas',10), cursor='hand2')
        self.wiz_back_btn.pack(side='left')
        self.wiz_next_btn = self._btn(nav, "Continuar →", self._wiz_next)
        self.wiz_next_btn.pack(side='right')

        self.wiz_idx = 0
        self._wiz_show(0)

    # ── Navegação do assistente ────────────────────────────────
    def _wiz_show(self, idx):
        for f in self.wiz_steps:
            f.pack_forget()
        self.wiz_idx = idx
        self.wiz_steps[idx].pack(fill='both', expand=True)
        n = len(self.wiz_steps)
        self.wiz_step_lbl.config(text=f"Passo {idx+1} de {n}")
        self.wiz_title_lbl.config(text=self.WIZ_TITLES[idx])
        self.wiz_prog_var.set((idx+1) / n * 100)
        self.wiz_back_btn.config(state='disabled' if idx == 0 else 'normal')
        self.wiz_next_btn.config(text="▶ Iniciar recuperação" if idx == n-1 else "Continuar →")
        if idx == n-1:
            self._wiz_update_summary()

    def _wiz_validate_step(self, idx):
        """Valida o passo atual antes de avançar. Retorna (ok, mensagem)."""
        if idx == 1:  # palavras
            wl = set(_get_wordlist())
            filled = [e.get().strip().lower() for e in self.word_entries
                      if e.get().strip()]
            invalid = [w for w in filled if w not in wl]
            if invalid:
                return False, f"Estas palavras não são BIP39 válidas: {', '.join(invalid)}"
            n_blank = self.seed_size_var.get() - len(filled)
            if n_blank == 0:
                return False, "Nenhuma palavra em branco. Deixe vazia a(s) que não lembra."
            return True, ""
        if idx == 4:  # credenciais
            if not self.addr_entry.get().strip():
                return False, "Insira o endereço Bitcoin antes de continuar."
        return True, ""

    def _wiz_next(self):
        if self.wiz_idx == len(self.wiz_steps) - 1:
            self._start()
            return
        ok, msg = self._wiz_validate_step(self.wiz_idx)
        if not ok:
            messagebox.showwarning("Verifique antes de continuar", msg)
            return
        self._wiz_show(self.wiz_idx + 1)

    def _wiz_back(self):
        if self.wiz_idx > 0:
            self._wiz_show(self.wiz_idx - 1)

    # ── Passo 1: tamanho da seed ────────────────────────────────
    def _wiz_step_seed_size(self, parent):
        f = tk.Frame(parent, bg='#0d1117')
        self._label(f, "Quantas palavras tem sua seed?", fg='#c9d1d9', size=11).pack(anchor='w', pady=(10,4))
        top = tk.Frame(f, bg='#0d1117'); top.pack(anchor='w', pady=4)
        self._label(top, "Tamanho da seed:").pack(side='left')
        self.seed_size_var = tk.IntVar(value=24)
        ttk.Combobox(top, textvariable=self.seed_size_var, width=5,
                     values=[12,15,18,21,24], state='readonly').pack(side='left', padx=6)
        self._label(top, "palavras").pack(side='left')

        top2 = tk.Frame(f, bg='#0d1117'); top2.pack(anchor='w', pady=8)
        self._label(top2, "Quantas você já tem escritas:").pack(side='left')
        self.known_count_var = tk.IntVar(value=23)
        tk.Spinbox(top2, from_=1, to=24, textvariable=self.known_count_var, width=4,
                   bg='#161b22', fg='#c9d1d9', font=('Consolas',10),
                   buttonbackground='#1f2937',
                   command=self._update_word_grid).pack(side='left', padx=6)
        self._label(f, "(no próximo passo, deixe em branco as posições que não lembra)",
                    fg='#484f58').pack(anchor='w', pady=(4,0))
        return f

    # ── Passo 2: palavras ────────────────────────────────────────
    def _wiz_step_words(self, parent):
        f = tk.Frame(parent, bg='#0d1117')
        paste_bar = tk.Frame(f, bg='#0d1117')
        paste_bar.pack(fill='x', pady=(10,2))
        self._label(paste_bar,
                    "💡 Cole todas as palavras de uma vez aqui e pressione ENTER ou clique em Distribuir:",
                    fg='#58a6ff', size=9).pack(side='left')

        paste_row = tk.Frame(f, bg='#0d1117')
        paste_row.pack(fill='x', pady=(2,6))
        self.paste_box = tk.Entry(
            paste_row, width=60, bg='#0d2a4a', fg='#c9d1d9',
            insertbackground='#58a6ff', relief='flat', bd=6,
            font=('Consolas',10), highlightthickness=1,
            highlightcolor='#58a6ff', highlightbackground='#1f6feb')
        self.paste_box.pack(side='left', padx=(0,6))
        self.paste_box.insert(0, "ex: hold ripple venue crime valid gossip ...")
        self.paste_box.config(fg='#484f58')

        def _pb_focus_in(_):
            if self.paste_box.get().startswith("ex:"):
                self.paste_box.delete(0, 'end')
                self.paste_box.config(fg='#c9d1d9')
        def _pb_focus_out(_):
            if not self.paste_box.get().strip():
                self.paste_box.insert(0, "ex: hold ripple venue crime valid gossip ...")
                self.paste_box.config(fg='#484f58')
        self.paste_box.bind('<FocusIn>',  _pb_focus_in)
        self.paste_box.bind('<FocusOut>', _pb_focus_out)
        self.paste_box.bind('<Control-v>', lambda e: self.root.after(10, self._smart_paste))
        self.paste_box.bind('<Return>',    lambda e: self._smart_paste())

        tk.Button(paste_row, text="⬇ Distribuir", command=self._smart_paste,
                  bg='#1f6feb', fg='white', activebackground='#388bfd',
                  relief='flat', bd=0, padx=12, pady=4,
                  font=('Consolas',9,'bold'), cursor='hand2').pack(side='left', padx=(0,4))
        tk.Button(paste_row, text="✕ Limpar tudo", command=self._clear_all_words,
                  bg='#21262d', fg='#8b949e', activebackground='#30363d',
                  relief='flat', bd=0, padx=10, pady=4,
                  font=('Consolas',9), cursor='hand2').pack(side='left')

        self.paste_status = tk.Label(f, text="", bg='#0d1117', font=('Consolas',9), anchor='w')
        self.paste_status.pack(fill='x', pady=(0,4))
        ttk.Separator(f, orient='horizontal').pack(fill='x', pady=(0,6))
        self._label(f, "Ou preencha campo a campo — a cor mostra se a palavra é válida.",
                    fg='#484f58').pack(anchor='w', pady=(0,6))

        self.word_entries = []
        self.grid_frame   = tk.Frame(f, bg='#0d1117')
        self.grid_frame.pack(fill='x', pady=(0,8))
        self._build_word_grid(24)
        return f

    # ── Passo 3: dicas ───────────────────────────────────────────
    def _wiz_step_hints(self, parent):
        f = tk.Frame(parent, bg='#0d1117')
        self._label(f, "Essas dicas são opcionais, mas reduzem MUITO o tempo de busca.",
                    fg='#3fb950', size=10).pack(anchor='w', pady=(10,8))
        h1 = tk.Frame(f, bg='#0d1117'); h1.pack(fill='x', pady=4)
        self._label(h1, "Palavra começa com:").pack(side='left')
        self.hint_starts = self._entry(h1, w=8)
        self.hint_starts.pack(side='left', padx=6)
        self._label(h1, "  Tem exatamente N letras (0 = qualquer):").pack(side='left', padx=(16,4))
        self.hint_length_var = tk.IntVar(value=0)
        tk.Spinbox(h1, from_=0, to=10, textvariable=self.hint_length_var, width=4,
                   bg='#161b22', fg='#c9d1d9', font=('Consolas',10),
                   buttonbackground='#1f2937').pack(side='left')
        h2 = tk.Frame(f, bg='#0d1117'); h2.pack(fill='x', pady=(8,8))
        self._label(h2, "Acho que errei a escrita de uma palavra — o que escrevi?").pack(side='left')
        self.hint_typo = self._entry(h2, w=20)
        self.hint_typo.pack(side='left', padx=6)
        self._label(h2, " (encontra palavras BIP39 similares)", fg='#3fb950').pack(side='left')
        return f

    # ── Passo 4: posições ────────────────────────────────────────
    def _wiz_step_positions(self, parent):
        f = tk.Frame(parent, bg='#0d1117')
        self.pos_mode_var = tk.StringVar(value="unknown")
        tk.Radiobutton(f, text="Não sei as posições — testar todas automaticamente",
                       variable=self.pos_mode_var, value="unknown",
                       bg='#0d1117', fg='#c9d1d9', selectcolor='#161b22',
                       activebackground='#0d1117', activeforeground='#f7b731',
                       font=('Consolas',10), command=self._on_pos_mode).pack(anchor='w', pady=(10,2))
        tk.Radiobutton(f, text="Sei as posições:",
                       variable=self.pos_mode_var, value="known",
                       bg='#0d1117', fg='#c9d1d9', selectcolor='#161b22',
                       activebackground='#0d1117', activeforeground='#f7b731',
                       font=('Consolas',10), command=self._on_pos_mode).pack(anchor='w', pady=2)
        pos_row = tk.Frame(f, bg='#0d1117')
        pos_row.pack(fill='x', padx=24, pady=(0,8))
        self._label(pos_row, "Posições (ex: 5 12 18):").pack(side='left')
        self.pos_entry = self._entry(pos_row, w=30)
        self.pos_entry.pack(side='left', padx=6)
        self._label(pos_row, " separadas por espaço", fg='#484f58').pack(side='left')
        self.pos_entry.config(state='disabled')
        return f

    # ── Passo 5: credenciais ─────────────────────────────────────
    def _wiz_step_credentials(self, parent):
        f = tk.Frame(parent, bg='#0d1117')
        r1 = tk.Frame(f, bg='#0d1117'); r1.pack(fill='x', pady=(10,4))
        self._label(r1, "Passphrase (senha extra):", size=10).pack(side='left')
        self.pass_entry = self._entry(r1, show='•', w=28)
        self.pass_entry.pack(side='left', padx=6)
        self.show_pass = tk.BooleanVar()
        tk.Checkbutton(r1, text="mostrar", variable=self.show_pass, bg='#0d1117', fg='#8b949e',
                       selectcolor='#161b22', activebackground='#0d1117', font=('Consolas',9),
                       command=lambda: self.pass_entry.config(
                           show='' if self.show_pass.get() else '•')).pack(side='left')
        self._label(r1, " (deixe vazio se não usou)", fg='#484f58').pack(side='left')

        r2 = tk.Frame(f, bg='#0d1117'); r2.pack(fill='x', pady=4)
        self._label(r2, "Endereço Bitcoin (bc1q / 1... / 3...):", size=10).pack(side='left')
        self.addr_entry = self._entry(r2, w=50)
        self.addr_entry.pack(side='left', padx=6)
        self.addr_hint_lbl = tk.Label(r2, text="", bg='#0d1117', font=('Consolas',9))
        self.addr_hint_lbl.pack(side='left', padx=6)

        r3 = tk.Frame(f, bg='#0d1117'); r3.pack(fill='x', pady=(4,8))
        self._label(r3, "Tipo de endereço:", size=10).pack(side='left')
        self.path_var = tk.StringVar(value="bip84")
        ttk.Combobox(r3, textvariable=self.path_var, width=18,
                     values=["bip84 (bc1q...)", "bip44 (1...)", "bip49 (3...)"],
                     state='readonly').pack(side='left', padx=6)
        self._label(r3, "  Índices:", size=10).pack(side='left', padx=(12,4))
        self.addr_lim = tk.IntVar(value=10)
        tk.Spinbox(r3, from_=1, to=50, textvariable=self.addr_lim, width=4,
                   bg='#161b22', fg='#c9d1d9', font=('Consolas',10),
                   buttonbackground='#1f2937').pack(side='left')
        self.change_var = tk.BooleanVar(value=False)
        tk.Checkbutton(r3, text=" testar caminho de troco também",
                       variable=self.change_var, bg='#0d1117', fg='#8b949e',
                       selectcolor='#161b22', activebackground='#0d1117',
                       font=('Consolas',9)).pack(side='left', padx=8)

        # Detecta o tipo de endereço automaticamente enquanto digita
        def _on_addr_change(*_):
            addr = self.addr_entry.get().strip()
            if addr.startswith('bc1q'):
                self.path_var.set("bip84 (bc1q...)")
                self.addr_hint_lbl.config(text="✅ SegWit nativo detectado (BIP84)", fg='#3fb950')
            elif addr.startswith('3'):
                self.path_var.set("bip49 (3...)")
                self.addr_hint_lbl.config(text="✅ SegWit-P2SH detectado (BIP49)", fg='#3fb950')
            elif addr.startswith('1'):
                self.path_var.set("bip44 (1...)")
                self.addr_hint_lbl.config(text="✅ Legacy detectado (BIP44)", fg='#3fb950')
            elif addr:
                self.addr_hint_lbl.config(text="⚠ Formato não reconhecido", fg='#f7b731')
            else:
                self.addr_hint_lbl.config(text="")
        self._addr_trace = self.addr_entry
        self.addr_entry.bind('<KeyRelease>', _on_addr_change)
        return f

    # ── Passo 6: resumo + iniciar ────────────────────────────────
    def _wiz_step_summary(self, parent):
        f = tk.Frame(parent, bg='#0d1117')
        self.wiz_summary_box = scrolledtext.ScrolledText(
            f, height=13, bg='#010409', fg='#c9d1d9', font=('Consolas',10),
            relief='flat', bd=4, insertbackground='#f7b731', state='disabled')
        self.wiz_summary_box.pack(fill='both', expand=True, pady=(10,4))
        self._label(f, "Confira os dados acima. Clique em ▶ Iniciar recuperação quando estiver pronto.",
                    fg='#484f58').pack(anchor='w')
        return f

    def _wiz_update_summary(self):
        words_raw = [e.get().strip().lower() for e in self.word_entries]
        seed_size = self.seed_size_var.get()
        words_raw = words_raw[:seed_size]
        n_missing = sum(1 for w in words_raw if not w)
        addr = self.addr_entry.get().strip() or "(não informado)"
        passphrase = "sim" if self.pass_entry.get() else "não"
        path = self.path_var.get().split()[0] if self.path_var.get() else "bip84"
        workers = self.workers_var.get() if hasattr(self, 'workers_var') else 1
        has_typo = bool(self.hint_typo.get().strip())
        has_starts = bool(self.hint_starts.get().strip())

        combos = 2048 ** max(1, n_missing)
        cdiv = checksum_divisor(seed_size)
        effective = max(1, combos // cdiv)
        level, color, secs = feasibility(effective, workers)

        lines = [
            "━━━ RESUMO DA RECUPERAÇÃO ━━━", "",
            f"  Tamanho da seed     : {seed_size} palavras",
            f"  Palavras ausentes   : {n_missing}",
            f"  Endereço alvo       : {addr}",
            f"  Tipo de endereço    : {path}",
            f"  Passphrase informada: {passphrase}",
            f"  Dicas ativas        : {'sim' if (has_typo or has_starts) else 'nenhuma'}",
            f"  Workers de CPU      : {workers} de {CPU_COUNT} núcleos",
            "",
            f"  Combinações a testar: ~{effective:,} (após filtro de checksum)",
            f"  Tempo estimado      : {fmt_time(secs)}",
            f"  Viabilidade         : {level}",
        ]
        self.wiz_summary_box.config(state='normal')
        self.wiz_summary_box.delete('1.0', 'end')
        self.wiz_summary_box.tag_config("lvl", foreground=color, font=('Consolas',10,'bold'))
        for ln in lines:
            tag = "lvl" if level in ln else None
            if tag:
                self.wiz_summary_box.insert('end', ln+"\n", tag)
            else:
                self.wiz_summary_box.insert('end', ln+"\n")
        self.wiz_summary_box.config(state='disabled')

    # ── Word grid (com validação em tempo real) ────────────────
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
            e.bind('<KeyRelease>', self._on_word_entry_change)
            self.word_entries.append(e)

    def _on_word_entry_change(self, event=None):
        """Valida a palavra em tempo real: verde = válida, vermelho = não reconhecida,
        cinza = em branco. Também atualiza o contador de status ao lado."""
        wl = set(_get_wordlist())
        e = event.widget if event else None
        if e is not None:
            w = e.get().strip().lower()
            if not w:
                e.config(bg='#161b22', highlightbackground='#30363d')
            elif w in wl:
                e.config(bg='#0d2a0d', highlightbackground='#3fb950')
            else:
                e.config(bg='#2a0d0d', highlightbackground='#da3633')

        ok = unk = blank = 0
        for entry in self.word_entries:
            w = entry.get().strip().lower()
            if not w: blank += 1
            elif w in wl: ok += 1
            else: unk += 1
        parts = []
        if ok:  parts.append(f"✅ {ok} válidas")
        if unk: parts.append(f"❌ {unk} não reconhecidas")
        if blank: parts.append(f"⬜ {blank} em branco")
        self.paste_status.config(text="   ".join(parts),
                                 fg='#3fb950' if unk == 0 else '#f7b731')

    def _update_word_grid(self):
        self._build_word_grid(self.seed_size_var.get())

    def _on_pos_mode(self):
        self.pos_entry.config(
            state='normal' if self.pos_mode_var.get() == 'known' else 'disabled')

    # ── Cola inteligente ──────────────────────────────────────
    def _smart_paste(self):
        raw = self.paste_box.get().strip()
        if not raw or raw.startswith("ex:"):
            self.paste_status.config(
                text="⚠  Cole as palavras no campo azul antes de distribuir.", fg='#f7b731')
            return
        words = [w.strip().lower() for w in re.split(r'[\s,;]+', raw) if w.strip()]
        if not words:
            self.paste_status.config(text="⚠  Nenhuma palavra encontrada.", fg='#f7b731')
            return

        wl       = set(_get_wordlist())
        n_cells  = len(self.word_entries)
        ok, unk, truncated = 0, 0, False

        for e in self.word_entries:
            e.config(bg='#161b22', highlightbackground='#30363d')
            e.delete(0, 'end')

        for i, word in enumerate(words):
            if i >= n_cells:
                truncated = True
                break
            e = self.word_entries[i]
            e.delete(0, 'end')
            e.insert(0, word)
            if word in wl:
                e.config(bg='#0d2a0d', highlightbackground='#3fb950')
                ok += 1
            else:
                e.config(bg='#2a0d0d', highlightbackground='#da3633')
                unk += 1

        n_blank = n_cells - min(len(words), n_cells)
        parts   = []
        if ok:  parts.append(f"✅ {ok} válidas")
        if unk: parts.append(f"❌ {unk} não reconhecidas")
        if n_blank: parts.append(f"⬜ {n_blank} em branco")
        if truncated: parts.append(f"⚠ truncado em {n_cells}")
        self.paste_status.config(text="   ".join(parts),
                                 fg='#3fb950' if unk == 0 else '#f7b731')
        self.paste_box.delete(0, 'end')
        self.paste_box.insert(0, "ex: hold ripple venue crime valid gossip ...")
        self.paste_box.config(fg='#484f58')

    def _clear_all_words(self):
        for e in self.word_entries:
            e.delete(0, 'end')
            e.config(bg='#161b22', highlightbackground='#30363d')
        self.paste_status.config(text="")
        self.paste_box.delete(0, 'end')
        self.paste_box.insert(0, "ex: hold ripple venue crime valid gossip ...")
        self.paste_box.config(fg='#484f58')

    # ── Tab: Hardware ─────────────────────────────────────────
    def _tab_hardware(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text=" ⚡ Controle de Hardware ")
        cpu_f = ttk.LabelFrame(tab, text=" WORKERS DE CPU ")
        cpu_f.pack(fill='x', padx=12, pady=(12,6))
        info = tk.Frame(cpu_f, bg='#161b22')
        info.pack(fill='x', padx=12, pady=(8,4))
        tk.Label(info,
                 text="  ⚡ v4.5 usa mp.Process + Pool — GUI nunca trava no Windows.\n"
                      "  O uso de CPU mostrará ~100% × workers. Isso é correto e esperado.",
                 bg='#161b22', fg='#3fb950', font=('Consolas',9), justify='left').pack(anchor='w', pady=4)
        self._label(cpu_f, f"Seu CPU tem {CPU_COUNT} núcleos. Escolha quantos dedicar à recuperação:",
                    fg='#8b949e').pack(anchor='w', padx=12, pady=(4,2))

        sf = tk.Frame(cpu_f, bg='#0d1117'); sf.pack(fill='x', padx=12, pady=6)
        self.workers_var = tk.IntVar(value=max(1, CPU_COUNT//2))
        self.w_lbl = tk.Label(sf, text=f"Workers: {self.workers_var.get()}",
                              bg='#0d1117', fg='#f7b731', font=('Consolas',12,'bold'), width=14)
        self.w_lbl.pack(side='left')

        def on_slide(v):
            n = int(float(v))
            self.workers_var.set(n)
            self.w_lbl.config(text=f"Workers: {n}")
            self.hw_wlbl.config(text=f"Workers: {n}")
            pct  = int(n / CPU_COUNT * 100)
            desc = "🟢 Leve" if pct<=40 else "🟡 Moderado" if pct<=70 else "🔴 Pesado"
            self.w_desc.config(text=f"{pct}% da CPU {desc}")

        tk.Scale(sf, from_=1, to=CPU_COUNT, orient='horizontal', variable=self.workers_var,
                 command=on_slide, length=400, bg='#0d1117', fg='#c9d1d9',
                 troughcolor='#161b22', activebackground='#f7b731', highlightthickness=0,
                 sliderrelief='flat', font=('Consolas',9)).pack(side='left', padx=10)
        self.w_desc = self._label(cpu_f, "")
        self.w_desc.pack(anchor='w', padx=12, pady=(0,4))
        on_slide(self.workers_var.get())

        pf = ttk.LabelFrame(tab, text=" PRESETS ")
        pf.pack(fill='x', padx=12, pady=6)
        row = tk.Frame(pf, bg='#0d1117'); row.pack(fill='x', padx=12, pady=8)

        def preset_btn(text, workers, color):
            tk.Button(row, text=text, width=28,
                      command=lambda: (self.workers_var.set(workers), on_slide(workers)),
                      bg='#161b22', fg='#c9d1d9', activebackground=color,
                      relief='flat', bd=1, padx=8, pady=8,
                      font=('Consolas',9), cursor='hand2', justify='left').pack(side='left', padx=6)

        preset_btn(f"🟢 Modo Seguro\n(1 worker — PC continua responsivo)", 1, '#238636')
        preset_btn(f"🟡 Balanceado\n({max(1,CPU_COUNT//2)} workers — recomendado)", max(1,CPU_COUNT//2), '#b08800')
        preset_btn(f"🔴 Máxima Potência\n({CPU_COUNT} workers — PC pode lentificar)", CPU_COUNT, '#da3633')

        # ── v4.5: Prioridade de processo (deixa o SO priorizar o resto) ──
        pr_f = ttk.LabelFrame(tab, text=" PRIORIDADE DOS PROCESSOS (novo em v4.5) ")
        pr_f.pack(fill='x', padx=12, pady=6)
        self._label(pr_f,
            "Controla quanto o SO 'empresta' de CPU aos workers quando outros\n"
            "programas também precisam. Não muda quantos núcleos são usados —\n"
            "só a prioridade deles na fila do sistema operacional.",
            fg='#8b949e').pack(anchor='w', padx=12, pady=(8,4))
        self.priority_var = tk.StringVar(value='below')
        prow = tk.Frame(pr_f, bg='#0d1117'); prow.pack(fill='x', padx=12, pady=(2,10))
        for val, text in [
            ('normal', "🔴 Normal — mais rápido, compete de igual pra igual com outros apps"),
            ('below',  "🟡 Baixa (recomendado) — cede CPU quando você abre algo"),
            ('idle',   "🟢 Muito baixa — só usa CPU que estiver realmente sobrando"),
        ]:
            tk.Radiobutton(prow, text=text, variable=self.priority_var, value=val,
                           bg='#0d1117', fg='#c9d1d9', selectcolor='#161b22',
                           activebackground='#0d1117', activeforeground='#f7b731',
                           font=('Consolas',9)).pack(anchor='w', pady=1)
        if not IS_WINDOWS:
            self._label(pr_f, "  (No Linux/Mac isso usa 'nice' — funciona igual)",
                        fg='#484f58').pack(anchor='w', padx=12, pady=(0,6))

        # ── v4.5: Boost automático quando o PC está ocioso ────────────
        idle_avail = get_idle_seconds() is not None
        boost_f = ttk.LabelFrame(tab, text=" BOOST AUTOMÁTICO (novo em v4.5) ")
        boost_f.pack(fill='x', padx=12, pady=6)
        self.idle_boost_var = tk.BooleanVar(value=False)
        cb = tk.Checkbutton(boost_f,
            text="🌙 Aumentar a prioridade para Normal quando o PC ficar 5 min sem uso"
                 + ("" if idle_avail else "  (indisponível — requer Windows)"),
            variable=self.idle_boost_var, bg='#0d1117', fg='#c9d1d9' if idle_avail else '#484f58',
            selectcolor='#161b22', activebackground='#0d1117',
            font=('Consolas',9), state='normal' if idle_avail else 'disabled')
        cb.pack(anchor='w', padx=12, pady=(8,4))
        self.idle_boost_status = self._label(boost_f, "", fg='#484f58')
        self.idle_boost_status.pack(anchor='w', padx=12, pady=(0,8))

        wf = ttk.LabelFrame(tab, text=" ORIENTAÇÕES DE SEGURANÇA ")
        wf.pack(fill='both', expand=True, padx=12, pady=6)
        tk.Label(wf, text="""
  🌡️ Mais workers = mais calor. Evite Máximo em notebooks ou PCs com pouca ventilação.
  💾 Cada worker usa ~50–100 MB de RAM. Use Modo Seguro se tiver menos de 4 GB RAM.
  🔋 Na bateria? Use Modo Seguro — Máxima Potência gasta rápido.
  🖥️ Balanceado permite usar o PC normalmente enquanto a recuperação roda em segundo plano.
  🐢 Prioridade "Baixa" (abaixo) cede CPU automaticamente pro resto do sistema — o PC
     não trava mesmo em Máxima Potência, só fica mais lento se você abrir algo pesado.
  ⚡ v4.5: GUI nunca trava — motor roda em processo OS separado!
        """, bg='#0d1117', fg='#8b949e', font=('Consolas',9), justify='left').pack(anchor='w', padx=8)

    # ── Tab: Análise ──────────────────────────────────────────
    def _tab_analysis(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text=" 📊 Análise de Viabilidade ")
        ctrl = ttk.LabelFrame(tab, text=" O QUE VOCÊ TEM? ")
        ctrl.pack(fill='x', padx=12, pady=(12,6))
        r1 = tk.Frame(ctrl, bg='#0d1117'); r1.pack(fill='x', padx=12, pady=6)
        self._label(r1, "Tamanho da seed:", size=10).pack(side='left')
        self.an_seed = tk.IntVar(value=24)
        ttk.Combobox(r1, textvariable=self.an_seed, width=5,
                     values=[12,15,18,21,24], state='readonly').pack(side='left', padx=6)
        self._label(r1, "  Palavras que tem:", size=10).pack(side='left', padx=(12,4))
        self.an_known = tk.IntVar(value=23)
        tk.Spinbox(r1, from_=0, to=24, textvariable=self.an_known, width=4,
                   bg='#161b22', fg='#c9d1d9', font=('Consolas',10),
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
                           activeforeground='#f7b731', font=('Consolas',10)).pack(side='left', padx=10)

        cb(r2, "Sei a(s) posição(ões)", self.an_pos)
        cb(r2, "Tenho passphrase",      self.an_pass)
        cb(r2, "Tenho o endereço",      self.an_addr)
        r3 = tk.Frame(ctrl, bg='#0d1117'); r3.pack(fill='x', padx=12, pady=(2,8))
        cb(r3, "Sei o tipo de derivação", self.an_bip)
        cb(r3, "Tenho dica do padrão",    self.an_hint)
        self._btn(ctrl, " CALCULAR ANÁLISE ", self._run_analysis, '#1f6feb', 'white').pack(pady=(0,10))

        rf = ttk.LabelFrame(tab, text=" RESULTADO ")
        rf.pack(fill='both', expand=True, padx=12, pady=6)
        self.an_box = scrolledtext.ScrolledText(
            rf, height=14, bg='#010409', fg='#c9d1d9', font=('Consolas',10),
            relief='flat', bd=4, insertbackground='#f7b731', state='disabled')
        self.an_box.pack(fill='both', expand=True, padx=4, pady=4)
        self.root.after(400, self._run_analysis)

    def _run_analysis(self):
        total   = self.an_seed.get()
        known   = min(self.an_known.get(), total)
        missing = total - known
        workers = self.workers_var.get() if hasattr(self, 'workers_var') else 1
        has_hint = self.an_hint.get()
        base    = int(2048 * 0.05) if has_hint else 2048
        combos  = base ** max(1, missing)
        cdiv = checksum_divisor(total)
        effective = max(1, combos // cdiv)
        level, color, secs = feasibility(effective, workers)
        tempo = fmt_time(secs)

        lines = ["━━━ ANÁLISE DA SITUAÇÃO (motor v4.5) ━━━", ""]
        lines += [
            f"  Tamanho da seed    : {total} palavras",
            f"  Você tem           : {known} palavras",
            f"  Ausentes           : {missing} palavra(s)",
            f"  Posição conhecida  : {'Sim ✅' if self.an_pos.get() else 'Não ❌'}",
            f"  Tem passphrase     : {'Sim ✅' if self.an_pass.get() else 'Não ❌'}",
            f"  Tem endereço       : {'Sim ✅' if self.an_addr.get() else 'Não ❌ ← importante!'}",
            f"  Tem derivação      : {'Sim ✅' if self.an_bip.get() else 'Não ❌'}",
            f"  Dica de padrão     : {'Sim ✅ (~95% menos candidatas)' if has_hint else 'Não'}",
            f"  Workers            : {workers} processos reais ⚡",
            "",
            f"  Combinações brutas : {combos:,}",
            f"  Após checksum      : ~{effective:,} ← 2048× menos",
            f"  Tempo estimado     : {tempo}",
            f"  Viabilidade        : {level}",
            ""
        ]
        if missing == 0:
            lines += ["  ℹ️ Você tem todas as palavras! Verifique passphrase e derivação."]
        elif missing == 1: lines += ["  🟢 Ótimo. Uma palavra ausente — segundos a minutos."]
        elif missing == 2: lines += ["  🟡 Possível. Minutos a horas com v4.5."]
        elif missing == 3: lines += ["  🟠 Difícil. Use todas as dicas. Pode levar horas/dias."]
        elif missing <= 5: lines += ["  🔴 Muito difícil. Dicas são essenciais."]
        else:              lines += ["  💀 Inviável sem hardware GPU."]

        lines += ["", "  💡 O que ainda ajuda:"]
        if not self.an_addr.get(): lines.append("  ➕ Endereço público → essencial para confirmar matches")
        if not self.an_pos.get() and missing >= 1: lines.append("  ➕ Posição das palavras ausentes → enorme ganho")
        if not has_hint: lines.append("  ➕ Dica de padrão → reduz candidatas em ~95%")
        if missing > 1: lines.append(f"  ➕ Cada palavra extra lembrada divide o tempo por {base:,}")
        if workers < CPU_COUNT: lines.append(f"  ➕ Mais workers → você tem {CPU_COUNT} núcleos disponíveis")

        self.an_box.config(state='normal')
        self.an_box.delete('1.0', 'end')
        self.an_box.tag_config("ok",  foreground="#3fb950")
        self.an_box.tag_config("bad", foreground="#da3633")
        self.an_box.tag_config("tip", foreground="#58a6ff")
        self.an_box.tag_config("lvl", foreground=color, font=('Consolas',10,'bold'))
        self.an_box.tag_config("dim", foreground="#c9d1d9")
        for ln in lines:
            tag = "dim"
            if "✅" in ln:   tag = "ok"
            elif "❌" in ln: tag = "bad"
            elif level in ln: tag = "lvl"
            elif "➕" in ln or "💡" in ln: tag = "tip"
            elif any(x in ln for x in ["🟢","🟡","🟠","🔴","💀"]):
                tag = "ok" if "🟢" in ln else "bad"
            self.an_box.insert('end', ln+"\n", tag)
        self.an_box.config(state='disabled')

    # ── Tab: Sobre ────────────────────────────────────────────
    def _tab_about(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text=" ℹ Sobre ")
        tk.Label(tab, text="""
  ₿ BIP39 Bitcoin Wallet Recovery Tool v4.5
  ════════════════════════════════════════════════════
  FIX v4.5 — GUI não trava mais no Windows:
  ├─ Pool criado em mp.Process separado da GUI
  ├─ Comunicação GUI ↔ motor via mp.Queue (IPC)
  └─ Stop via mp.Event compartilhado entre processos

  Otimizações mantidas de v3.0:
  ├─ derive_address recebe master já criado
  ├─ Globais MNEMO/WORDLIST removidas do topo
  ├─ hw_monitor e log via root.after() — thread-safe
  ├─ islice nos chunks, template como tuple
  ├─ rapidfuzz opcional (pip install rapidfuzz)
  └─ Cola inteligente Ctrl+V com feedback visual

  Derivações:
  ├─ BIP84 → bc1q... (Native SegWit)
  ├─ BIP44 → 1...    (Legacy)
  └─ BIP49 → 3...    (SegWit)

  ⚠️ Sempre rode OFFLINE. Nunca compartilhe sua seed.
  ─────────────────────────────────────────────────────
  github.com/leonardoramcke/bitcoin-recovery
  MIT License © 2026 leonardoramcke
        """, bg='#0d1117', fg='#8b949e', font=('Consolas',10), justify='left').pack(anchor='w', padx=20, pady=10)

    # ── Log ───────────────────────────────────────────────────
    def _log(self, msg):
        self._flush_log(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def _export(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Texto","*.txt")], title="Salvar log")
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self.log_box.get('1.0', 'end'))
            messagebox.showinfo("Salvo", f"Log salvo em:\n{path}")

    # ── Start / Stop ──────────────────────────────────────────
    def _stop(self):
        self._mp_stop.set()
        if self._rec_proc and self._rec_proc.is_alive():
            self._rec_proc.terminate()
            self._rec_proc = None
        self._log("⛔ Parado pelo usuário.")
        self.speed_lbl.config(text=""); self.hw_speed_l.config(text="")
        self._wiz_reset_start_button()

    def _start(self):
        # Mata processo anterior se ainda estiver rodando
        if self._rec_proc and self._rec_proc.is_alive():
            messagebox.showwarning("Em execução", "Uma recuperação já está em andamento.\nClique em PARAR primeiro.")
            return

        words_raw = [e.get().strip().lower() for e in self.word_entries]
        seed_size = self.seed_size_var.get()
        words_raw = words_raw[:seed_size]

        known_words, missing_positions = [], []
        for i, w in enumerate(words_raw):
            if not w: missing_positions.append(i)
            else:     known_words.append(w)

        if not missing_positions:
            messagebox.showerror("Erro", "Nenhuma palavra em branco encontrada.\nDeixe em branco as que não lembra.")
            return

        wl = _get_wordlist()
        invalid = [w for w in known_words if w not in wl]
        if invalid:
            messagebox.showerror("Erro",
                f"Estas palavras não estão na lista BIP39:\n{', '.join(invalid)}\n\nVerifique a ortografia.")
            return

        addr = self.addr_entry.get().strip()
        if not addr:
            messagebox.showerror("Erro", "Insira o endereço Bitcoin.")
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
                messagebox.showerror("Erro",
                    f"Posições inválidas. Insira números de 1 a {seed_size} separados por espaço.")
                return

        n_missing = len(missing_positions)
        combos    = 2048 ** n_missing
        if combos > 10_000_000:
            cdiv = checksum_divisor(seed_size)
            effective = combos // cdiv
            _, _, secs = feasibility(effective, workers)
            if not messagebox.askyesno("⚠️ Aviso",
                    f"{n_missing} palavra(s) ausente(s) → {combos:,} combinações\n"
                    f"Após filtro de checksum: ~{effective:,} efetivas (÷{cdiv})\n"
                    f"Tempo estimado (v4.5): {fmt_time(secs)}\n\nIniciar mesmo assim?"):
                return

        # Reset visual
        self._mp_stop.clear()
        # Recria a fila IPC para limpar mensagens antigas
        self._ipc_queue = mp.Queue()
        self.log_box.config(state='normal')
        self.log_box.delete('1.0', 'end')
        self.log_box.config(state='disabled')
        self.prog_var.set(0)
        self.prog_lbl.config(text="0%")
        self.speed_lbl.config(text=""); self.hw_speed_l.config(text="")
        self._last_done = 0
        self._last_time = 0
        self._start_time = time.time()

        self._log("▶ Iniciando recuperação [v4.5 — mp.Process + Pool]")
        self._log(f"  Endereço alvo    : {addr}")
        self._log(f"  Derivação        : {path}")
        self._log(f"  Passphrase       : {'(vazia)' if not passphrase else '***'}")
        self._log(f"  Palavras ausentes: {n_missing} nas posições {[x+1 for x in missing_positions]}")
        self._log(f"  Workers de CPU   : {workers} de {CPU_COUNT} núcleos ⚡")
        self._log(f"  Filtro checksum  : ATIVO — ~2048× menos chamadas PBKDF2")
        if hint_typo:
            similar = similar_words(hint_typo, max_dist=2)
            self._log(f"  Busca de typo    : '{hint_typo}' → {len(similar)} palavras similares")
        if hint_starts:
            self._log(f"  Filtro padrão    : começa com '{hint_starts}'")
        if hint_length > 0:
            self._log(f"  Filtro tamanho   : {hint_length} letras")

        self.worker_pids = []
        self._is_boosted = False
        priority = self.priority_var.get() if hasattr(self, 'priority_var') else 'below'

        params = dict(
            known_words=known_words, missing_positions=missing_positions,
            passphrase=passphrase, target=addr, path=path,
            addr_limit=addr_limit, change_limit=change_limit,
            hint_starts=hint_starts, hint_length=hint_length,
            hint_typo=hint_typo, seed_size=seed_size, workers=workers,
            priority=priority)

        pr_label = {'normal':'Normal','below':'Baixa','idle':'Muito baixa'}.get(priority, priority)
        self._log(f"  Prioridade do SO : {pr_label}"
                   + ("  (boost automático ligado)" if getattr(self, 'idle_boost_var', None) and self.idle_boost_var.get() else ""))

        # ── CORREÇÃO WINDOWS: cria mp.Process (não threading.Thread)
        # O Pool é criado DENTRO do processo filho, nunca na thread da GUI.
        # daemon=False obrigatório — processo daemon não pode criar filhos (Pool)
        self._rec_proc = mp.Process(
            target=_recovery_process,
            args=(params, self._ipc_queue, self._mp_stop),
            daemon=False)
        self._rec_proc.start()

        # FIX v4.5: o botão continuava mostrando "▶ Iniciar recuperação"
        # mesmo com a busca já rodando — parecia que o clique não tinha
        # feito nada. Agora ele muda de estado imediatamente e só volta
        # ao normal quando o processo termina (msg 'done'/'error') ou é
        # parado (_stop()).
        self.wiz_next_btn.config(text="⏳ Buscando... (veja o LOG abaixo)",
                                 state='disabled', bg='#30363d', fg='#8b949e')
        self.wiz_back_btn.config(state='disabled')


# ══════════════════════════════════════════════════════════════
# INTRO SCREEN
# ══════════════════════════════════════════════════════════════
import random, math as _math

class IntroScreen:
    W, H = 900, 560
    _NODES = [
        (80,80),(220,80),(380,80),(540,80),(700,80),(820,80),
        (80,180),(180,180),(340,180),(500,180),(660,180),(820,180),
        (80,280),(240,280),(420,280),(580,280),(740,280),(820,280),
        (80,380),(200,380),(360,380),(520,380),(680,380),(820,380),
        (80,460),(220,460),(400,460),(560,460),(720,460),(820,460),
    ]
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
    _MAX_PARTICLES = 12

    def __init__(self, root, launch_callback):
        self.root      = root
        self.callback  = launch_callback
        self._running  = True
        self._phase    = 'boot'
        self._tick     = 0
        self._after_id = None
        self._drawn    = 0
        self._particles     = []
        self._particle_pool = []
        self._btn_alpha  = 0
        self._logo_alpha = 0

        root.title("BIP39 Wallet Recovery v4.5")
        root.geometry(f"{self.W}x{self.H}")
        root.resizable(False, False)
        root.configure(bg='#010c18')
        root.update_idletasks()
        sw = root.winfo_screenwidth(); sh = root.winfo_screenheight()
        root.geometry(f"{self.W}x{self.H}+{(sw-self.W)//2}+{(sh-self.H)//2}")

        self.canvas = tk.Canvas(root, width=self.W, height=self.H,
                                bg='#010c18', highlightthickness=0)
        self.canvas.pack(fill='both', expand=True)
        self._build_static()
        self._animate()

    def _build_static(self):
        c = self.canvas
        for x in range(0, self.W, 40):
            for y in range(0, self.H, 40):
                c.create_oval(x-1,y-1,x+1,y+1, fill='#0a1f35', outline='')
        self._edge_ids = []
        for a, b in self._EDGES:
            ax,ay=self._NODES[a]; bx,by=self._NODES[b]
            self._edge_ids.append(c.create_line(ax,ay,bx,by, fill='#051525', width=1))
        self._node_ids = []
        for x,y in self._NODES:
            self._node_ids.append(
                c.create_oval(x-4,y-4,x+4,y+4, fill='#051525', outline='#051525', width=1))
        self._ring1    = c.create_oval(390,210,510,330, outline='#1f6feb', width=2)
        self._ring2    = c.create_oval(378,198,522,342, outline='#0d3a7a', width=1)
        self._logo_btc = c.create_text(450,270, text='₿', fill='#0a2a5e', font=('Consolas',42,'bold'))
        self._logo_title  = c.create_text(450,390, text='B I P 3 9  W A L L E T  R E C O V E R Y',
                                          fill='#051525', font=('Consolas',11,'bold'))
        self._logo_sub    = c.create_text(450,412, text='v4.5 · Multiprocessing · 100% Offline',
                                          fill='#051525', font=('Consolas',9))
        self._logo_author = c.create_text(450,500, text='by leonardoramcke',
                                          fill='#051525', font=('Consolas',9))
        self._btn_rect = c.create_rectangle(350,430,550,468, fill='#010c18', outline='#051525', width=1)
        self._btn_text = c.create_text(450,449, text='▶ INICIAR', fill='#051525', font=('Consolas',12,'bold'))
        for item in (self._btn_rect, self._btn_text):
            c.tag_bind(item, '<Button-1>', self._on_start)
            c.tag_bind(item, '<Enter>',    self._btn_hover_on)
            c.tag_bind(item, '<Leave>',    self._btn_hover_off)
        for _ in range(self._MAX_PARTICLES * 4):
            oid = c.create_oval(-10,-10,-2,-2, fill='#58a6ff', outline='', state='hidden')
            self._particle_pool.append(oid)

    @staticmethod
    def _lerp_color(c1, c2, t):
        r1,g1,b1=int(c1[1:3],16),int(c1[3:5],16),int(c1[5:7],16)
        r2,g2,b2=int(c2[1:3],16),int(c2[3:5],16),int(c2[5:7],16)
        return f'#{int(r1+(r2-r1)*t):02x}{int(g1+(g2-g1)*t):02x}{int(b1+(b2-b1)*t):02x}'

    def _animate(self):
        if not self._running: return
        self._tick += 1
        c = self.canvas; t = self._tick

        if self._phase == 'boot':
            if t % 3 == 0 and self._drawn < len(self._NODES):
                x,y = self._NODES[self._drawn]
                c.itemconfig(self._node_ids[self._drawn], fill='#1f6feb', outline='#58a6ff')
                self._drawn += 1
            if self._drawn >= len(self._NODES):
                self._phase = 'draw'; self._drawn = 0

        elif self._phase == 'draw':
            for _ in range(2):
                if self._drawn < len(self._EDGES):
                    c.itemconfig(self._edge_ids[self._drawn], fill='#0d3a6e', width=1)
                    self._drawn += 1
            if self._drawn >= len(self._EDGES):
                self._phase = 'particles'; self._spawn_particles(8)

        elif self._phase in ('particles','ready'):
            self._update_particles()
            if self._logo_alpha < 255:
                self._logo_alpha = min(255, self._logo_alpha + 6)
                a = self._logo_alpha / 255
                c.itemconfig(self._logo_btc,    fill=self._lerp_color('#0a2a5e','#58a6ff',a))
                c.itemconfig(self._logo_title,   fill=self._lerp_color('#051525','#c9d1d9',a))
                c.itemconfig(self._logo_sub,     fill=self._lerp_color('#051525','#484f58',a))
                c.itemconfig(self._logo_author,  fill=self._lerp_color('#051525','#484f58',a))
            pulse = 0.5 + 0.5*_math.sin(t*0.08)
            c.itemconfig(self._ring1, outline=self._lerp_color('#061d3d','#1f6feb',pulse))
            c.itemconfig(self._ring2, outline=self._lerp_color('#030e1e','#0d3a7a',pulse*0.6))
            if t % 18 == 0: self._spawn_particles(2)
            if self._logo_alpha > 150:
                if self._btn_alpha < 255:
                    self._btn_alpha = min(255, self._btn_alpha + 5)
                    a = self._btn_alpha / 255
                    c.itemconfig(self._btn_rect, outline=self._lerp_color('#051525','#1f6feb',a))
                    c.itemconfig(self._btn_text, fill=self._lerp_color('#051525','#58a6ff',a))
                if self._btn_alpha >= 255 and self._phase != 'ready':
                    self._phase = 'ready'

        self._after_id = self.root.after(30, self._animate)

    def _get_pool_oval(self):
        return self._particle_pool.pop() if self._particle_pool else None

    def _return_pool_oval(self, oid):
        self.canvas.itemconfig(oid, state='hidden')
        self._particle_pool.append(oid)

    def _spawn_particles(self, n):
        for _ in range(n):
            if len(self._particles) >= self._MAX_PARTICLES: break
            edge = random.choice(self._EDGES)
            a,b  = edge
            ax,ay=self._NODES[a]; bx,by=self._NODES[b]
            color = random.choice(['#58a6ff','#f7b731','#3fb950','#79c0ff'])
            ovals = []
            for _ in range(4):
                oid = self._get_pool_oval()
                if oid is None: break
                ovals.append(oid)
            if len(ovals) < 4:
                for oid in ovals: self._return_pool_oval(oid)
                continue
            self._particles.append({'ax':ax,'ay':ay,'bx':bx,'by':by,
                                    't':0.0,'speed':random.uniform(0.015,0.04),
                                    'color':color,'ovals':ovals})

    def _update_particles(self):
        c = self.canvas; dead = []
        for p in self._particles:
            p['t'] += p['speed']
            if p['t'] >= 1.0: dead.append(p); continue
            ax,ay,bx,by = p['ax'],p['ay'],p['bx'],p['by']
            x = ax+(bx-ax)*p['t']; y = ay+(by-ay)*p['t']
            c.itemconfig(p['ovals'][0], fill=p['color'], outline='white', state='normal')
            c.coords(p['ovals'][0], x-4,y-4,x+4,y+4)
            for i,dt in enumerate([0.06,0.12,0.18]):
                tt=max(0,p['t']-dt); tx=ax+(bx-ax)*tt; ty=ay+(by-ay)*tt
                r=2-i; tid=p['ovals'][i+1]
                if r>0:
                    c.itemconfig(tid, fill=p['color'], outline='', state='normal')
                    c.coords(tid, tx-r,ty-r,tx+r,ty+r)
                else:
                    c.itemconfig(tid, state='hidden')
        for p in dead:
            for oid in p['ovals']: self._return_pool_oval(oid)
            self._particles.remove(p)

    def _btn_hover_on(self, _=None):
        if self._btn_alpha >= 200:
            self.canvas.itemconfig(self._btn_rect, fill='#0d2a4a', outline='#58a6ff', width=2)
            self.canvas.itemconfig(self._btn_text, fill='#ffffff')
            self.canvas.configure(cursor='hand2')

    def _btn_hover_off(self, _=None):
        if self._btn_alpha >= 200:
            self.canvas.itemconfig(self._btn_rect, fill='#010c18', outline='#1f6feb', width=1)
            self.canvas.itemconfig(self._btn_text, fill='#58a6ff')
            self.canvas.configure(cursor='')

    def _on_start(self, _=None):
        self._running = False
        # FIX v4.5: havia uma animação já agendada (root.after) pra rodar
        # daqui a pouco. Sem cancelar, o Tcl tenta executá-la numa janela
        # que acabou de ser destruída → "invalid command name ..._animate"
        # no terminal (inofensivo, mas feio e evitável).
        if self._after_id is not None:
            try:
                self.root.after_cancel(self._after_id)
            except Exception:
                pass
        self.root.destroy()
        self.callback()


# ══════════════════════════════════════════════════════════════
# Entry point
# freeze_support() OBRIGATÓRIO no Windows com PyInstaller
# ══════════════════════════════════════════════════════════════
def _launch_main():
    root = tk.Tk()
    App(root)
    root.mainloop()

if __name__ == '__main__':
    mp.freeze_support()   # obrigatório Windows + PyInstaller
    intro_root = tk.Tk()
    IntroScreen(intro_root, _launch_main)
    intro_root.mainloop()