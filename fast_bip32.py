"""
fast_bip32.py — Derivação BIP32 usando coincurve (bindings em C p/ libsecp256k1)
Substitui bip32utils (Python puro) por operações EC nativas — muito mais rápido
na etapa de derivação de chaves, que é o segundo maior custo depois do PBKDF2.
"""
import hashlib
import hmac
import coincurve

HARDEN = 0x80000000


class FastBIP32:
    __slots__ = ("privkey", "chaincode")

    def __init__(self, privkey: bytes, chaincode: bytes):
        self.privkey = coincurve.PrivateKey(privkey)
        self.chaincode = chaincode

    @classmethod
    def from_seed(cls, seed: bytes):
        I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        return cls(I[:32], I[32:])

    def child(self, index: int) -> "FastBIP32":
        if index & HARDEN:
            data = b"\x00" + self.privkey.secret + index.to_bytes(4, "big")
        else:
            pub = self.privkey.public_key.format(compressed=True)
            data = pub + index.to_bytes(4, "big")
        I = hmac.new(self.chaincode, data, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]
        child_priv = self.privkey.add(IL)
        obj = FastBIP32.__new__(FastBIP32)
        obj.privkey = child_priv
        obj.chaincode = IR
        return obj

    def public_key(self) -> bytes:
        return self.privkey.public_key.format(compressed=True)


if __name__ == "__main__":
    # ── Vetor de teste oficial BIP32 (Test vector 1) ──────────────
    # seed = 000102030405060708090a0b0c0d0e0f
    # m/0H/1/2H  →  pubkey esperado (compressed, hex):
    # 0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    m = FastBIP32.from_seed(seed)
    node = m.child(0 + HARDEN).child(1).child(2 + HARDEN)
    got = node.public_key().hex()
    expected = "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc"
    print("pubkey :", got)
    print("esperado:", expected)
    assert got == expected, "FALHA na derivação BIP32!"
    print("✅ Vetor de teste BIP32 OK — derivação correta")
