import os
import math
import random
import hashlib

"""
Class ADRS, armazena os endereços do sphincs
"""


class ADRS:
    # TYPES
    WOTS_HASH = 0
    WOTS_PK = 1
    TREE = 2
    FORS_TREE = 3
    FORS_ROOTS = 4

    def __init__(self):
        self.layer = 0
        self.tree_address = 0

        self.type = 0

        # Words for which role can change depending on ADRS.type
        self.word_1 = 0
        self.word_2 = 0
        self.word_3 = 0

    def copy(self):
        adrs = ADRS()
        adrs.layer = self.layer
        adrs.tree_address = self.tree_address

        adrs.type = self.type
        adrs.word_1 = self.word_1
        adrs.word_2 = self.word_2
        adrs.word_3 = self.word_3
        return adrs

    def to_bin(self):
        adrs = int(self.layer).to_bytes(4, byteorder='big')
        adrs += self.tree_address.to_bytes(12, byteorder='big')

        adrs += self.type.to_bytes(4, byteorder='big')
        adrs += self.word_1.to_bytes(4, byteorder='big')
        adrs += self.word_2.to_bytes(4, byteorder='big')
        adrs += self.word_3.to_bytes(4, byteorder='big')

        return adrs

    def set_type(self, val):
        self.type = val

        self.word_2 = 0
        self.word_3 = 0
        self.word_1 = 0

    def set_layer_address(self, val):
        self.layer = val

    def set_tree_address(self, val):
        self.tree_address = val

    def set_key_pair_address(self, val):
        self.word_1 = val

    def get_key_pair_address(self):
        return self.word_1

    def set_chain_address(self, val):
        self.word_2 = val

    def set_hash_address(self, val):
        self.word_3 = val

    def set_tree_height(self, val):
        self.word_2 = val

    def get_tree_height(self):
        return self.word_2

    def set_tree_index(self, val):
        self.word_3 = val

    def get_tree_index(self):
        return self.word_3

# FUNÇÕES DE HASH TWEAKABLES


def hash_(seed, adrs: ADRS, value, digest_size):
    hashing = hashlib.sha256()

    hashing.update(seed)
    hashing.update(adrs.to_bin())
    hashing.update(value)

    hashed = hashing.digest()[:digest_size]

    return hashed


def prf(secret_seed, adrs, digest_size):
    # Pseudorandom key generation
    random.seed(int.from_bytes(secret_seed + adrs.to_bin(), "big"))
    return random.randint(0, 256 ** digest_size - 1).to_bytes(digest_size, byteorder='big')


def hash_msg(r, public_seed, public_root, value, digest_size):
    # Comprime a mensagem a ser assinada
    hashing = hashlib.sha256()

    hashing.update(r)
    hashing.update(public_seed)
    hashing.update(public_root)
    hashing.update(value)

    hashed = hashing.digest()[:digest_size]

    i = 0
    while len(hashed) < digest_size:
        i += 1
        hashing = hashlib.sha256()

        hashing.update(r)
        hashing.update(public_seed)
        hashing.update(public_root)
        hashing.update(value)
        hashing.update(bytes([i]))

        hashed += hashing.digest()[:digest_size - len(hashed)]

    return hashed


def prf_msg(secret_seed, opt, m, digest_size):
    # Gera aleatoriedade para a compressão da mensagem
    random.seed(int.from_bytes(secret_seed + opt + hash_msg(b'0', b'0', b'0', m, digest_size * 2), "big"))
    return random.randint(0, 256 ** digest_size - 1).to_bytes(digest_size, byteorder='big')


# Input: len_X-byte string X, int w, tamanho do output out_len
# Output: out_len int array basew
def base_w(x, w, out_len):
    v_in = 0
    v_out = 0
    total = 0
    bits = 0
    basew = list()

    for consumed in range(out_len):
        if bits == 0:
            total = x[v_in]
            v_in += 1
            bits += 8
        bits -= math.floor(math.log(w, 2))
        basew.append((total >> bits) % w)
        v_out += 1

    return basew
