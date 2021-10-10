from sphincs_aux import *

# WOTS⁺
# O Sphincs+ utiliza um One-Time Signature (OTS),
# onde cada par de chaves pode ser utilizado para assinar uma única mensagem.


class Wots:
    def __init__(self):

        self._n = 16  # Parametro de segurança 
        self._w = 16  # Parametro de Winternitz (4, 16 ou 256)
        self._h = 64  # Altura da Hypertree
        self._d = 8   # Camadas da Hypertree
        self._a = 15  # Numero de folhas de cada arvore no FORS

        self._len_1 = math.ceil(8 * self._n / math.log(self._w, 2))
        self._len_2 = math.floor(math.log(self._len_1 * (self._w - 1), 2) / math.log(self._w, 2)) + 1
        self._len_0 = self._len_1 + self._len_2 # n-bit values in WOTS+ sk, pk, and signature.

    # Input: Input string X, start index i, number of steps s, public seed PK.seed, address ADRS
    # Output: value of F iterated s times on X
    def chain(self, x, i, s, public_seed, adrs: ADRS):
        if s == 0:
            return bytes(x)

        if (i + s) > (self._w - 1):
            return -1

        tmp = self.chain(x, i, s - 1, public_seed, adrs)

        adrs.set_hash_address(i + s - 1)
        tmp = hash_(public_seed, adrs, tmp, self._n)

        return tmp

    # Input: secret seed SK.seed, address ADRS
    # Output: WOTS+ private key sk
    def wots_sk_gen(self, secret_seed, adrs: ADRS): 
        sk = []
        for i in range(self._len_0):
            adrs.set_chain_address(i)
            adrs.set_hash_address(0)
            sk.append(prf(secret_seed, adrs.copy(), self._n))
        return sk

    # Input: secret seed SK.seed, address ADRS, public seed PK.seed
    # Output: WOTS+ public key pk
    def wots_pk_gen(self, secret_seed, public_seed, adrs: ADRS):
        wots_pk_adrs = adrs.copy()
        tmp = bytes()
        for i in range(self._len_0):
            adrs.set_chain_address(i)
            adrs.set_hash_address(0)
            sk = prf(secret_seed, adrs.copy(), self._n)
            tmp += bytes(self.chain(sk, 0, self._w - 1, public_seed, adrs.copy()))

        wots_pk_adrs.set_type(ADRS.WOTS_PK)
        wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())

        pk = hash_(public_seed, wots_pk_adrs, tmp, self._n)
        return pk

    # Input: Message M, secret seed SK.seed, public seed PK.seed, address ADRS
    # Output: WOTS+ signature sig
    def wots_sign(self, m, secret_seed, public_seed, adrs):
        checksum = 0

        msg = base_w(m, self._w, self._len_1)

        for i in range(self._len_1):
            checksum += self._w - 1 - msg[i]

        padding = (self._len_2 * math.floor(math.log(self._w, 2))) % 8 if (self._len_2 * math.floor(
            math.log(self._w, 2))) % 8 != 0 else 8
        checksum = checksum << (8 - padding)
        checksumb = checksum.to_bytes(math.ceil((self._len_2 * math.floor(math.log(self._w, 2))) / 8), byteorder='big')
        checksumw = base_w(checksumb, self._w, self._len_2)
        msg += checksumw

        sig = []
        for i in range(self._len_0):
            adrs.set_chain_address(i)
            adrs.set_hash_address(0)
            sk = prf(secret_seed, adrs.copy(), self._n)
            sig += [self.chain(sk, 0, msg[i], public_seed, adrs.copy())]

        return sig

    def wots_pk_from_sig(self, sig, m, public_seed, adrs: ADRS):
        checksum = 0
        wots_pk_adrs = adrs.copy()

        msg = base_w(m, self._w, self._len_1)

        for i in range(0, self._len_1):
            checksum += self._w - 1 - msg[i]

        padding = (self._len_2 * math.floor(math.log(self._w, 2))) % 8 if (self._len_2 * math.floor(
            math.log(self._w, 2))) % 8 != 0 else 8
        checksum = checksum << (8 - padding)
        checksumb = checksum.to_bytes(math.ceil((self._len_2 * math.floor(math.log(self._w, 2))) / 8), byteorder='big')
        checksumw = base_w(checksumb, self._w, self._len_2)
        msg += checksumw

        tmp = bytes()
        for i in range(self._len_0):
            adrs.set_chain_address(i)
            tmp += self.chain(sig[i], msg[i], self._w - 1 - msg[i], public_seed, adrs.copy())

        wots_pk_adrs.set_type(ADRS.WOTS_PK)
        wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        pk_sig = hash_(public_seed, wots_pk_adrs, tmp, self._n)
        return pk_sig