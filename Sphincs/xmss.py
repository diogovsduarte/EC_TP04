import math
from sphincs_aux import *
from wots import Wots


# XMSS - Extended Merkle Signature Scheme


class Xmss:

    def __init__(self):
        
        self._n = 16
        self._w = 16
        self._h = 64
        self._d = 8
        self.wots = Wots()

        self._len_1 = math.ceil(8 * self._n / math.log(self._w, 2))
        self._len_2 = math.floor(math.log(self._len_1 * (self._w - 1), 2) / math.log(self._w, 2)) + 1
        self._len_0 = self._len_1 + self._len_2
        self._h_prime = self._h // self._d
     

    def sig_wots_from_sig_xmss(self, sig):
        return sig[0:self._len_0]

    def auth_from_sig_xmss(self, sig):
        return sig[self._len_0:]

    def sigs_xmss_from_sig_hypertree(self, sig):
        sigs = [sig[i * (self._h_prime + self._len_0):(i + 1) * (self._h_prime + self._len_0)] for i in range(self._d)]
        return sigs

    # Input: Secret seed SK.seed, start index s, target node height z, public seed PK.seed, address ADRS
    # Output: n-byte root node - top node on Stack
    def treehash(self, secret_seed, s, z, public_seed, adrs: ADRS):
        if s % (1 << z) != 0:
            return -1

        stack = []

        for i in range(2 ** z):
            adrs.set_type(ADRS.WOTS_HASH)
            adrs.set_key_pair_address(s + i)
            node = self.wots.wots_pk_gen(secret_seed, public_seed, adrs.copy())

            adrs.set_type(ADRS.TREE)
            adrs.set_tree_height(1)
            adrs.set_tree_index(s + i)

            if len(stack) > 0:
                while stack[len(stack) - 1]['height'] == adrs.get_tree_height():
                    adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                    node = hash_(public_seed, adrs.copy(), stack.pop()['node'] + node, self._n)
                    adrs.set_tree_height(adrs.get_tree_height() + 1)

                    if len(stack) <= 0:
                        break

            stack.append({'node': node, 'height': adrs.get_tree_height()})

        return stack.pop()['node']

    # Input: Secret seed SK.seed, public seed PK.seed, address ADRS
    # Output: XMSS public key PK
    def xmss_pk_gen(self, secret_seed, public_key, adrs: ADRS):
        pk = self.treehash(secret_seed, 0, self._h_prime, public_key, adrs.copy())
        return pk

    # Input: n-byte message M, secret seed SK.seed, index idx, public seed PK.seed, address ADRS
    # Output: XMSS signature SIG_XMSS = (sig || AUTH)
    def xmss_sign(self, m, secret_seed, idx, public_seed, adrs):
        auth = []
        for j in range(self._h_prime):
            ki = math.floor(idx // 2 ** j)
            if ki % 2 == 1:  # XORING idx/ 2**j with 1
                ki -= 1
            else:
                ki += 1

            auth += [self.treehash(secret_seed, ki * 2 ** j, j, public_seed, adrs.copy())]

        adrs.set_type(ADRS.WOTS_HASH)
        adrs.set_key_pair_address(idx)

        sig = self.wots.wots_sign(m, secret_seed, public_seed, adrs.copy())
        sig_xmss = sig + auth
        return sig_xmss

    # Input: index idx, XMSS signature SIG_XMSS = (sig || AUTH), n-byte message M, public seed PK.seed, address ADRS
    # Output: n-byte root value node[0]
    def xmss_pk_from_sig(self, idx, sig_xmss, m, public_seed, adrs):
        adrs.set_type(ADRS.WOTS_HASH)
        adrs.set_key_pair_address(idx)
        sig = self.sig_wots_from_sig_xmss(sig_xmss)
        auth = self.auth_from_sig_xmss(sig_xmss)

        node_0 = self.wots.wots_pk_from_sig(sig, m, public_seed, adrs.copy())
        node_1 = 0

        adrs.set_type(ADRS.TREE)
        adrs.set_tree_index(idx)
        for i in range(self._h_prime):
            adrs.set_tree_height(i + 1)

            if math.floor(idx / 2 ** i) % 2 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node_1 = hash_(public_seed, adrs.copy(), node_0 + auth[i], self._n)
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node_1 = hash_(public_seed, adrs.copy(), auth[i] + node_0, self._n)

            node_0 = node_1

        return node_0

    # HYPERTREE XMSS
    # Por questão de eficiência, é utilizado uma HYPERTREE (árvore de árvores) descrita na documentação
    # =================================================

    # Input: Private seed SK.seed, public seed PK.seed
    # Output: Hypertree public key PK_HT
    def hypertree_pk_gen(self, secret_seed, public_seed):
        adrs = ADRS()
        adrs.set_layer_address(self._d - 1)
        adrs.set_tree_address(0)
        root = self.xmss_pk_gen(secret_seed, public_seed, adrs.copy())
        return root

    # Input: Mensagem M, private seed SK.seed, public seed PK.seed, tree index idx_tree, leaf index idx_leaf
    # Output: Assinatura HT SIG_HYPERTREE
    def hypertree_sign(self, m, secret_seed, public_seed, idx_tree, idx_leaf):
        adrs = ADRS()
        adrs.set_layer_address(0)
        adrs.set_tree_address(idx_tree)

        sig_tmp = self.xmss_sign(m, secret_seed, idx_leaf, public_seed, adrs.copy())
        sig_hypertree = sig_tmp
        root = self.xmss_pk_from_sig(idx_leaf, sig_tmp, m, public_seed, adrs.copy())

        for j in range(1, self._d):
            idx_leaf = idx_tree % 2 ** self._h_prime
            idx_tree = idx_tree >> self._h_prime

            adrs.set_layer_address(j)
            adrs.set_tree_address(idx_tree)

            sig_tmp = self.xmss_sign(root, secret_seed, idx_leaf, public_seed, adrs.copy())
            sig_hypertree = sig_hypertree + sig_tmp

            if j < self._d - 1:
                root = self.xmss_pk_from_sig(idx_leaf, sig_tmp, root, public_seed, adrs.copy())

        return sig_hypertree

    # Input: Mensagem M, assinatura SIG_HYPERTREE, public seed PK.seed, tree index idx_tree, leaf index idx_leaf, HT public key PK_HT
    # Output: Boolean
    def hypertree_verify(self, m, sig_hypertree, public_seed, idx_tree, idx_leaf, public_key_hypertree):
        adrs = ADRS()

        sigs_xmss = self.sigs_xmss_from_sig_hypertree(sig_hypertree)
        sig_tmp = sigs_xmss[0]

        adrs.set_layer_address(0)
        adrs.set_tree_address(idx_tree)
        node = self.xmss_pk_from_sig(idx_leaf, sig_tmp, m, public_seed, adrs)

        for j in range(1, self._d):
            idx_leaf = idx_tree % 2 ** self._h_prime
            idx_tree = idx_tree >> self._h_prime

            sig_tmp = sigs_xmss[j]

            adrs.set_layer_address(j)
            adrs.set_tree_address(idx_tree)

            node = self.xmss_pk_from_sig(idx_leaf, sig_tmp, node, public_seed, adrs)

        if node == public_key_hypertree:
            return True
        else:
            return False