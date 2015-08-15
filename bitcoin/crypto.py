import hashlib, hmac, struct
from bitcoin import *
from bitcoin.pyspecials import unhexify, hexify, from_bytes_to_string, from_string_to_bytes

# def pbkdf2_hmac(name, password, salt, rounds, dklen=None):
#     """Returns the result of the Password-Based Key Derivation Function 2"""
#     h = hmac.new(key=password, digestmod=lambda d=b'': hashlib.new(name, d))
#     hs = h.copy()
#     hs.update(salt)
#
#     blocks = bytearray()
#     dklen = hs.digest_size if dklen is None else dklen
#     block_count, last_size = divmod(dklen, hs.digest_size)
#     block_count += last_size > 0
#
#     for block_number in xrange(1, block_count + 1):
#         hb = hs.copy()
#         hb.update(struct.pack('>L', block_number))
#         U = bytearray(hb.digest())
#
#         if rounds > 1:
#             Ui = U
#             for i in xrange(rounds - 1):
#                 hi = h.copy()
#                 hi.update(Ui)
#                 Ui = bytearray(hi.digest())
#                 for j in xrange(hs.digest_size):
#                     U[j] ^= Ui[j]
#         blocks.extend(U)
#
#     if last_size:
#         del blocks[dklen:]
#     return bytes(blocks)

# Modifications based on https://matt.ucc.asn.au/src/pbkdf2.py
def bin_pbkdf2_hmac(hashname, password, salt, rounds, dklen=None):
    """Password-Based Key Derivation Function (PBKDF) 2"""
    h = hmac.new(key=password, digestmod=lambda d=b'': hashlib.new(hashname, d))
    dklen = h.digest_size if dklen is None else dklen
    def prf(data):
        hm = h.copy()
        hm.update(data)
        return bytearray(hm.digest())
    key = bytearray()
    i = 1
    while len(key) < dklen:
        T = U = prf(salt + struct.pack('>i', i))
        for _ in range(rounds - 1):
            U = prf(U)
            T = bytearray(x ^ y for x, y in zip(T, U))
        key += T
        i += 1
    return bytes(key[:dklen])

def pbkdf2_hmac_sha512(password, salt):
    password, salt = from_str_to_bytes(password), from_str_to_bytes(salt)
    if hasattr(hashlib, 'pbkdf2_hmac'):
        b = hashlib.pbkdf2_hmac('sha512', password, salt, 2048, 64)
    else:
        b = bin_pbkdf2_hmac('sha512', password, salt, 2048, 64)
    return hexify(b)

hmac_sha256 = lambda k, s: hmac.new(k, s, hashlib.sha256)
hmac_sha512 = lambda k, s: hmac.new(k, s, hashlib.sha512)