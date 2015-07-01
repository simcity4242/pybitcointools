from bitcoin.main import *
from bitcoin.pyspecials import *

import base64

def encode_sig(v, r, s):
    """Takes vbyte and (r,s) as ints, returns base64 string"""
    vb, rb, sb = from_int_to_byte(v), encode(r, 256), encode(s, 256)
    result = base64.b64encode(vb + b'\x00'*(32-len(rb)) + rb + b'\x00'*(32-len(sb)) + sb)
    return st(result)


def decode_sig(sig):
    """takes Base64 sig string and returns (vbyte, r, s) in binary"""
    bytez = base64.b64decode(sig)
    return from_byte_to_int(bytez[0]), decode(bytez[1:33], 256), decode(bytez[33:], 256)

# https://tools.ietf.org/html/rfc6979#section-3.2
def deterministic_generate_k(msghash, priv):
    hmac_sha_256 = lambda k, s: hmac.new(k, s, hashlib.sha256)
    v = bytearray([1]*32)	# b'\x01' * 32 
    k = bytearray(32) 		# b'\x00' * 32 
    priv = encode_privkey(priv, 'bin')					# binary private key
    msghash = encode(hash_to_int(msghash), 256, 32)		# encode msg hash as 32 bytes
    k = hmac_sha_256(k, v + b'\x00' + priv + msghash).digest()
    v = hmac_sha_256(k, v).digest()
    k = hmac_sha_256(k, v + b'\x01' + priv + msghash).digest()
    v = hmac_sha_256(k, v).digest()
    res = hmac_sha_256(k, v).digest()
    return decode(by(res), 256)
   #return decode(hmac_sha_256(k, v).digest(), 256)


def ecdsa_raw_sign(msghash, priv):
    """Deterministically sign binary msghash (z) with k, returning (vbyte, r, s) as ints"""
    z = hash_to_int(msghash)
    k = deterministic_generate_k(msghash, priv)

    r, y = fast_multiply(G, k)
    s = inv(k, N) * (z + r*decode_privkey(priv)) % N

    return 27+(y % 2), r, s		# vbyte, r, s


def ecdsa_sign(msg, priv):
    return encode_sig(*ecdsa_raw_sign(electrum_sig_hash(msg), priv))


def ecdsa_raw_verify(msghash, vrs, pub):
    """Takes msghash, tuple of (vbyte, r, s) and pubkey as hex"""
    v, r, s = vrs

    w = inv(s, N)
    z = hash_to_int(msghash)

    u1, u2 = z*w % N, r*w % N
    x, y = fast_add(fast_multiply(G, u1), fast_multiply(decode_pubkey(pub), u2))

    return r == x


def ecdsa_verify(msg, sig, pub):
    return ecdsa_raw_verify(electrum_sig_hash(msg), decode_sig(sig), pub)


def ecdsa_raw_recover(msghash, vrs):
    v, r, s = vrs

    x = r
    beta = pow(x*x*x+A*x+B, (P+1)//4, P)
    y = beta if v % 2 ^ beta % 2 else (P - beta)
    z = hash_to_int(msghash)
    Gz = jacobian_multiply((Gx, Gy, 1), (N - z) % N)
    XY = jacobian_multiply((x, y, 1), s)
    Qr = jacobian_add(Gz, XY)
    Q = jacobian_multiply(Qr, inv(r, N))
    Q = from_jacobian(Q)

    if ecdsa_raw_verify(msghash, vrs, Q):
        return Q
    return False


def ecdsa_recover(msg, sig):
    return encode_pubkey(ecdsa_raw_recover(electrum_sig_hash(msg), decode_sig(sig)), 'hex')

def signature_form(tx, i, script, hashcode=SIGHASH_ALL):
    i, hashcode = int(i), int(hashcode)
    if isinstance(tx, string_or_bytes_types):
        return serialize(signature_form(deserialize(tx), i, script, hashcode))
    newtx = copy.deepcopy(tx)
    for inp in newtx["ins"]:
        inp["script"] = ""
    newtx["ins"][i]["script"] = script
    if hashcode == SIGHASH_NONE:
        newtx["outs"] = []
    elif hashcode == SIGHASH_SINGLE:
        newtx["outs"] = newtx["outs"][:len(newtx["ins"])]
        for out in range(len(newtx["ins"]) - 1):
            out.value = 2**64 - 1
            out.script = ""
    elif hashcode == SIGHASH_ANYONECANPAY:
        newtx["ins"] = [newtx["ins"][i]]
    else:
        pass
    return newtx

# Making the actual signatures

    # If the S value is above the order of the curve divided by two, its
    # complement modulo the order could have been used instead, which is
    # one byte shorter when encoded correctly.
def der_encode_sig(v, r, s):
    """Takes (vbyte, r, s) as ints and returns hex der encode sig"""
    s = (N-s) if s > N//2 else s
    assert s < N//2
    b1, b2 = encode(r, 256), encode(s, 256)
    # TODO: check s < N // 2, otherwise s = complement (1 byte shorter)
    # https://gist.github.com/3aea5d82b1c543dd1d3c
    if r >= 2**255:
        b1 = b'\x00' + b1
    if s >= 2**255:
        b2 = b'\x00' + b2
    left = b'\x02' + encode(len(b1), 256, 1) + b1
    right = b'\x02' + encode(len(b2), 256, 1) + b2
    sighex = safe_hexlify(b'x\30' + encode(len(left+right), 256, 1) + left + right)	# TODO: standard format
    assert is_bip66(sighex)
    return sighex


def der_decode_sig(sig):
    """Takes hex der sig and returns (None, r, s) as ints"""
    sig = safe_unhexlify(sig)
    leftlen = decode(sig[3:4], 256)
    left = sig[4:4+leftlen]
    rightlen = decode(sig[5+leftlen:6+leftlen], 256)
    right = sig[6+leftlen:6+leftlen+rightlen]
    assert 3 + left + 3 + right + 1 == len(sig)		# check for new s code
    return (None, decode(left, 256), decode(right, 256))

def is_bip66(sig):
    """Takes hex string sig"""

    #https://raw.githubusercontent.com/bitcoin/bips/master/bip-0066.mediawiki
    #0x30  [total-len]  0x02  [R-len]  [R]  0x02  [S-len]  [S]  [sighash]
    #sig = changebase(sig, 16, 256) if IS_HEX else sig
    if isinstance(sig, string_types) and re.match('^[0-9a-fA-F]*$', sig):
        sig = bytearray.fromhex(sig)
    
    if len(sig) < 9 or len(sig) > 73: return False
    if (sig[0] != 0x30): return False
    if (sig[1] != len(sig)-3): return False
    rlen = sig[3]
    if (5+rlen >= len(sig)): return False
    slen = sig[5+rlen]
    if (rlen + slen + 7 != len(sig)): return False
    if (sig[2] != 0x02): return False
    if (rlen == 0): return False
    if (sig[4] & 0x80): return False
    if (rlen > 1 and (sig[4] == 0x00) and not (sig[5] & 0x80)): return False
    if (sig[4+rlen] != 0x02): return False
    if (slen == 0): return False
    if (sig[rlen+6] & 0x80): return False
    if (slen > 1 and (sig[6+rlen] == 0x00) and not (sig[7+rlen] & 0x80)): return False
    
    return True

def txhash(tx, hashcode=None):
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        tx = changebase(tx, 16, 256)
    if hashcode:
        return dbl_sha256(from_str_to_bytes(tx) + from_int_to_bytes(int(hashcode), 4))
    else:
        return safe_hexlify(bin_dbl_sha256(tx)[::-1])


def bin_txhash(tx, hashcode=None):
    return binascii.unhexlify(txhash(tx, hashcode))


def ecdsa_tx_sign(tx, priv, hashcode=SIGHASH_ALL):
    """Takes rawTx with scriptPubKey inserted"""
    rawsig = ecdsa_raw_sign(bin_txhash(tx, hashcode), priv)
    return der_encode_sig(*rawsig)+encode(hashcode, 16, 2)


def ecdsa_tx_verify(tx, sig, pub, hashcode=SIGHASH_ALL):
    return ecdsa_raw_verify(bin_txhash(tx, hashcode), der_decode_sig(sig), pub)


def ecdsa_tx_recover(tx, sig, hashcode=SIGHASH_ALL):
    z = bin_txhash(tx, hashcode)
    _, r, s = der_decode_sig(sig)
    left = ecdsa_raw_recover(z, (0, r, s))
    right = ecdsa_raw_recover(z, (1, r, s))
    return (encode_pubkey(left, 'hex'), encode_pubkey(right, 'hex'))