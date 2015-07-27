from bitcoin.main import *
from bitcoin.transaction import *

def ecdsa_raw_sign(msghash, priv, low_s=True):
    """Deterministically sign binary msghash (z) with k, returning (vbyte, r, s) as ints"""
    z = hash_to_int(msghash)
    k = deterministic_generate_k(msghash, priv)

    r, y = fast_multiply(G, k)
    priv = decode_privkey(priv)
    s = inv(k, N) * (z + r * priv) % N
    if low_s:
        s = N-s if s>N//2 else s
    return 27+(y % 2), r, s		# vbyte, r, s


def ecdsa_sign(msg, priv):
    """Sign a msg with privkey, returning base64 signature"""
    sighash = electrum_sig_hash(msg)
    v, r, s = ecdsa_raw_sign(sighash, priv)
    return encode_sig(v, r, s)


def ecdsa_raw_verify(msghash, vrs, pub):
    """Takes msghash, tuple of (vbyte, r, s) and pubkey as hex, verifies signature"""
    v, r, s = vrs

    w = inv(s, N)
    z = hash_to_int(msghash)

    u1, u2 = z*w % N, r*w % N
    pub = decode_pubkey(pub)
    x, y = fast_add(fast_multiply(G, u1), fast_multiply(pub, u2))

    return r == x


def ecdsa_verify(msg, sig, pub):
    """Verify (base64) signature of a message using pubkey"""
    sighash = electrum_sig_hash(msg)
    vrs = decode_sig(sig)
    return ecdsa_raw_verify(sighash, vrs, pub)


def ecdsa_raw_recover(msghash, vrs):
    v, r, s = vrs

    x = r
    xcubedaxb = (x*x*x+A*x+B) % P
    beta = pow(xcubedaxb, (P+1)//4, P)
    y = beta if ((v % 2) ^ (beta % 2)) else (P - beta)
    # If xcubedaxb is not a quadratic residue, then r cannot be the x coord
    # for a point on the curve, and so the sig is invalid
    if (xcubedaxb - y*y) % P != 0:
        return False
    z = hash_to_int(msghash)
    Gz = jacobian_multiply((Gx, Gy, 1), (N - z) % N)
    XY = jacobian_multiply((x, y, 1), s)
    Qr = jacobian_add(Gz, XY)
    Q = jacobian_multiply(Qr, inv(r, N))
    Q = from_jacobian(Q)

    if not ecdsa_raw_verify(msghash, vrs, Q):
        return False
    return Q


def ecdsa_recover(msg, sig):
    """Recover pubkey from message and base64 signature"""
    sighash = electrum_sig_hash(msg)
    vrs = decode_sig(sig)
    Q = ecdsa_raw_recover(sighash, vrs)
    return encode_pubkey(Q, 'hex')


# TRANSACTION.py

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