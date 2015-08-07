from bitcoin.main import *
from bitcoin.pyspecials import *
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
    if hashcode: return dbl_sha256(from_str_to_bytes(tx) + from_int_to_bytes(int(hashcode), 4))
    else:        return safe_hexlify(bin_dbl_sha256(tx)[::-1])


def bin_txhash(tx, hashcode=None):
    return binascii.unhexlify(txhash(tx, hashcode))


def ecdsa_tx_sign(tx, priv, hashcode=SIGHASH_ALL):
    """Takes rawTx with scriptPubKey inserted"""
    rawsig = ecdsa_raw_sign(bin_txhash(tx, hashcode), priv)
    return der_encode_sig(*rawsig) + encode(hashcode, 16, 2)


def ecdsa_tx_verify(tx, sig, pub, hashcode=SIGHASH_ALL):
    decoded_sig = der_decode_sig(sig)
    tx_digest = bin_txhash(tx, hashcode)
    return ecdsa_raw_verify(tx_digest, decoded_sig, pub)

def ecdsa_raw_verify(msghash, vrs, pub):
    """Takes msghash, DER sign (as ints), pubkey; verifies signature"""
    v, r, s = vrs

    w = inv(s, N)
    z = hash_to_int(msghash)

    u1 = z*w % N
    u2 = r*w % N
    pub = decode_pubkey(pub)
    first = fast_multiply(G, u1)
    second = fast_multiply(pub, u2)
    x, y = fast_add(first, second)

    return r == x

def ecdsa_tx_recover(tx, sig, hashcode=SIGHASH_ALL):
    z = bin_txhash(tx, hashcode)
    _, r, s = der_decode_sig(sig)
    left = ecdsa_raw_recover(z, (0, r, s))
    right = ecdsa_raw_recover(z, (1, r, s))
    return (encode_pubkey(left, 'hex'), encode_pubkey(right, 'hex'))

def verify_tx_input(tx, i, script, sig, pub):
    if re.match('^[0-9a-fA-F]*$', tx):
        tx = binascii.unhexlify(tx)
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    if not re.match('^[0-9a-fA-F]*$', sig):
        sig = safe_hexlify(sig)
    hashcode = decode(sig[-2:], 16)
    modtx = signature_form(tx, int(i), script, hashcode)
    return ecdsa_tx_verify(modtx, sig, pub, hashcode)


#pizzatxid = 'cca7507897abc89628f450e8b1e0c6fca4ec3f7b34cccf55f3f531c659ff4d79'
#verify_tx_input(tx, 0, inspk, inder, inpub)
#inder = "30450221009908144ca6539e09512b9295c8a27050d478fbb96f8addbc3d075544dc41328702201aa528be2b907d316d2da068dd9eb1e23243d97e444d59290d2fddf25269ee0e01"
#inpub = "042e930f39ba62c6534ee98ed20ca98959d34aa9e057cda01cfd422c6bab3667b76426529382c23f42b9b08d7832d4fee1d6b437a8526e59667ce9c4e9dcebcabb"
#inspk = "76a91446af3fb481837fadbb421727f9959c2d32a3682988ac"
#inaddr = "17SkEw2md5avVNyYgj6RiXuQKNwkXaxFyQ"
#tx = "01000000018dd4f5fbd5e980fc02f35c6ce145935b11e284605bf599a13c6d415db55d07a1000000001976a91446af3fb481837fadbb421727f9959c2d32a3682988acffffffff0200719a81860000001976a914df1bd49a6c9e34dfa8631f2c54cf39986027501b88ac009f0a5362000000434104cd5e9726e6afeae357b1806be25a4c3d3811775835d235417ea746b7db9eeab33cf01674b944c64561ce3388fa1abd0fa88b06c44ce81e2234aa70fe578d455dac00000000"
#txh = "01000000018dd4f5fbd5e980fc02f35c6ce145935b11e284605bf599a13c6d415db55d07a1000000008b4830450221009908144ca6539e09512b9295c8a27050d478fbb96f8addbc3d075544dc41328702201aa528be2b907d316d2da068dd9eb1e23243d97e444d59290d2fddf25269ee0e0141042e930f39ba62c6534ee98ed20ca98959d34aa9e057cda01cfd422c6bab3667b76426529382c23f42b9b08d7832d4fee1d6b437a8526e59667ce9c4e9dcebcabbffffffff0200719a81860000001976a914df1bd49a6c9e34dfa8631f2c54cf39986027501b88ac009f0a5362000000434104cd5e9726e6afeae357b1806be25a4c3d3811775835d235417ea746b7db9eeab33cf01674b944c64561ce3388fa1abd0fa88b06c44ce81e2234aa70fe578d455dac00000000"