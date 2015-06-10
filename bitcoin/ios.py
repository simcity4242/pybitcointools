import ecdsa
import binascii
import hashlib
import struct
from bitcoin.main import *
from bitcoin.pyspecials import safe_hexlify, safe_unhexlify, by, st

# https://gist.github.com/b22e178cff75c4b432a8

# Returns byte string value, not hex string
def varint(n):
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n < 0xffff:
        return struct.pack('<cH', '\xfd', n)
    elif n < 0xffffffff:
        return struct.pack('<cI', '\xfe', n)
    else:
        return struct.pack('<cQ', '\xff', n)

# Takes and returns byte string value, not hex string
def varstr(s):
    return num_to_var_int(len(s)) + s

def privtopubkey(s, compressed=False):
    # accepts hex encoded (sec) key, returns hex pubkey
    sk = ecdsa.SigningKey.from_string(safe_unhexlify(s), curve=ecdsa.SECP256k1)
    if compressed:
        return '%02x'% (2+(int(safe_hexlify(sk.verifying_key.to_string()),16) & 1)) \
               + safe_hexlify(sk.verifying_key.to_string())
    return "04" + safe_hexlify(sk.verifying_key.to_string())		


# Input is a hex-encoded, DER-encoded signature
# Output is a 64-byte hex-encoded signature
def derSigToHexSig(s):
    s, junk = ecdsa.der.remove_sequence(s.decode('hex'))
    if junk != '':
        print 'JUNK', junk.encode('hex')
    assert(junk == '')
    x, s = ecdsa.der.remove_integer(s)
    y, s = ecdsa.der.remove_integer(s)
    return '%064x%064x' % (x, y)

def readyRawTx(rawtx, scriptpubkey, hashcode=1):
	# takes rawtx and inserts scriptpubkey into scriptsig and appends '01000000'
	seqidx = rawtx.find('00ffffffff', 81)
	rawtx.replace('00fffffffff', scriptpubkey+'ffffffff', 1)
	return rawtx + binascii.hexlify(struct.pack('<L',1))

def signTx(rawtx, privkey, scriptpubkey, hashcode=1):
    # rawtx = unsigned Tx w/ scriptPubKey in ScriptSig and '01000000' appended
    rawtx = readyRawTx(rawtx, scriptpubkey, hashcode=hashcode)
    s256 = hashlib.sha256(hashlib.sha256(rawtx.decode('hex')).digest()).digest()
    sk = ecdsa.SigningKey.from_string(privkey.decode('hex'), curve=ecdsa.SECP256k1)
    sig = sk.sign_digest(s256, sigencode=ecdsa.util.sigencode_der) + '\01' # 01 is hashtype
    pubKey = privtopubkey(privkey)
    scriptSig = safe_hexlify(varstr(sig)) + safe_hexlify(varstr(safe_unhexlify(pubKey)))
    return scriptSig

def privkey_to_pubkey(privkey):
    f = get_privkey_format(privkey)
    privkey = decode_privkey(privkey, f)
    if privkey >= N:
        raise Exception("Invalid privkey")
    if f in ['bin', 'bin_compressed', 'hex', 'hex_compressed', 'decimal']:
        try:
            return encode_pubkey(fast_multiply(G, privkey), f)
        except RuntimeError:
            assert f is 'hex'
            import bitcoin.ios as ios
            return ios.privtopub(privkey)		
    else:
        try: return encode_pubkey(fast_multiply(G, privkey), f.replace('wif', 'hex'))
        except RuntimeError:
            assert f in ('hex', 'wif')
            import bitcoin.ios as ios
            return ios.privtopub(privkey)

# SIG = '47304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac014104392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55'

#47 30 44 0220 2c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f8 0220 # 797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac 01 41 
#04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55'

#if __name__ == '__main__':
#	unittest.main()
