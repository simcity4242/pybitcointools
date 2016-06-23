#! python2
#designed with Pythonista 3 for iOS 

from bitcoin.main import *
from bitcoin.pyspecials import *

import pyscrypt
import unicodedata, binascii, base64, sys, os, math, re

try:
    from Crypto.Cipher import AES
except ImportError:
    import aes

try:
    from strxor import strxor
except ImportError:
    def strxor(x, y):
        assert len(x)==len(y)
        return "".join([chr(ord(a) ^ ord(b)) for (a,b) in zip(x, y)])


COMPRESSION_FLAGBYTES = [u'20', u'24', u'28', u'2c', u'30', u'34', u'38', u'3c', u'e0', u'e8', u'f0', u'f8']
LOTSEQUENCE_FLAGBYTES = [u'04', u'0c', u'14', u'1c', u'24', u'2c', u'34', u'3c']


def aes_encrypt_bip38(msg, key, pad="{", blocksize=16):
    if len(key) != 32:
        raise Exception("aes_encrypt_bip38() key size must be 32 bytes")
    pad = "{:02x}".format(ord(pad.encode("utf-8")))
    msg = hexlify(msg)
    padlen = blocksize - (len(msg) % blocksize)
    for i in range(padlen):
        msg = msg + pad
    cipher = AES.new(key)
    ret = cipher.encrypt(unhexlify(msg))[:-16]
    return ret
    

def aes_decrypt_bip38(encmsg, key, pad="{"):
    pad = pad.encode('utf-8')
    if len(key) != 32:
        raise Exception("aes_decrypt_bip38() key size must be 32 bytes")
    cipher = AES.new(key)
    msg = cipher.decrypt(encmsg)
    msg = msg.rstrip(pad)
    if len(msg) != 16:
        if len(msg) > 16:
            raise Exception('aes_decrypt_bip38() decrypted msg larger than 16 bytes after pad strip')
        else:
            msg = msg + pad * int(16 - len(msg))
    return msg
    

def bip38_encrypt_privkey(password, privkey, compressFlag=False, **kwargs):
    network = kwargs.get("network", "btc")
    if re.match("^[5KL9c][1-9a-km-zA-LMNP-Z]{50,51}$", privkey):
        compressFlag = "compressed" in get_privkey_format(privkey)
        network = "testnet" if privkey[0] in "9c" else "btc"
        privkey = encode_privkey(decode_privkey(privkey), "hex_compressed" if compressFlag else "hex")
    elif re.match("^[0-9a-f]{64}(01)?$", privkey):
        compressFlag = (len(privkey) == 66 and privkey[-2:] == "01")
    elif len(privkey) in (32, 33):
        privkey = binascii.hexlify(privkey)
    btcprivkey = binascii.unhexlify(privkey)            # 32 byte hex string (no trailing "01")
    
    pubkey = privtopub(privkey)
    addr = privtoaddr(privkey, 111 if network == "testnet" else 0)
    
    pwd = str(unicodedata.normalize("NFC", unicode(password)))
    addrhash = bin_dbl_sha256(addr)[:4]
    scrypthash = pyscrypt.hash(password=pwd, salt=addrhash, N=16384, r=8, p=8, dkLen=64)
    derivedhalf1, derivedhalf2 = scrypthash[:32], scrypthash[32:]
    block1 = strxor(btcprivkey[:16], derivedhalf1[:16])
    block2 = strxor(btcprivkey[16:], derivedhalf1[16:])
    key = derivedhalf2
    encryptedhalf1 = aes_encrypt_bip38(block1, key)
    encryptedhalf2 = aes_encrypt_bip38(block2, key)
    
    prefix = '\x01\x42'             # Do not use EC multiplication
    flagbyte = 0b11000000           # 192
    if compressFlag:
        flagbyte = flagbyte + 0x20  # 224
    flagbyte = encode(flagbyte, 256, 1)
    
    res = prefix + flagbyte + addrhash + encryptedhalf1 + encryptedhalf2
    b58 = bin_to_b58check(res)    # 16PRN7XmtPiu8pHRQGW2DSGrHYLKhb1ny144SnAomjZ9ySY4QcfKenoqXYB
    return b58[1:]                #. 6PRN7XmtPiu8pHRQGW2DSGrHYLKhb1ny144SnAomjZ9ySY4QcfKenoqXYB

    

def intermediate_code(password, useLotAndSequence=False, lot=100000, sequence=0):
    if str == bytes:    password = unicode(password)    # Python 2
    password = str(unicodedata.normalize('NFC', password))
    if useLotAndSequence:
        if not (isinstance(lot, int) and isinstance(sequence, int)):
            raise TypeError("lot and sequence must be INTs")
        if not ((100000 < lot < 999999) and (0 < sequence < 4096)):
            raise ValueError("100000 < lot < 999999 and 0 < sequence < 4099")
            
            
def bip38_decrypt_privkey(password, enckey, returnLot=False):
    if str==bytes:
        password = unicode(password)
        enckey = unicode(enckey)
    password, enckey = map(lambda x: str(unicodedata.normalize("NFC", x)), [password, enckey])
    if enckey[:2] != "6P":
        raise Exception("decrypt_priv_key() private key input must begin with 6P")
    
    enckeyhex = "01" + b58check_to_hex(enckey)
    if len(enckeyhex) != 78 or enckeyhex[:3] != '014':    
        #014304e07669c7367f7c8252c94000786683ed440ac68a6cf1025de52dba301ac1e33dbd682ba0
        raise Exception('decrypt_priv_key() private key input error')
    
    prefix = enckeyhex[:-74]    #enckeyhex[:4]
    flagbyte = enckeyhex[4:-72]
    
    if prefix == '0142':
        salt = unhexlify(enckeyhex[6:-64])
        encryptedhalf1, encryptedhalf2 = unhexlify(enckeyhex[14:-32]), unhexlify(enckeyhex[46:])
    elif prefix == '0143':
        addrhash = enckeyhex[6:-64]
        ownerentropy = enckeyhex[14:-48]
        encryptedhalf1firsthalf, encryptedhalf2 = unhexlify(enckeyhex[30:-32]), unhexlify(enckeyhex[46:])
    else:
        raise Exception('decrypt_priv_key() unknown private key input error 1')
    
    if prefix == '0142':
        scrypthash = scrypt.hash(password, salt, 16384, 8, 8, 64)
        decryption1 = aes_decrypt_bip38(encryptedhalf1, scrypthash[32:])
        decryption2 = aes_decrypt_bip38(encryptedhalf2, scrypthash[32:])
        privkeyhalf1 = encode(decode(decryption1, 16) ^ decode(scrypthash[:16], 16), 16, 32)
        privkeyhalf2 = encode(decode(decryption2, 16) ^ decode(scrypthash[16:32], 16), 16, 32)
        privkeyhex = privkeyhalf1 + privkeyhalf2
        
        if flagbyte.lower() in COMPRESSION_FLAGBYTES:
            pubkey = privtopub(privkeyhex+"01")
        else:
            pubkey = privtopub(privkeyhex)
        addr = pubtoaddr(pubkey)
        addrhash = bin_dbl_sha256(addr)[:4]
        
        if addrhash == salt:
            if flagbyte.lower() in COMPRESSION_FLAGBYTES:
                privkeyhex += "01"
            if returnLot:
                return base58_check_and_encode(rehexlify(privKeyHex)), False, False
            else:
                return base58_check_and_encode(rehexlify(privKeyHex))
    elif prefix == "0143":
        if flagbyte.lower() in LOTSEQUENCE_FLAGBYTES:
            lotsequence = ownerentropy[8:]
            ownersalt = ownerentropy[:-8]
            returnlot2 = True
        else:
            ownersalt = ownerentropy
            returnlot2 = False
        scryptsalt = unhexlify(ownersalt)
        prefactor = hexlify(scrypt.hash(password, scryptsalt, 16384, 8, 8, 32))
        if flagbyte.lower() in LOTSEQUENCE_FLAGBYTES: 
            passfactor = dbl_sha256(prefactor + ownerentropy)
        else:
            passfactor = prefactor
        
        passpoint = compress(privtopub(passfactor))
        password2 = unhexlify(passpoint)
        scryptsalt2 = unhexlify(addrhash + ownerentropy)
        secondseedbkey = scrypt.hash(password2, scryptSalt2, 1024, 1, 1, 64)
        decryption2 = aes_decrypt_bip38(encryptedhalf2, secondseedbkey[32:])
        encryptedHalf1SecondHalfCATseedblastthird = encode(
                                decode(decryption2, 256) ^ decode(secondseedbkey, 256), 
                                                            256, 16)
        encryptedhalf1 = encryptedhalf1firsthalf + encryptedHalf1SecondHalfCATseedblastthird[:-8]
        decryption1 = aes_decrypt_bip38(encryptedhalf1, secondseedbkey[32:])
        seedbfirstpart = encode(decode(decryption1, 256) ^ decode(secondseedbkey[:-48], 256), 256, 8)
        seedb = seedbfirstpart + encryptedHalf1SecondHalfCATseedblastthird[8:]
        factorb = bin_dbl_sha256(seedb)
        
        newprivkey = encode(int(decode(factorb, 256) * decode(passfactor, 256)) % N, 16, 64)
        newpubkey = compress(privtopub(newprivkey)) if flagbyte.lower() in \
                    COMPRESSION_FLAGBYTES else decompress(rivtopub(newprivkey))
        btcaddr = pubtoaddr(newpubkey)
        checksum = bin_dbl_sha256(btcaddr)[:4]
        
        if addrhash == checksum:
            newprivkey = newprivkey + "01" if flagbyte.lower() in COMPRESSION_FLAGBYTES else newprivkey
            if returnLot:
                if returnlot2:
                    lotsequence = decode(lotsequence, 16)
                    sequencenum = int(lotsequence % 4096)
                    lotnum = (lotsequence - sequencenum) // 4096
                    return hex_to_b58check(newprivkey), lotnum, sequencenum
                else:
                    return hex_to_b58check(newprivkey), False, False
            else:
                return hex_to_b58check(newprivkey)
