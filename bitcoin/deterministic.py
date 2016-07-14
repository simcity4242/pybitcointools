from bitcoin.main import *
import hmac
import hashlib
import re
from binascii import hexlify
from bitcoin.mnemonic import elec2_prepare_seed, is_elec1_seed, is_elec2_seed, bip39_check, bip39_to_seed
from bitcoin.pyspecials import *

# Electrum wallets
def bin_electrum_extract_seed(mn_seed, password=b''):
    if isinstance(mn_seed, string_types):
        mn_seed = elec2_prepare_seed(mn_seed)
    else: 
        raise Exception("mnemonic string req")
    rootseed = safe_unhexlify(pbkdf2_hmac_sha512( \
        from_str_to_bytes(mn_seed), from_str_to_bytes("electrum"+password)))
    assert len(rootseed) == 64
    return rootseed

def electrum_extract_seed(mn_seed, password=''):
    if isinstance(mn_seed, list):
        mn_seed = ' '.join(mn_seed)
    return safe_hexlify(bin_electrum_extract_seed(elec2_prepare_seed(mn_seed), password))


def electrum_masterprivkey(mnemonic, password=''):
    return bip32_master_key(bin_electrum_extract_seed(mnemonic, password))


def electrum_keystretch(seed, password=None):
    if isinstance(seed, string_types) and re.match('^[0-9a-fA-F]*$', seed):
        seed = from_str_to_bytes(seed)
    if is_elec1_seed(seed):
        return slowsha(seed)
    elif is_elec2_seed(seed):
        password = from_str_to_bytes(password) if password else None
        return electrum_extract_seed(seed, password)
    else:
        return seed

# Accepts seed or stretched seed, returns master public key
def electrum_mpubk(seed):
    # TODO: add electrum_seed function to return mpk for both Elec1/2
    if len(seed) == 32 and not is_elec2_seed(seed):
        seed = electrum_keystretch(seed)
    return privkey_to_pubkey(seed)[2:]

# Accepts (seed or stretched seed), index and secondary index
# (conventionally 0 for ordinary addresses, 1 for change) , returns privkey
def electrum_privkey(seed, n, for_change=0):
    if len(seed) == 32:
        seed = electrum_keystretch(seed)
    mpk = electrum_mpubk(seed)
    offset = bin_dbl_sha256(from_str_to_bytes("{0}:{1}:{2}".format(n, for_change, safe_unhexlify(mpk))))
    return add_privkeys(seed, offset)


# Accepts (seed or stretched seed or master pubkey), index and secondary index
# (conventionally 0 for ordinary addresses, 1 for change) , returns pubkey
def electrum_pubkey(masterkey, n, for_change=0):
    if len(masterkey) == 32:
        mpk = electrum_mpubk(electrum_keystretch(masterkey))
    elif len(masterkey) == 64:
        mpk = electrum_mpubk(masterkey)
    else:
        mpk = masterkey
    bin_mpk = encode_pubkey(mpk, 'bin_electrum')
    offset = bin_dbl_sha256(from_str_to_bytes("{0}:{1}:{2}".format(n, for_change, bin_mpk)))
    return add_pubkeys('04'+mpk, privtopub(offset))

# seed/stretched seed/pubkey -> address (convenience method)
def electrum_address(masterkey, n, for_change=0, version=0):
    return pubkey_to_address(electrum_pubkey(masterkey, n, for_change), version)

# Given a master public key, a private key from that wallet and its index,
# cracks the secret exponent which can be used to generate all other private
# keys in the wallet
def crack_electrum_wallet(mpk, pk, n, for_change=0):
    bin_mpk = encode_pubkey(mpk, 'bin_electrum')
    offset = dbl_sha256(str(n)+':'+str(for_change)+':'+bin_mpk)
    return subtract_privkeys(pk, offset)

# Below code ASSUMES binary inputs and compressed pubkeys
MAINNET_PRIVATE, MAINNET_PUBLIC = b'\x04\x88\xAD\xE4', b'\x04\x88\xB2\x1E'
TESTNET_PRIVATE, TESTNET_PUBLIC = b'\x04\x35\x83\x94', b'\x04\x35\x87\xCF'
PRIVATE, PUBLIC = [MAINNET_PRIVATE, TESTNET_PRIVATE], [MAINNET_PUBLIC, TESTNET_PUBLIC]

# BIP32 child key derivation
def raw_bip32_ckd(rawtuple, i):
    vbytes, depth, fingerprint, oldi, chaincode, key = rawtuple
    i = int(i)

    if vbytes in PRIVATE:
        priv = key
        pub = privtopub(key)
    else:
        pub = key

    if i >= 2**31:
        if vbytes in PUBLIC:
            raise Exception("Can't do private derivation on public key!")
        I = hmac_sha512(chaincode, b'\x00'+priv[:32]+encode(i, 256, 4)).digest()
    else:
        I = hmac_sha512(chaincode, pub+encode(i, 256, 4)).digest()

    if vbytes in PRIVATE:
        newkey = add_privkeys(I[:32] + b'\x01', priv)
        fingerprint = bin_hash160(privtopub(key))[:4]
    if vbytes in PUBLIC:
        newkey = add_pubkeys(compress(privtopub(I[:32])), key)
        fingerprint = bin_hash160(key)[:4]

    return (vbytes, depth + 1, fingerprint, i, I[32:], newkey)


def bip32_serialize(rawtuple):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    i = encode(i, 256, 4)
    chaincode = encode(hash_to_int(chaincode), 256, 32)
    keydata = b'\x00'+key[:-1] if vbytes in PRIVATE else key
    bindata = vbytes + from_int_to_byte(depth % 256) + fingerprint + i + chaincode + keydata
    return changebase(bindata+bin_dbl_sha256(bindata)[:4], 256, 58)


def bip32_deserialize(data):
    dbin = changebase(data, 58, 256)
    checksum = dbin[-4:]
    if bin_dbl_sha256(dbin[:-4])[:4] != checksum:
        raise Exception("Invalid checksum")
    vbytes = dbin[0:4]
    depth = from_byte_to_int(dbin[4])
    fingerprint = dbin[5:9]
    i = decode(dbin[9:13], 256)
    chaincode = dbin[13:45]
    key = dbin[46:78]+b'\x01' if vbytes in PRIVATE else dbin[45:78]
    return (vbytes, depth, fingerprint, i, chaincode, key)


def raw_bip32_privtopub(rawtuple):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    newvbytes = MAINNET_PUBLIC if vbytes == MAINNET_PRIVATE else TESTNET_PUBLIC
    pubkey = privtopub(key)
    return (newvbytes, depth, fingerprint, i, chaincode, pubkey)


def bip32_privtopub(data):
    return bip32_serialize(raw_bip32_privtopub(bip32_deserialize(data)))


def bip32_master_key(seed, vbytes=MAINNET_PRIVATE):
    """Takes entropy hex or bip39 mnemonic and returns master xprv key"""
    if RE_MNEMONIC.match(seed):
        seed = unhexlify(bip39_to_seed(seed))
    elif re.match("^[0-9a-fA-F]$", seed):
        seed = unhexlify(seed)
    I = hmac_sha512(from_str_to_bytes("Bitcoin seed"), seed).digest()
    return bip32_serialize((vbytes, 0, b'\x00'*4, 0, I[32:], I[:32]+b'\x01'))


def bip32_bin_extract_key(data):
    return bip32_deserialize(data)[-1]


def bip32_extract_key(data):
    return safe_hexlify(bip32_deserialize(data)[-1])
    

def bip32_bin_extract_chaincode(data):
    return bip32_deserialize(data)[-2]


def bip32_extract_chaincode(data):
   return safe_hexlify(bip32_bin_extract_chaincode(data))


# Exploits the same vulnerability as above in Electrum wallets
# Takes a BIP32 pubkey and one of the child privkeys of its corresponding
# privkey and returns the BIP32 privkey associated with that pubkey
def raw_crack_bip32_privkey(parent_pub, priv):
    vbytes, depth, fingerprint, i, chaincode, key = priv
    pvbytes, pdepth, pfingerprint, pi, pchaincode, pkey = parent_pub
    i = int(i)

    if i >= 2**31: 
        raise Exception("Can't crack private derivation!")

    I = hmac_sha512(pchaincode, pkey+encode(i, 256, 4)).digest()

    pprivkey = subtract_privkeys(key, I[:32]+b'\x01')

    newvbytes = MAINNET_PRIVATE if vbytes == MAINNET_PUBLIC else TESTNET_PRIVATE
    return (newvbytes, pdepth, pfingerprint, pi, pchaincode, pprivkey)


def crack_bip32_privkey(parent_pub, priv):
    dsppub = bip32_deserialize(parent_pub)
    dspriv = bip32_deserialize(priv)
    return bip32_serialize(raw_crack_bip32_privkey(dsppub, dspriv))


def coinvault_pub_to_bip32(*args):
    if len(args) == 1:
        args = args[0].split(' ')
    vals = map(int, args[34:])
    I1 = ''.join(map(chr, vals[:33]))
    I2 = ''.join(map(chr, vals[35:67]))
    return bip32_serialize((MAINNET_PUBLIC, 0, b'\x00'*4, 0, I2, I1))


def coinvault_priv_to_bip32(*args):
    if len(args) == 1:
        args = args[0].split(' ')
    vals = map(int, args[34:])
    I2 = ''.join(map(chr, vals[35:67]))
    I3 = ''.join(map(chr, vals[72:104]))
    return bip32_serialize((MAINNET_PRIVATE, 0, b'\x00'*4, 0, I2, I3+b'\x01'))

#def bip32_descend(*args):
#    """Descend masterkey and return privkey"""
#    if len(args) == 2 and isinstance(args[1], list):
#        key, path = args
#    elif len(args) == 2 and isinstance(args[1], string_types):
#        key = args[0]
#        path = map(int, str(args[1]).lstrip("mM/").split('/'))
#    else:
#        key, path = args[0], map(int, args[1:])
#    for p in path:
#        key = bip32_ckd(key, p)
#    return bip32_extract_key(key)
	
#def bip32_ckd(key, *args, **kwargs):
#    """Same as bip32_ckd but takes bip32_path or ints"""
#    # use keyword public=True or end path in .pub for public child derivation
#    argz = map(str, args)
#    path = "/".join(argz)    # no effect if "m/path/0"
#    if not path.startswith(("m/", "M/")):
#        path = "m/{0}".format(path)
#    is_public = path.startswith("M/") or path.endswith(".pub") or kwargs.get("public", False)
#    pathlist = parse_bip32_path(path)
#    for p in pathlist:
#        key = bip32_serialize(raw_bip32_ckd(bip32_deserialize(key), p))
#    return key if not is_public else bip32_privtopub(key)

def bip32_harden(x):
    return int(x) | 0x80000000

def bip32_descend(*args):
    return bip32_extract_key(bip32_path(*args))

def bip32_ckd(data, i):
    return bip32_serialize(raw_bip32_ckd(bip32_deserialize(data), i))


def bip32_path(*args, **kwargs):
    if len(args) == 2 and isinstance(args[1], list):
        key, path = args
    elif len(args) == 2 and RE_BIP32_PATH.match(args[1]):
        key = args[0]
        path = parse_bip32_path(args[1])		
    else:
        key, path = args[0], map(int, args[1:])
    is_public = str(args[1]).startswith("M/") or str(args[1]).endswith(".pub") or kwargs.get("public", False)
    ret = reduce(bip32_ckd, path, key)
    return bip32_privtopub(ret) if is_public else ret


def parse_bip32_path(path):
    """Takes bip32 path, "m/0'/2H" or "m/0H/1/2H/2/1000000000.pub", returns list of ints """
    path = path.lstrip("mM/").rstrip(".pub")
    if not path:
        return []
    if path.endswith("/"):
        path += "0"
    patharr = []
    for v in path.split('/'):
        if v is None: 
            continue
        elif v[-1] in ("'H"):  # hardened path
            v = bip32_harden(v[:-1])
        patharr.append(int(v))
    return patharr


def bip44_ckd(masterkey, account=0, change=0, **kwargs):
    # m / purpose' / coin_type' / account' / change / address_index
    assert masterkey[0] in "xt", "Master key {0} must be xprv/xpub or tprv/tpub".format(masterkey)
    is_public = masterkey[:4] in ('xpub', 'tpub') or kwargs.get('public', False)
    path = "{keytype}/44H/{network}/{account}/{change}".format( \
                keytype = "M" if is_public else "m",
                network = "{0}H".format(1 if masterkey.startswith("t") else 0), 
                account = "{0}H".format(account),
                change = change
           )
    return bip32_ckd(masterkey, path)
    
    
def bip44_ckd_privpub(masterkey, account=0, change=0, **kwargs):
    keyprv = bip44_ckd(masterkey, account, change, **kwargs)
    keypub = bip32_privtopub(keyprv)
    return keyprv, keypub


def bip44_descend(masterkey, network="btc", account=0, change=0, addr_index=0):
    # m / purpose' / coin_type' / account' / change / address_index
    assert bip32_deserialize(masterkey)[1] == 0, "Masterkey depth != 0 (not a masterkey)"
    xprv = bip44_ckd(masterkey, account, change)
    return bip32_descend(xprv, int(addr_index))


def bip44_address(masterkey, network='btc', account=0, for_change=0, index=0):
    assert 0 <= (int(index) or int(account)) <= 0x7fffffff
    return privtoaddr(bip44_descend(masterkey, network, account, for_change, index), 0 if network=='btc' else 111)


def bip44_address_info(masterkey, network='btc', account=0, for_change=0, index=0):
    # m / purpose' / coin_type' / account' / change / address_index
    index = int(index)
    paths, addrs, wifs = [], [], []
    for i in range(index, index+20):
        paths.append(str("m/44'/0'/0'/0/{0}".format(i)).ljust(20))
        addrs.append(str(bip44_descend(masterkey, network, account, for_change, i)).ljust(42))
        wifs.append(str(bip44_address(masterkey, network, account, for_change, i)).ljust(66))
    lines = zip(paths, addrs, wifs, ["\n"]*20)
    res = "".join(map(lambda o: "".join(list(o)), lines))
    print res
        


def bip32_info(xkey):
    #deser = [x.encode('hex') if isinstance(x, str) else x for x in bip32_deserialize(xkey)]
    deser = [safe_hexlify(x) for x in bip32_deserialize(xkey) if isinstance(x, string_types)]
    deser[0] = "tPRV" if changebase(deser[0], 16, 256, 4) == TESTNET_PRIVATE else "xPRV"
    return deser
   
