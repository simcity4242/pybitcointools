from bitcoin.pyspecials import *
from bitcoin.main import *
from bitcoin.deterministic import *

import re, hmac, hashlib

# Alice's wallet:
# Mnemonic (BIP39): [response seminar brave tip suit recall often sound stick owner lottery motion]
# Hex seed (BIP39): b7b8706d714d9166e66e7ed5b3c61048

RE_BIP47_HEXCODE = re.compile(ur'^0100(02|03)[0-9a-fA-F]{128}0{26}$')
RE_BIP47_PAYCODE = re.compile(ur"^P[1-9a-km-zA-HJ-NP-Z]{0,115}$")


def bip47_is_paycode(pcode):
    if not bool(RE_BIP47_PAYCODE.match(pcode)):
        return False
    try:
        b58check_to_hex(pcode)
        return True
    except AssertionError:
        return False
    raise Exception("{0} can't be IDd. Verify payment code is correct").format(pcode)   # should never reach this
        

def bip47_is_hexcode(hexstr):
    return bool(RE_BIP47_HEXCODE.match(hexstr))
    

def bip47_derive_xpub(seed):
    """Derive derived xpub from entropy or mnemonic"""
    master_key = bip32_master_key(seed)
    xpub = bip32_ckd(master_key, """M/47'/0'/0'""")
    return xpub
    

def bip47_paycode_to_hex(pcode):
    hex = b58check_to_hex(pcode)
    assert bip47_is_hexcode(hex)
    return hex
    

def bip47_hex_to_paycode(hex):
    pcode = hex_to_b58check(hex, 0x47)
    assert bip47_is_paycode(pcode)
    return pcode


def bip47_deserialize_paycode(pcode):
    """Deserialize payment code to (pubkey, chaincode) """
    assert isinstance(pcode, basestring) and pcode[0] == "P"
    hex = bip47_paycode_to_hex(pcode)
    pubkey = hex[4:70]
    chaincode = hex[70:134]
    return pubkey, chaincode
    

def bip47_serialize(*args):
    """Takes xpub, (pubkey, chaincode) or (chaincode, pubkey) & serializes into bip47 hex code"""
    if len(args) == 1 and args[0][:4] == 'xpub':
        xpub = args[0]
        assert bip32_deserialize(xpub)[1] == 3, "xpub is not M/47'/0'/0'"
        chaincode = bip32_extract_chaincode(xpub)
        pubkey = bip32_extract_key(xpub)
    elif len(args) == 2:
        chaincode = args[0] if len(args[0]) == 64 else args[1]
        pubkey = args[1] if len(args[1]) == 66 else args[0]
    return '0100{0}{1}00000000000000000000000000'.format(pubkey, chaincode)


def bip47_derive_paycode(xkey):
    if xkey.startswith("xprv") or xkey.count(" ") in (11, 23) or (re.match("^[0-9a-fA-F]$", xkey) and len(xkey) % 32 == 0):
        pcode = bip47_serialize(bip47_derive_pubkey(xkey))
    elif xkey[:4] == "xpub":
        pcode = bip47_serialize(xkey)
    return pcode


def bip47_find_S(a, B):
    """Find secret point, S, from notification Tx's 1st privkey (a) and receiver's pubkey (B)"""
    assert is_privkey(a) and is_pubkey(B)
    a, B = decode_privkey(a), decode_pubkey(B)
    S = encode_pubkey(fast_multiply(B, a), 'hex_compressed')
    return S[2:]
    

def bip47_find_blinding_factor(a, B, outpoint):
    """Outpoint is in "TXID:VOUT", a is Alice's privkey, B is Bob's pubkey"""
    txid, vout = outpoint.split(":")
    x = changebase(bip47_find_S(a, B), 16, 256, 32)
    o = changebase(txid, 16, 256, 32)[::-1] + changebase(vout, 16, 256,  4)[::-1]
    s = hmac.new(x, o, hashlib.sha512).hexdigest()
    return s
    



Amn = "response seminar brave tip suit recall often sound stick owner lottery motion"
Apc = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA"
Bmn = "reward upper indicate eight swift arch injury crystal super wrestle already dentist"
Bpc = "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97"

a0 = "8d6a8ecd8ee5e0042ad0cb56e3a971c760b5145c3917a8e7beaf0ed92d7a520c"
A0 = "0353883a146a23f988e0f381a9507cbdb3e3130cd81b3ce26daf2af088724ce683"
b0 = "04448fd1be0c9c13a5ca0b530e464b619dc091b299b98c5cab9978b32b4a1b8b"
B0 = "024ce8e3b04ea205ff49f529950616c3db615b1e37753858cc60c1ce64d17e2ad8"

S0 = multiply(B0, a0)    # "03f5bb84706ee366052471e6139e6a9a969d586e5fe6471a9b96c3d8caefe86fef"

addrs = ['141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK', '12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6', '1FsBVhT5dQutGwaPePTYMe5qvYqqjxyftc', '1CZAmrbKL6fJ7wUxb99aETwXhcGeG3CpeA', '1KQvRShk6NqPfpr4Ehd53XUhpemBXtJPTL', '1KsLV2F47JAe6f8RtwzfqhjVa8mZEnTM7t', '1DdK9TknVwvBrJe7urqFmaxEtGF2TMWxzD', '16DpovNuhQJH7JUSZQFLBQgQYS4QB9Wy8e', '17qK2RPGZMDcci2BLQ6Ry2PDGJErrNojT5', '1GxfdfP286uE24qLZ9YRP3EWk2urqXgC4s']

Ss = ['f5bb84706ee366052471e6139e6a9a969d586e5fe6471a9b96c3d8caefe86fef', 'adfb9b18ee1c4460852806a8780802096d67a8c1766222598dc801076beb0b4d', '79e860c3eb885723bb5a1d54e5cecb7df5dc33b1d56802906762622fa3c18ee5', 'd8339a01189872988ed4bd5954518485edebf52762bf698b75800ac38e32816d', '14c687bc1a01eb31e867e529fee73dd7540c51b9ff98f763adf1fc2f43f98e83', '725a8e3e4f74a50ee901af6444fb035cb8841e0f022da2201b65bc138c6066a2', '521bf140ed6fb5f1493a5164aafbd36d8a9e67696e7feb306611634f53aa9d1f', '5f5ecc738095a6fb1ea47acda4996f1206d3b30448f233ef6ed27baf77e81e46', '1e794128ac4c9837d7c3696bbc169a8ace40567dc262974206fcf581d56defb4', 'fe36c27c62c99605d6cd7b63bf8d9fe85d753592b14744efca8be20a4d767c37']

bs = ['04448fd1be0c9c13a5ca0b530e464b619dc091b299b98c5cab9978b32b4a1b8b', '6bfa917e4c44349bfdf46346d389bf73a18cec6bc544ce9f337e14721f06107b', '46d32fbee043d8ee176fe85a18da92557ee00b189b533fce2340e4745c4b7b8c', '4d3037cfd9479a082d3d56605c71cbf8f38dc088ba9f7a353951317c35e6c343', '97b94a9d173044b23b32f5ab64d905264622ecd3eafbe74ef986b45ff273bbba', 'ce67e97abf4772d88385e66d9bf530ee66e07172d40219c62ee721ff1a0dca01', 'ef049794ed2eef833d5466b3be6fe7676512aa302afcde0f88d6fcfe8c32cc09', 'd3ea8f780bed7ef2cd0e38c5d943639663236247c0a77c2c16d374e5a202455b', 'efb86ca2a3bad69558c2f7c2a1e2d7008bf7511acad5c2cbf909b851eb77e8f3', '18bcf19b0b4148e59e2bba63414d7a8ead135a7c2f500ae7811125fb6f7ce941']

Bs = ['024ce8e3b04ea205ff49f529950616c3db615b1e37753858cc60c1ce64d17e2ad8', '03e092e58581cf950ff9c8fc64395471733e13f97dedac0044ebd7d60ccc1eea4d', '029b5f290ef2f98a0462ec691f5cc3ae939325f7577fcaf06cfc3b8fc249402156', '02094be7e0eef614056dd7c8958ffa7c6628c1dab6706f2f9f45b5cbd14811de44', '031054b95b9bc5d2a62a79a58ecfe3af000595963ddc419c26dab75ee62e613842', '03dac6d8f74cacc7630106a1cfd68026c095d3d572f3ea088d9a078958f8593572', '02396351f38e5e46d9a270ad8ee221f250eb35a575e98805e94d11f45d763c4651', '039d46e873827767565141574aecde8fb3b0b4250db9668c73ac742f8b72bca0d0', '038921acc0665fd4717eb87f81404b96f8cba66761c847ebea086703a6ae7b05bd', '03d51a06c6b48f067ff144d5acdfbe046efa2e83515012cf4990a89341c1440289']

bip47_txid = "bad5802e2183be44007b6b94395113d7cb513dbeb68d40245a83f5fadfcc76f3"
