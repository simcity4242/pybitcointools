from bitcoin.pyspecials import *
from bitcoin.main import *
from bitcoin.deterministic import *
from bitcoin.bci import *
from bitcoin.transaction import *
from bitcoin.composite import *

import re, hmac, hashlib
try:
    from strxor import strxor as sxor
except ImportError:
    sxor = lambda a,b: ''.join([chr(ord(a) ^ ord(b)) for a,b in zip(s1, s2)])


RE_HEXCODE = re.compile(r'^0100(02|03)[0-9a-fA-F]{128}0{26}$') 
RE_PAYCODE = re.compile(r"^P[1-9a-km-zA-HJ-NP-Z]{0,115}$")


def is_bip47_code(s):
    assert isinstance(s, string_types)
    if not RE_HEX_CHARS.match(s) and len(s)==80:
        return is_bip47_code(safe_hexlify(s))
    elif RE_HEX_CHARS.match(s) and len(s)==160: 
        return bool(RE_HEXCODE.match(s))
    elif s[0] == 'P':
        return bool(RE_PAYCODE.match(s))
    return False


def bip47_ckd(seed):
    """Derive derived xpub from entropy or mnemonic"""
    assert isinstance(seed, string_types) and \
           (RE_MNEMONIC.match(seed) or RE_BIP32_PRIV.match(seed)), \
        ""
    return bip32_ckd(bip32_master_key(seed), "M/47'/0'/0'")
    

def mk_paycode(xkey):
    """Derive paycode from initial entropy/mnemonic/bip32 root key """
    if xkey.startswith("xprv") or RE_MNEMONIC.match(xkey) or \
             (RE_HEX_CHARS.match(xkey) and len(xkey) % 32 == 0):
        pcode = serialize_paycode(bip47_ckd(xkey))
    elif xkey[:4] == "xpub":
        pcode = serialize_paycode(xkey)
    return pcode
    

def b58_paycode_decode(pcode):
    """Decode b58check to hex paycode"""
    assert is_bip47_code(pcode)
    return b58check_to_hex(pcode)
    

def b58_paycode_encode(hexstr):
    """Encode hex paycode to b58check hexcode"""
    assert is_bip47_code(hexstr)
    return hex_to_b58check(hexstr, 0x47)


# args = (pubkey, chaincode) or derived xpub(key)
def serialize_paycode(*args):
    """Serialize xpub or (pubkey, chaincode) into hex"""
    # Convenience function, derived xpub
    if RE_BIP32_PUB.match(str(args[0])):
        xpub = args[0]
        depth = bip32_deserialize(xpub)[1]
        assert depth == 3, "xpub depth is {0} and must be 3".format(depth)
        cc = bip32_extract_chaincode(xpub)
        pub = bip32_extract_key(xpub)
    elif isinstance(args[0], tuple):
        pub, cc = sorted(args, key=lambda x: -len(x))
    pub, cc = decode(pub, 16), decode(cc, 16)
    return '0100{0:066x}{1:064x}{2:026x}'.format(pub, cc, 0)


def deserialize_paycode(pcode):
    """Deserialize hex or b58check paycode to (pubkey, chaincode) """
    assert is_bip47_code(pcode)
    hex = b58_paycode_decode(pcode) if pcode.startswith('P') else pcode
    pubkey = hex[4:70]
    chaincode = hex[70:134]
    assert (hex[:4], hex[-26:]) == ('0100', '00'*13), \
        "Deserialize Error! Ensure hex paycode is hexlified"
    return pubkey, chaincode


def find_S(a, B):
    """Find secret point, S, from notification Tx's 1st privkey (a) and receiver's pubkey (B)"""
    assert is_privkey(a) and is_pubkey(B)
    a, B = decode_privkey(a), decode_pubkey(B)
    S = encode_pubkey(fast_multiply(B, a), 'hex_compressed')
    return S[2:]
    

def find_blinding_factor(a, B, outpoint):
    """Outpoint is in "TXID:VOUT", a is Alice's privkey, B is Bob's pubkey"""
    txid, vout = outpoint.split(":")
    x = changebase(find_S(a, B), 16, 256, 32)
    o = changebase(txid, 16, 256, 32)[::-1] + changebase(vout, 16, 256,  4)[::-1]
    s = hmac.new(x, o, hashlib.sha512).hexdigest()
    return s


# TODO: not working, matches A0
# deserialize_paycode() broken??
# def bip47_check_derivation(privkey, paycode):
#     assert RE_PRIVKEY.match(privkey), "{0} is not a privkey".format(privkey)
#     assert RE_PAYCODE.match(paycode), "{0} is not a paycode".format(paycode)
#     pubkey, _ = deserialize_paycode(paycode)
#     return compress(privtopub(privkey)) == pubkey


def get_xor_paycode(a, B, outpoint, paycode_in):
    #assert bip47_check_derivation(a, paycode_in), "Privkey, {0}, not derived from {1}".format(a, paycode_in)
    bf = unhexlify(find_blinding_factor(a, B, outpoint))
    x, c = deserialize_paycode(paycode_in)
    parity = x[:2]
    x = x[2:]
    assert parity in ('02', '03')
    xdash = sxor(bf[:32], changebase(x, 16, 256, 32))
    cdash = sxor(bf[-32:], changebase(c, 16, 256, 32))
    return serialize_paycode(parity+changebase(xdash, 256, 16, 64), changebase(cdash, 256, 16, 64))


#def check_blinded_paycode(a, B, outpoint, paycode_in):
#    bf = unhexlify(find_blinding_factor(a, B, outpoint))

# a = private key which signs outpoint, "txid:1", and sends to B's notification address
def bip47_mk_notification_tx(a, outpoint, paycodeB):
    # a is a privkey which should be difficult to associate with Alice
    from_addr = privtoaddr(a)
    from_pubkey = compress(privtopub(a))
    pubB, chaincodeB = deserialize_paycode(paycodeB)
    notification_address = pubtoaddr(pubB)
    
    # TODO: need to figure out how the value is decided
    
    txh = blockcypher_mktx(from_addr, notification_address, 50000)
    txo = deserialize(txh)
    outpoint = ""
#     for inp in txo["ins"]:
#         spk_items = deserialize_script(inp.get("script"))
#         if RE_DER.match(spk_items[0]) and RE_PUBKEY.match(spk_items[-1]):
#                      
#         if spk[-1] in (from_pubkey, decompress(from_pubkey)):
#              outpoint = "{hash}:{index}".format(hash=inp["outpoint"]["hash"], index=inp["outpoint"]["index"])
#     txo['outs'].append({'script': get_xor_paycode(a, B, outpoint, ), 'value': 0})




def bip47_check_address(addr, index=0):
    """Checks notification address at decreasing indexes for payments, 
    returns [{"txid:vout": "6a4c5001..."}]"""
    #from bitcoin.transaction import get_script
    un = unspent(addr)[int(index) : 1+int(index)]
    outpoints = access(un, "output")[int(index)]
    txids = map(lambda s: str(s[:64]), outpoints)
    #scripts = []
    scriptpks = list(multiaccess(txo.get('outs'), 'script'))
    opret = filter(lambda s: s.startswith("6a4c5001"), scriptpks)
    assert is_bip47_code(deserialize_script(opret)[-1])
    
    return scripts
    # if scriptpk startswith 01 then select first exposed pubkey



    

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
bip47_txid2 = "9414f1681fb1255bd168a806254321a837008dd4480c02226063183deb100204"

pchex = "010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b00000000000000000000000000"

txh = "010000000186f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c010000006b483045022100ac8c6dbc482c79e86c18928a8b364923c774bfdbd852059f6b3778f2319b59a7022029d7cc5724e2f41ab1fcfc0ba5a0d4f57ca76f72f19530ba97c860c70a6bf0a801210272d83d8a1fa323feab1c085157a0791b46eba34afb8bfbfaeb3a3fcc3f2c9ad8ffffffff0210270000000000001976a9148066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac1027000000000000536a4c50010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b0000000000000000000000000000000000"

txo = {
    'ins': [{'outpoint': {'hash': '9c6000d597c5008f7bfc2618aed5e4a6ae57677aab95078aae708e1cab11f486',
                       'index': 1},
          'script': '483045022100ac8c6dbc482c79e86c18928a8b364923c774bfdbd852059f6b3778f2319b59a7022029d7cc5724e2f41ab1fcfc0ba5a0d4f57ca76f72f19530ba97c860c70a6bf0a801210272d83d8a1fa323feab1c085157a0791b46eba34afb8bfbfaeb3a3fcc3f2c9ad8',
          'sequence': 4294967295}],
    'locktime': 0,
    'outs': [{'script': '76a9148066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac',
           'value': 10000},
          {'script': '6a4c50010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b00000000000000000000000000',
           'value': 10000}],
    'version': 1}


ins = ['9414f1681fb1255bd168a806254321a837008dd4480c02226063183deb100204:1']
outs = ['1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV:50000']
outpoint = ins[0]
raw = "0100000001040210eb3d18636022020c48d48d0037a821432506a868d15b25b11f68f114940100000000ffffffff0150c30000000000001976a9148066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac00000000"
rawo = {'locktime': 0, 'outs': [{'value': 50000, 'script': '76a9148066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac'}], 'version': 1, 'ins': [{'script': '', 'outpoint': {'index': 1, 'hash': '9414f1681fb1255bd168a806254321a837008dd4480c02226063183deb100204'}, 'sequence': 4294967295}]}
#rawo['outs'].append({'script': get_xor_paycode(a0, B0, outpoint, Bpc), 'value': 0})
 
Apubkey = "xpub6D3t231wUi5v9PEa8mgmyV7Tovg3CzrGEUGNQTfm9cK93je3PgX9udfhzUDx29pkeeHQBPpTSHpAxnDgsf2XRbvLrmbCUQybjtHx8SUb3JB"
Bpubkey = "xpub6CcJ6kZ6c9PaqcHS11GvRBHtGQS6Q5scFxNoBBSHMGZgXgPQdnwA9xZwfquC4rnLVH9ua1sNmL6uBLFHSYH2ZwFvsVHV1ELuM5pSDSA9pfK"
