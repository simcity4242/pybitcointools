import re
from pprint import pprint as pp
from bitcoin.main import *
from bitcoin.transaction import *
from bitcoin.bci import *


def ishex(s):
    return set(s).issubset(set('0123456789abcdefABCDEF'))

def isbin(s):
    if not (is_python2 or isinstance(s, bytes)):
        return False
    if len(s)%2 == 1:
        return True
    try: 
        binascii.unhexlify(s)
        return False
    except TypeError: 
        return True

def satoshi_to_btc(val):
    return (float(val) / 1e8)

def btc_to_satoshi(val):
    return int(val*1e8 + 0.5)

# Return the address and btc_amount from the parsed uri_string.
# If either of address or amount is not found that particular return value is None.
def parse_bitcoin_uri(uri_string):
    # TODO: fix for new BIP70
    import urlparse
    parsed = urlparse.urlparse(uri_string)
    if parsed.scheme != 'bitcoin':
        return None, None
    elif parsed.scheme == 'bitcoin':
        addr = parsed.path
        queries = urlparse.parse_qs(parsed.query)
        if 'amount' not in queries:       btc_amount = None
        elif len(queries['amount']) == 1: btc_amount = float(queries['amount'][0])
        else:                             btc_amount = None
        return addr, btc_amount


OPCODE_LIST = [
  ("OP_0", 0),
  ("OP_PUSHDATA1", 76),
  ("OP_PUSHDATA2", 77),
  ("OP_PUSHDATA4", 78),
  ("OP_1NEGATE", 79),
  ("OP_RESERVED", 80),
  ("OP_1", 81),
  ("OP_2", 82),
  ("OP_3", 83),
  ("OP_4", 84),
  ("OP_5", 85),
  ("OP_6", 86),
  ("OP_7", 87),
  ("OP_8", 88),
  ("OP_9", 89),
  ("OP_10", 90),
  ("OP_11", 91),
  ("OP_12", 92),
  ("OP_13", 93),
  ("OP_14", 94),
  ("OP_15", 95),
  ("OP_16", 96),
  ("OP_NOP", 97),
  ("OP_VER", 98),
  ("OP_IF", 99),
  ("OP_NOTIF", 100),
  ("OP_VERIF", 101),
  ("OP_VERNOTIF", 102),
  ("OP_ELSE", 103),
  ("OP_ENDIF", 104),
  ("OP_VERIFY", 105),
  ("OP_RETURN", 106),
  ("OP_TOALTSTACK", 107),
  ("OP_FROMALTSTACK", 108),
  ("OP_2DROP", 109),
  ("OP_2DUP", 110),
  ("OP_3DUP", 111),
  ("OP_2OVER", 112),
  ("OP_2ROT", 113),
  ("OP_2SWAP", 114),
  ("OP_IFDUP", 115),
  ("OP_DEPTH", 116),
  ("OP_DROP", 117),
  ("OP_DUP", 118),
  ("OP_NIP", 119),
  ("OP_OVER", 120),
  ("OP_PICK", 121),
  ("OP_ROLL", 122),
  ("OP_ROT", 123),
  ("OP_SWAP", 124),
  ("OP_TUCK", 125),
  ("OP_CAT", 126),
  ("OP_SUBSTR", 127),
  ("OP_LEFT", 128),
  ("OP_RIGHT", 129),
  ("OP_SIZE", 130),
  ("OP_INVERT", 131),
  ("OP_AND", 132),
  ("OP_OR", 133),
  ("OP_XOR", 134),
  ("OP_EQUAL", 135),
  ("OP_EQUALVERIFY", 136),
  ("OP_RESERVED1", 137),
  ("OP_RESERVED2", 138),
  ("OP_1ADD", 139),
  ("OP_1SUB", 140),
  ("OP_2MUL", 141),
  ("OP_2DIV", 142),
  ("OP_NEGATE", 143),
  ("OP_ABS", 144),
  ("OP_NOT", 145),
  ("OP_0NOTEQUAL", 146),
  ("OP_ADD", 147),
  ("OP_SUB", 148),
  ("OP_MUL", 149),
  ("OP_DIV", 150),
  ("OP_MOD", 151),
  ("OP_LSHIFT", 152),
  ("OP_RSHIFT", 153),
  ("OP_BOOLAND", 154),
  ("OP_BOOLOR", 155),
  ("OP_NUMEQUAL", 156),
  ("OP_NUMEQUALVERIFY", 157),
  ("OP_NUMNOTEQUAL", 158),
  ("OP_LESSTHAN", 159),
  ("OP_GREATERTHAN", 160),
  ("OP_LESSTHANOREQUAL", 161),
  ("OP_GREATERTHANOREQUAL", 162),
  ("OP_MIN", 163),
  ("OP_MAX", 164),
  ("OP_WITHIN", 165),
  ("OP_RIPEMD160", 166),
  ("OP_SHA1", 167),
  ("OP_SHA256", 168),
  ("OP_HASH160", 169),
  ("OP_HASH256", 170),
  ("OP_CODESEPARATOR", 171),
  ("OP_CHECKSIG", 172),
  ("OP_CHECKSIGVERIFY", 173),
  ("OP_CHECKMULTISIG", 174),
  ("OP_CHECKMULTISIGVERIFY", 175),
  ("OP_NOP1", 176),
  ("OP_NOP2", 177),
  ("OP_NOP3", 178),
  ("OP_NOP4", 179),
  ("OP_NOP5", 180),
  ("OP_NOP6", 181),
  ("OP_NOP7", 182),
  ("OP_NOP8", 183),
  ("OP_NOP9", 184),
  ("OP_NOP10", 185),
  ("OP_PUBKEYHASH", 253),
  ("OP_PUBKEY", 254),
  ("OP_INVALIDOPCODE", 255),
]

OP_ALIASES = [
    ("OP_CHECKLOCKTIMEVERIFY", 177),
    ("OP_TRUE", 81),
    ("OP_FALSE", 0)
]

OPname = dict([(k[3:], v) for k, v in OPCODE_LIST + OP_ALIASES]);OPname.update(dict([(k,v) for k,v in OPCODE_LIST + OP_ALIASES]))
OPint = dict([(v,k) for k,v in OPCODE_LIST])

def get_op(s):
    """Returns OP_CODE for integer, or integer for OP_CODE"""
    getop = lambda o: OPname.get(o.upper() if not o.startswith("OP_") else str(o[2:]).upper(), 0)
    if isinstance(s, int):
        return OPint.get(s, '')
    elif isinstance(s, basestring):
        return getop(s)

def parse_script(s):
    from bitcoin.transaction import serialize_script
    r = []
    for word in s.split():
        if word.isdigit() or (word[0] == '-' and word[1:].isdigit()):
            r.append(int(word, 0))
        elif word.startswith('0x') and ishex(word[2:]):
            if int(word[2:], 16) < 0x4c:
                continue
            else:
                r.append(word[2:])
        elif len(word) >= 2 and word[0] == "'" and word[-1] == "'":
            r.append(word[1:-1])
        elif word in OPname:
            r.append(OPname[word])  # r.append(get_op(v[3:]))
    return serialize_script(r)

#priv, pub, addr = '', '', ''

def mk_privpubaddr(privkey, compressed=False, magicbyte=0):
    global priv, pub, addr
    priv = encode_privkey(decode_privkey(privkey), 'hex')
    pub = privtopub(compress(priv)) if compressed else privtopub(priv)
    addr = pubtoaddr(pub, int(magicbyte))

def is_tx_hex(txhex):
    if not isinstance(txhex, basestring):
        return False
    elif not re.match('^[0-9a-fA-F]*$', txhex):
        return binascii.unhexlify(is_tx_hex(binascii.hexlify(txhex)))
    txhex = st(txhex)
    return txhex.startswith('01000000')

def is_tx_obj(txobj):
    if not isinstance(txobj, dict):
        return False
    elif isinstance(txobj, list) and len(txobj) == 1:
        return is_tx_obj(txobj[0]) if isinstance(txobj[0], dict) else False
    return {txobj.keys()} > {['locktime', 'version']}

             #addr="n1hjyVvYQPQtejJcANd5ZJM5rmxHCCgWL7"

#SIG64="G8kH/WEgiATGXSy78yToe36IF9AUlluY3bMdkDFD1XyyDciIbXkfiZxk/qmjGdMeP6/BQJ/C5U/pbQUZv1HGkn8="

tpriv = hashlib.sha256("mrbubby"*3+"!")
# tpub = privtopub(tpriv)
# taddr = privtoaddr(tpriv, 111)
#tpkh = pkh = mk_pubkey_script(addr)[6:-4]

masterpriv = hashlib.sha256("master"*42)
# masterpub = compress(privtopub(masterpriv))
# masteraddr = pubtoaddr(masterpub, 111)

# ops = [
#        OPname['IF'],
#        masterpub,
#        OPname['CHECKSIGVERIFY'],
#        OPname['ELSE'],
#        '80bf07', #binascii.hexlify(from_int_to_le_bytes(507776)), # '80bf07'
#        OPname['NOP2'],
#        OPname['DROP'],
#        OPname['ENDIF'],
#        tpub,
#        OPname['CHECKSIG']
#        ]

myscript = "63210330ed33784ee1891122bc608b89da2da45194efaca68564051e5a7be9bee7f63fad670380bf07" \
           "b1756841042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe999" \
           "7d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9ac"

msaddr = "2NBrWPN37wvZhMYb66h23v5rScuVRDDFNsR"

pushedtx_txid = "2e7f518ce5ab61c1c959d25e396bc9d3d684d22ea86dc477b1a90329c6ca354f"

txid = pizzatxid = 'cca7507897abc89628f450e8b1e0c6fca4ec3f7b34cccf55f3f531c659ff4d79';vout=i=0
#verify_tx_input(tx, 0, inspk, inder, inpub)
inder = "30450221009908144ca6539e09512b9295c8a27050d478fbb96f8addbc3d075544dc41328702201aa528be2b907d316d2da068dd9eb1e23243d97e444d59290d2fddf25269ee0e01"
inpub = "042e930f39ba62c6534ee98ed20ca98959d34aa9e057cda01cfd422c6bab3667b76426529382c23f42b9b08d7832d4fee1d6b437a8526e59667ce9c4e9dcebcabb"
inspk = "76a91446af3fb481837fadbb421727f9959c2d32a3682988ac"
inaddr = "17SkEw2md5avVNyYgj6RiXuQKNwkXaxFyQ";
modtx = signing_tx = tx = "01000000018dd4f5fbd5e980fc02f35c6ce145935b11e284605bf599a13c6d415db55d07a1000000001976a91446af3fb481837fadbb421727f9959c2d32a3682988acffffffff0200719a81860000001976a914df1bd49a6c9e34dfa8631f2c54cf39986027501b88ac009f0a5362000000434104cd5e9726e6afeae357b1806be25a4c3d3811775835d235417ea746b7db9eeab33cf01674b944c64561ce3388fa1abd0fa88b06c44ce81e2234aa70fe578d455dac00000000"
txh = "01000000018dd4f5fbd5e980fc02f35c6ce145935b11e284605bf599a13c6d415db55d07a1000000008b4830450221009908144ca6539e09512b9295c8a27050d478fbb96f8addbc3d075544dc41328702201aa528be2b907d316d2da068dd9eb1e23243d97e444d59290d2fddf25269ee0e0141042e930f39ba62c6534ee98ed20ca98959d34aa9e057cda01cfd422c6bab3667b76426529382c23f42b9b08d7832d4fee1d6b437a8526e59667ce9c4e9dcebcabbffffffff0200719a81860000001976a914df1bd49a6c9e34dfa8631f2c54cf39986027501b88ac009f0a5362000000434104cd5e9726e6afeae357b1806be25a4c3d3811775835d235417ea746b7db9eeab33cf01674b944c64561ce3388fa1abd0fa88b06c44ce81e2234aa70fe578d455dac00000000"


#raw = mktx(
#    ["2e7f518ce5ab61c1c959d25e396bc9d3d684d22ea86dc477b1a90329c6ca354f:1"],
#    [{'value': 84480000, 'script': '76a914dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac'}])
#
#signing_tx = signature_form(tx, i, '<utxo_scriptPubKey>', hashcode)
#signing_tx = signature_form(raw, 0, myscript)
#
#sig1 = multisign(signing_tx, 0, myscript, masterpriv)
#sig2 = multisign(signing_tx, 0, myscript, priv)
#signed1 = apply_multisignatures(raw, 0, myscript, sig1, sig2)
#
#txh = txh23b = "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba26000000000" \
#               "490047304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220" \
#               "ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f" \
#               "00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000"

#txo = txo23b = deserialize(txh23b)

#wif_re = re.compile(r"[1-9a-km-zA-LMNP-Z]{51,111}")


# PK = """3081d30201010420{0:064x}a081a53081a2020101302c06072a8648ce3d0101022100{1:064x}3006040100040107042102{2:064x}022100{3:064x}020101a124032200"""
# PK.strip().format(rki, P, Gx, N)+ compress(privtopub(rk))
# https://gist.github.com/simcity4242/b0bb0f0281fcf58deec2
