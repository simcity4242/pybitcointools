import re
from pprint import pprint as pp
from bitcoin.main import *;from bitcoin.main import privtopub, privtoaddr, pubtoaddr
from bitcoin.transaction import *
from bitcoin.bci import *


def ishex(s):
    return set(s).issubset(set('0123456789abcdefABCDEF'))


def isbin(s):
    if not (is_python2 and isinstance(s, bytes)): return False
    else: return True


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

OPname = dict([(k[3:], v) for k, v in OPCODE_LIST + OP_ALIASES]); OPname.update(dict([(k,v) for k,v in OPCODE_LIST + OP_ALIASES]))
OPint = dict([(v,k) for k,v in OPCODE_LIST])

def get_op(s):
    """Returns OP_CODE for integer, or integer for OP_CODE"""
    getop = lambda o: OPname.get(o.upper() if not o.startswith("OP_") else str(o[2:]).upper(), 0)
    if isinstance(s, int):
        return OPint.get(s, "")
    elif isinstance(s, string_types):
        return getop(s)

def parse_script(spk):
    from bitcoin.transaction import serialize_script
    spk, res = str(spk), []
    if all([x in spk for x in ['[', ']']]):   # HASH160 0x14 [0xdc44b1164188067c3a32d4780f5996fa14a4f2d9] EQUALVERIFY
        spk = spk.replace('[', '0x').replace(']', '')
    for word in spk.split():
        if word.isdigit() or (word[0] == '-' and word[1:].isdigit()):
            res.append(int(word, 0))
        elif word.startswith('0x') and re.match('^[0-9a-fA-F]*$', word[2:]):
            if int(word[2:], 16) < 0x4c:
                continue
            else:
                res.append(word[2:])
        elif len(word) >= 2 and word[0] == "'" and word[-1] == "'":
            res.append(word[1:-1])
        elif word.startswith('[0x') and word.endswith(']') and re.match('^[0-9a-fA-F]*$', word[3:-1]):
            word = word[1:-1]
            if int(word[2:], 16) < 0x4c:
                continue
            else:
                res.append(word[2:])
        elif word in OPname:
            res.append(OPname[word])  # r.append(get_op(v[3:]))
    return serialize_script(res)

#priv, pub, addr = '', '', ''

def mk_privpubaddr(privkey, compressed=False, magicbyte=0):
    global priv, pub, addr
    priv = encode_privkey(decode_privkey(privkey), 'hex')
    pub = privtopub(compress(priv)) if compressed else privtopub(priv)
    addr = pubtoaddr(pub, int(magicbyte))

def is_txhex(txhex):
    if not isinstance(txhex, basestring):
        return False
    elif not re.match('^[0-9a-fA-F]*$', txhex):
        return binascii.unhexlify(is_tx_hex(binascii.hexlify(txhex)))
    txhex = st(txhex)
    return txhex.startswith('01000000')

def is_txobj(txobj):
    if not isinstance(txobj, dict):
        return False
    elif isinstance(txobj, list) and len(txobj) == 1:
        return is_tx_obj(txobj[0]) if isinstance(txobj[0], dict) else False
    return set(['locktime', 'version']).issubset(set(txobj.keys()))


#SIG64="G8kH/WEgiATGXSy78yToe36IF9AUlluY3bMdkDFD1XyyDciIbXkfiZxk/qmjGdMeP6/BQJ/C5U/pbQUZv1HGkn8="

tpriv = hashlib.sha256(b"mrbubby"*3+b"!").hexdigest()
tpub = privtopub(tpriv)
taddr = privtoaddr(tpriv, 111)
#tpkh = pkh = mk_pubkey_script(addr)[6:-4]

masterpriv = hashlib.sha256(b"master"*42).hexdigest()
masterpub = compress(privtopub(masterpriv))
masteraddr = pubtoaddr(masterpub, 111)

# ops = [OPname['IF'], masterpub, OPname['CHECKSIGVERIFY'], OPname['ELSE'], '80bf07', #binascii.hexlify(from_int_to_le_bytes(507776)), # '80bf07' OPname['NOP2'], OPname['DROP'], OPname['ENDIF'], tpub, OPname['CHECKSIG']]


#wif_re = re.compile(r"[1-9a-km-zA-LMNP-Z]{51,111}")


PK = "3081d30201010420{0:064x}a081a53081a2020101302c06072a8648ce3d0101022100" \
     "{1:064x}3006040100040107042102{2:064x}022100{3:064x}020101a124032200"
#PK.strip().format(rki, P, Gx, N)+ compress(privtopub(rk))
# https://gist.github.com/simcity4242/b0bb0f0281fcf58deec2
