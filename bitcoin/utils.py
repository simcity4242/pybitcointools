from bitcoin.main import *
from bitcoin.bci import *
from bitcoin.transaction import *
from bitcoin.pyspecials import safe_hexlify, safe_unhexlify, st, by
import re

def ishex(s):
    return set(s).issubset(set('0123456789abcdefABCDEF'))

def satoshi_to_btc(val):
    return (float(val) / 1e8)

def btc_to_satoshi(val):
    return int(val*1e8 + 0.5)

# Return the address and btc_amount from the parsed uri_string.
# If either of address or amount is not found that particular
# return value is None.
def parse_bitcoin_uri(uri_string):
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

OPS = {
    '00': 'OP_FALSE',
    '4c': 'OP_PUSHDATA1',
    '4d': 'OP_PUSHDATA2',
    '4e': 'OP_PUSHDATA4',
    '4f': 'OP_1NEGATE',
    '51': 'OP_TRUE',
    '52': 'OP_2',
    '53': 'OP_3',
    '54': 'OP_4',
    '55': 'OP_5',
    '56': 'OP_6',
    '57': 'OP_7',
    '58': 'OP_8',
    '59': 'OP_9',
    '5a': 'OP_10',
    '5b': 'OP_11',
    '5c': 'OP_12',
    '5d': 'OP_13',
    '5e': 'OP_14',
    '5f': 'OP_15',
    '60': 'OP_16',
    '61': 'OP_NOP',
    '63': 'OP_IF',
    '64': 'OP_NOTIF',
    '67': 'OP_ELSE',
    '68': 'OP_ENDIF',
    '69': 'OP_VERIFY',
    '6a': 'OP_RETURN',
    '6b': 'OP_TOALTSTACK',
    '6c': 'OP_FROMALTSTACK',
    '73': 'OP_IFDUP',
    '74': 'OP_DEPTH',
    '75': 'OP_DROP',
    '76': 'OP_DUP',
    '77': 'OP_NIP',
    '78': 'OP_OVER',
    '79': 'OP_PICK',
    '7a': 'OP_ROLL',
    '7b': 'OP_ROT',
    '7c': 'OP_SWAP',
    '7d': 'OP_TUCK',
    '6d': 'OP_2DROP',
    '6e': 'OP_2DUP',
    '6f': 'OP_3DUP',
    '70': 'OP_2OVER',
    '71': 'OP_2ROT',
    '72': 'OP_2SWAP',
    '7e': 'OP_CAT',
    '7f': 'OP_SUBSTR',
    '80': 'OP_LEFT',
    '81': 'OP_RIGHT',
    '82': 'OP_SIZE',
    '83': 'OP_INVERT',
    '84': 'OP_AND',
    '85': 'OP_OR',
    '86': 'OP_XOR',
    '87': 'OP_EQUAL',
    '88': 'OP_EQUALVERIFY',
    '8b': 'OP_1ADD',
    '8c': 'OP_1SUB',
    '8d': 'OP_2MUL',
    '8e': 'OP_2DIV',
    '8f': 'OP_NEGATE',
    '90': 'OP_ABS',
    '91': 'OP_NOT',
    '92': 'OP_0NOTEQUAL',
    '93': 'OP_ADD',
    '94': 'OP_SUB',
    '95': 'OP_MUL',
    '96': 'OP_DIV',
    '97': 'OP_MOD',
    '98': 'OP_LSHIFT',
    '99': 'OP_RSHIFT',
    '9a': 'OP_BOOLAND',
    '9b': 'OP_BOOLOR',
    '9c': 'OP_NUMEQUAL',
    '9d': 'OP_NUMEQUALVERIFY',
    '9e': 'OP_NUMNOTEQUAL',
    '9f': 'OP_LESSTHAN',
    'a0': 'OP_GREATERTHAN',
    'a1': 'OP_LESSTHANOREQUAL',
    'a2': 'OP_GREATERTHANOREQUAL',
    'a3': 'OP_MIN',
    'a4': 'OP_MAX',
    'a5': 'OP_WITHIN',
    'a6': 'OP_RIPEMD160',
    'a7': 'OP_SHA1',
    'a8': 'OP_SHA256',
    'a9': 'OP_HASH160',
    'aa': 'OP_HASH256',
    'ab': 'OP_CODESEPARATOR',
    'ac': 'OP_CHECKSIG',
    'ad': 'OP_CHECKSIGVERIFY',
    'ae': 'OP_CHECKMULTISIG',
    'af': 'OP_CHECKMULTISIGVERIFY',
    'fd': 'OP_PUBKEYHASH',
    'fe': 'OP_PUBKEY',
    'ff': 'OP_INVALIDOPCODE',
    '50': 'OP_RESERVED',
    '62': 'OP_VER',
    '65': 'OP_VERIF',
    '66': 'OP_VERNOTIF',
    '89': 'OP_RESERVED1',
    '8a': 'OP_RESERVED2',
    'b0': 'OP_NOP0',
    'b1': 'OP_NOP1',
    'b2': 'OP_NOP2',
    'b3': 'OP_NOP3',
    'b4': 'OP_NOP4',
    'b5': 'OP_NOP5',
    'b6': 'OP_NOP6',
    'b7': 'OP_NOP7',
    'b8': 'OP_NOP8',
    'b9': 'OP_NOP9',
}

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

# SUBSETS
#OPCODES_PUSHDATA = set(xrange(0, 96+1))
#OPCODES_INTEGERS = set(xrange(0x51, 0x60+1))
#OPCODES_CRYPTO = set([166, 167, 168, 169, 170])
#OPCODES_LOGIC = set([99, 100, 101, 102, 103, 104])
#OPCODES_ARITHMETIC = set(xrange(139, 152))
#OPCODES_SIGCHECKS = 


#REGEX_PATTERNS = {
#        'P2PKH': re.compile('OP_DUP OP_HASH160 [abcdef0123456789]+ OP_EQUALVERIFY OP_CHECKSIG'),
#        'P2SH': re.compile('OP_HASH160 .* OP_EQUAL'),
#        'Multisig': re.compile('(OP_FALSE|OP_0|OP_TRUE) ([abcdef0123456789]+ )+(OP_1|OP_2|OP_3|OP_4|OP_5) OP_CHECKMULTISIG'),
#        'Pubkey': re.compile('[abcdef0123456789]+ OP_CHECKSIG'),
#        'Null Data': re.compile('OP_RETURN [abcdef0123456789]+'),
#}

OPname = dict([(k[3:], v) for k, v in OPCODE_LIST])
OPint = dict([(v,k) for k,v in OPCODE_LIST])
OPhex = dict([(encode(k, 16, 2), v) for v,k in OPCODE_LIST])
getop = lambda o: OPname.get(o.upper() if not o.startswith("OP_") else o[2:], 0)

#addr="n1hjyVvYQPQtejJcANd5ZJM5rmxHCCgWL7"

#SIG64="G8kH/WEgiATGXSy78yToe36IF9AUlluY3bMdkDFD1XyyDciIbXkfiZxk/qmjGdMeP6/BQJ/C5U/pbQUZv1HGkn8="

priv = sha256("mrbubby"*3+"!")
pub = privtopub(priv)
addr = privtoaddr(priv, 111)
pkh = mk_pubkey_script(addr)[6:-4]

masterpriv = sha256("master"*42)
masterpub = compress(privtopub(masterpriv))
masteraddr = pubtoaddr(masterpub, 111)

ops = [
       OPname['IF'], 
       masterpub, 
       OPname['CHECKSIGVERIFY'], 
       OPname['ELSE'],
       safe_hexlify(from_int_to_le_bytes(507776)), # '80bf07'
       OPname['NOP2'], 
       OPname['DROP'], 
       OPname['ENDIF'], 
       pub, 
       OPname['CHECKSIG']
       ]

myscript = "63210330ed33784ee1891122bc608b89da2da45194efaca68564051e5a7be9bee7f63fad670380bf07" \
           "b1756841042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe999" \
           "7d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9ac"

msaddr = "2NBrWPN37wvZhMYb66h23v5rScuVRDDFNsR"

pushedtx_txid = "2e7f518ce5ab61c1c959d25e396bc9d3d684d22ea86dc477b1a90329c6ca354f"

raw = mktx(
    ["2e7f518ce5ab61c1c959d25e396bc9d3d684d22ea86dc477b1a90329c6ca354f:1"],
    [{'value': 84480000, 'script': '76a914dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac'}])

#signing_tx = signature_form(tx, i, '<utxo_scriptPubKey>', hashcode)
signing_tx = signature_form(raw, 0, myscript)

sig1 = multisign(signing_tx, 0, myscript, masterpriv)
sig2 = multisign(signing_tx, 0, myscript, priv)
signed1 = apply_multisignatures(raw, 0, myscript, sig1, sig2)
