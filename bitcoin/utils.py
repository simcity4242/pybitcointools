from bitcoin.main import *
from bitcoin.pyspecials import *
import urlparse, re

def satoshi_to_btc(val):
    return (float(val) / 10**8)

def btc_to_satoshi(val):
    return int(val * 10**8 + 0.5)

# Return the address and btc_amount from the
# parsed uri_string. If either of address
# or amount is not found that particular
# return value is None.
def parse_bitcoin_uri(uri_string):
    parsed = urlparse.urlparse(uri_string)
    if parsed.scheme == 'bitcoin':
        addr = parsed.path
        queries = urlparse.parse_qs(parsed.query)
        if 'amount' not in queries:
            btc_amount = None
        elif len(queries['amount']) == 1:
            btc_amount = float(queries['amount'][0])
        else:
            btc_amount = None
        return addr, btc_amount
    else:
        return None, None


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

STANDARD_TRANSACTION_LIST = [
    'P2PKH',
    'P2SH',
    'Multisig',
    'Pubkey',
    'Null Data',
]

REGEX_PATTERNS = {
        'P2PKH': re.compile('OP_DUP OP_HASH160 [abcdef0123456789]+ OP_EQUALVERIFY OP_CHECKSIG'),
        'P2SH': re.compile('OP_HASH160 .* OP_EQUAL'),
        'Multisig': re.compile('(OP_FALSE|OP_0|OP_TRUE) ([abcdef0123456789]+ )+(OP_1|OP_2|OP_3|OP_4|OP_5) OP_CHECKMULTISIG'),
        'Pubkey': re.compile('[abcdef0123456789]+ OP_CHECKSIG'),
        'Null Data': re.compile('OP_RETURN [abcdef0123456789]+'),
}

OPname = dict([(v[3:], k) for k, v in OPS.iteritems()])
OPint = dict([(decode(k, 16), v) for k, v in OPS.iteritems()])
OPhex = OPS.copy()

addr="n1hjyVvYQPQtejJcANd5ZJM5rmxHCCgWL7"

#SIG64="G8kH/WEgiATGXSy78yToe36IF9AUlluY3bMdkDFD1XyyDciIbXkfiZxk/qmjGdMeP6/BQJ/C5U/pbQUZv1HGkn8="
