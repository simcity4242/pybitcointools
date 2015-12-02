import re
from pprint import pprint as pp
from struct import pack
from bitcoin.main import *
from bitcoin.main import privtopub, privtoaddr, pubtoaddr
from bitcoin.transaction import *
from bitcoin.bci import *



OPS = {
 'OP_0': 0,
 'OP_0NOTEQUAL': 146,
 'OP_1': 81,
 'OP_10': 90,
 'OP_11': 91,
 'OP_12': 92,
 'OP_13': 93,
 'OP_14': 94,
 'OP_15': 95,
 'OP_16': 96,
 'OP_1ADD': 139,
 'OP_1NEGATE': 79,
 'OP_1SUB': 140,
 'OP_2': 82,
 'OP_2DIV': 142,
 'OP_2DROP': 109,
 'OP_2DUP': 110,
 'OP_2MUL': 141,
 'OP_2OVER': 112,
 'OP_2ROT': 113,
 'OP_2SWAP': 114,
 'OP_3': 83,
 'OP_3DUP': 111,
 'OP_4': 84,
 'OP_5': 85,
 'OP_6': 86,
 'OP_7': 87,
 'OP_8': 88,
 'OP_9': 89,
 'OP_ABS': 144,
 'OP_ADD': 147,
 'OP_AND': 132,
 'OP_BOOLAND': 154,
 'OP_BOOLOR': 155,
 'OP_CAT': 126,
 'OP_CHECKLOCKTIMEVERIFY': 177,
 'OP_CHECKMULTISIG': 174,
 'OP_CHECKMULTISIGVERIFY': 175,
 'OP_CHECKSIG': 172,
 'OP_CHECKSIGVERIFY': 173,
 'OP_CODESEPARATOR': 171,
 'OP_DEPTH': 116,
 'OP_DIV': 150,
 'OP_DROP': 117,
 'OP_DUP': 118,
 'OP_ELSE': 103,
 'OP_ENDIF': 104,
 'OP_EQUAL': 135,
 'OP_EQUALVERIFY': 136,
 'OP_FALSE': 0,
 'OP_FROMALTSTACK': 108,
 'OP_GREATERTHAN': 160,
 'OP_GREATERTHANOREQUAL': 162,
 'OP_HASH160': 169,
 'OP_HASH256': 170,
 'OP_IF': 99,
 'OP_IFDUP': 115,
 'OP_INVALIDOPCODE': 255,
 'OP_INVERT': 131,
 'OP_LEFT': 128,
 'OP_LESSTHAN': 159,
 'OP_LESSTHANOREQUAL': 161,
 'OP_LSHIFT': 152,
 'OP_MAX': 164,
 'OP_MIN': 163,
 'OP_MOD': 151,
 'OP_MUL': 149,
 'OP_NEGATE': 143,
 'OP_NIP': 119,
 'OP_NOP': 97,
 'OP_NOP1': 176,
 'OP_NOP10': 185,
 'OP_NOP2': 177,
 'OP_NOP3': 178,
 'OP_NOP4': 179,
 'OP_NOP5': 180,
 'OP_NOP6': 181,
 'OP_NOP7': 182,
 'OP_NOP8': 183,
 'OP_NOP9': 184,
 'OP_NOT': 145,
 'OP_NOTIF': 100,
 'OP_NUMEQUAL': 156,
 'OP_NUMEQUALVERIFY': 157,
 'OP_NUMNOTEQUAL': 158,
 'OP_OR': 133,
 'OP_OVER': 120,
 'OP_PICK': 121,
 'OP_PUBKEY': 254,
 'OP_PUBKEYHASH': 253,
 'OP_PUSHDATA1': 76,
 'OP_PUSHDATA2': 77,
 'OP_PUSHDATA4': 78,
 'OP_RESERVED': 80,
 'OP_RESERVED1': 137,
 'OP_RESERVED2': 138,
 'OP_RETURN': 106,
 'OP_RIGHT': 129,
 'OP_RIPEMD160': 166,
 'OP_ROLL': 122,
 'OP_ROT': 123,
 'OP_RSHIFT': 153,
 'OP_SHA1': 167,
 'OP_SHA256': 168,
 'OP_SIZE': 130,
 'OP_SUB': 148,
 'OP_SUBSTR': 127,
 'OP_SWAP': 124,
 'OP_TOALTSTACK': 107,
 'OP_TRUE': 81,
 'OP_TUCK': 125,
 'OP_VER': 98,
 'OP_VERIF': 101,
 'OP_VERIFY': 105,
 'OP_VERNOTIF': 102,
 'OP_WITHIN': 165,
 'OP_XOR': 134
       }

OPCODES_BY_NAME = dict([(k, v) for k, v in OPS.items()])
OPCODES_BY_NAME.update(dict([(k[3:], v) for k, v in OPS.items()]))

OPint = dict([(v,k) for k,v in OPS.items()])

def get_op(s):
    """Returns OP_CODE for integer, or integer for OP_CODE"""
    getop = lambda o: OPCODES_BY_NAME.get(o.upper() if not o.startswith("OP_") else str(o[2:]).upper(), 0)
    if isinstance(s, int):
        return OPint.get(s, "")
    elif isinstance(s, string_types):
        return getop(s)

def parse_script(s):
    def ishex(s):
        return set(s).issubset(set('0123456789abcdefABCDEF'))
    r = []

    opcodes_by_name = {}
    for name, code in OPCODES_BY_NAME.items():
        opcodes_by_name[name] = code
        opcodes_by_name[name[3:]] = code

    for word in s.split():
        if word.isdigit() or (word[0] == '-' and word[1:].isdigit()):
            r.append(int(word))
        elif word.startswith('0x') and ishex(word[2:]):
            if int(word[2:], 16) <= 0x4e:
                continue
            else:
                r.append(word[2:])
        elif len(word) >= 2 and word[0] == "'" and word[-1] == "'":
            r.append(word[1:-1])
        elif word in opcodes_by_name:
            r.append(opcodes_by_name[word])  # r.append(get_op(v[3:]))
        else:
            raise ValueError("could not parse script! (word=\t%s)" % str(word))

    try:
        sc = serialize_script(r)
    except:
        sys.stderr.write("Didnt work!\nr = %s" % repr(r))
        raw_input("??")
        #FIXME: index #s 7,12,13,24 don't work
        sc = r
    return sc

priv, pub, addr = '', '', ''

def mk_privpubaddr(privkey, compressed=False, magicbyte=0):
    global priv, pub, addr
    priv = encode_privkey(decode_privkey(privkey), 'hex')
    pub = privtopub(compress(priv)) if compressed else privtopub(priv)
    addr = pubtoaddr(pub, int(magicbyte))
    return priv, pub, addr


def is_hex(s):
        return re.match('^[0-9a-fA-F]*$', s) #set(s).issubset(set('0123456789abcdefABCDEF'))

def is_txhex(txhex):
    if not isinstance(txhex, basestring):
        return False
    elif not re.match('^[0-9a-fA-F]*$', txhex):
        return binascii.unhexlify(is_txhex(binascii.hexlify(txhex)))
    txhex = st(txhex)
    return txhex.startswith('01000000')


def is_txobj(txobj):
    if not isinstance(txobj, dict):
        return False
    elif isinstance(txobj, list) and len(txobj) == 1:
        return is_txobj(txobj[0]) if isinstance(txobj[0], dict) else False
    return set(['locktime', 'version']).issubset(set(txobj.keys()))


def is_tx(txobj):
    if isinstance(txobj, dict):
        return is_txobj(txobj)
    elif isinstance(txobj, string_types):
        return is_txhex(txobj)
    else:
        return False

sig64="G8kH/WEgiATGXSy78yToe36IF9AUlluY3bMdkDFD1XyyDciIbXkfiZxk/qmjGdMeP6/BQJ/C5U/pbQUZv1HGkn8="

#tpriv = hashlib.sha256(b"mrbubby"*3+b"!").hexdigest()
#tpriv2 = tpriv+"01"
#tpub, tpub2 = privtopub(tpriv), privtopub(tpriv2)
#taddr, taddr2 = privtoaddr(tpriv, 111), privtoaddr(tpriv2, 111)
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


def little_endian_varint(integer):
    """Convert an integer to the Bitcoin variable length integer.
    See here for the protocol specification:
        https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
    See here for the `struct.pack` format options:
        https://docs.python.org/2/library/struct.html#format-characters
    """
    if integer < 0xfd:
        prefix = b''
        format = b'<B'
    elif integer <= 0xffff:
        prefix = b'\xfd'
        format = b'<H'
    elif integer <= 0xffffffff:
        prefix = b'\xfe'
        format = b'<I'
    else:
        prefix = b'\xff'
        format = b'<Q'

    return prefix + pack(format, integer)


def little_endian_uint8(int8):
    """Convert an integer into a 1 byte little endian string."""
    return pack(b'<B', int8)


def little_endian_uint16(int16):
    """Convert an integer into a 2 bytes little endian string."""
    return pack(b'<H', int16)


def little_endian_uint32(int32):
    """Convert an integer into a 4 bytes little endian string."""
    return pack(b'<I', int32)


def little_endian_uint64(int32):
    """Convert an integer into a 8 bytes little endian string."""
    return pack(b'<Q', int32)


def little_endian_str(string):
    return string[::-1]


def little_endian_hex(hexa):
    data = binascii.unhexlify(hexa)
    return data[::-1]


def rev(s):
    """Reverse Endianess of bytes or hex string"""
    if isinstance(s, string_or_bytes_types) and re.match('^[0-9a-fA-F]*$', s):
        return safe_hexlify(rev(safe_unhexlify(s)))
    return s[::-1]



mtxid, ttxid = "6df88400ab991f31be5d44be76d46ff3cb482e6417c8b472037d932424a191ff", "b6bdca9c8550fc41e064bbf2dd8f47095477a90500669bd5e68045720c6a4735"

txid, txh = "45138cc9dd17b13950230cd64d75891df829ec9b4b3e8aa3b9d2efbb3710965e", "0100000001c09beb3a51df3bac6291cfdef518dd212aeef25b40846c6470fc851f71ffc097010000008b483045022100b5809dab5c6769877e96b3d01f3397e845eaf8fa3156e45a78b22f8c56c9ed790220748538a23636121fc231cf20303f73dd782c9a346061e6597d1d993f754e51180141042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9ffffffff02e063b637000000001976a914dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac00e1f505000000001976a9144311df3f63e71ab012d52ac148637278993fd39f88ac00000000"

txh2 = "0100000003d5001aae8358ae98cb02c1b6f9859dc1ac3dbc1e9cc88632afeb7b7e3c510a49000000008b4830450221009e03bb6122437767e2ca785535824f4ed13d2ebbb9fa4f9becc6d6f4e1e217dc022064577353c08d8d974250143d920d3b963b463e43bbb90f3371060645c49266b90141048ef80f6bd6b073407a69299c2ba89de48adb59bb9689a5ab040befbbebcfbb15d01b006a6b825121a0d2c546c277acb60f0bd3203bd501b8d67c7dba91f27f47ffffffff1529d655dff6a0f6c9815ee835312fb3ca4df622fde21b6b9097666e9284087d010000008a473044022035dd67d18b575ebd339d05ca6ffa1d27d7549bd993aeaf430985795459fc139402201aaa162cc50181cee493870c9479b1148243a33923cb77be44a73ca554a4e5d60141048ef80f6bd6b073407a69299c2ba89de48adb59bb9689a5ab040befbbebcfbb15d01b006a6b825121a0d2c546c277acb60f0bd3203bd501b8d67c7dba91f27f47ffffffff23d5f9cf0a8c233b35443c3ae48d0bdb41bef357b8bfb972336322a34cd75c80010000008b483045022014daa5c5bbe9b3e5f2539a5cd8e22ce55bc84788f946c5b3643ecac85b4591a9022100a4062074a1df3fa0aea5ef67368d0b1f0eaac520bee6e417c682d83cd04330450141048ef80f6bd6b073407a69299c2ba89de48adb59bb9689a5ab040befbbebcfbb15d01b006a6b825121a0d2c546c277acb60f0bd3203bd501b8d67c7dba91f27f47ffffffff02204e0000000000001976a914946cb2e08075bcbaf157e47bcb67eb2b2339d24288ac5b3c4411000000001976a914a41d15ae657ad3bfd0846771a34d7584c37d54a288ac00000000"

der = '3045022100bcef87b07aacf2349811036bed425b5b2f1e5b3d7a572b567354688dae503c4e02205df245bd973d236320b8252f4d898699455101d215c01c83ab8370d9bb6b548c01'


addr_1jca = "1JCAugEs1ETUKRXMBpxeCPERS6xPymP3ZM" 
addr_14zw = "14zWNsgUMmHhYx4suzc2tZD6HieGbkQi5s"
addr_1e8j = "1E8JPJRav51yGrCYXKtCQr4k9o93MvprdQ"
addr_14md = "14MDR5y8nHpqN7VtCKoDMMyfbeAD1HP9EW"
