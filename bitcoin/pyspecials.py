import sys
import re
import binascii
import os
import hashlib
import struct


is_python2 = (str == bytes)
is_ios = "Pythonista" in os.environ.get("XPC_SERVICE_NAME", "")		# for Pythonista iOS

# REGEX

RE_HEX_CHARS = re.compile(r"^[0-9a-f]*$", re.I)
RE_TXID = re.compile(r'^[0-9a-f]{64}$', re.I)
RE_TXHEX = re.compile(r'^01000000[0-9a-f]{108,}$', re.I)
RE_BASE58_CHARS = re.compile('^[0-9a-km-zA-HJ-NP-Z]$')
RE_BLOCKHASH = re.compile(r'^(00000)[0-9a-f]{59}$', re.I)
RE_ADDR = re.compile(r'^[123mn][a-km-zA-HJ-NP-Z0-9]{25,34}$')
RE_PUBKEY = re.compile(r'^((02|03)[0-9a-f]{64})|(04[0-9a-f]{128})$', re.I)
RE_PRIVKEY = re.compile(r'^([0-9a-f]{64}(01)?)|([5KL9c][1-9a-km-zA-LMNP-Z]{50,51})|(\d){1,78}$')
RE_MNEMONIC = re.compile(r'^((\w+\b ){11})|(\w+\b ){23}\w+\b$')
RE_BIP32_PRIV = re.compile(r'^[xt]+prv[0-9a-km-zA-HJ-NP-Z]{76,108}$')
RE_BIP32_PUB = re.compile(r'^[xt]pub[0-9a-km-zA-HJ-NP-Z]{76,108}$')
RE_BIP32_PATH = re.compile(r'^((m/)|(M/))(\d+[\'H/])*(\.pub)?$')
RE_DER = re.compile(r'''
    30(?P<siglen>[0-4][0-9a-f])
    02(?P<rlen>[0-2][0-9a-f])(?P<r>(?:00)?[a-f0-9]{2,64})
    02(?P<slen>[0-2][0-9a-f])(?P<s>(?:00)?[a-f0-9]{2,64})
    (?P<sighash>(0|8)[0-3])?''', re.I | re.X)


#   PYTHON 2
if is_python2:
    
    st = lambda u: str(u)
    by = lambda v: bytes(v)

    string_types = (str, unicode)
    string_or_bytes_types = (str, unicode)
    int_types = (int, float, long)

    # Base switching
    code_strings = {
        2: '01',
        10: '0123456789',
        16  : '0123456789abcdef',
        32: 'abcdefghijklmnopqrstuvwxyz234567',
        58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
        256: ''.join([chr(x) for x in range(256)])
       }

    ### Hex to bin converter and vice versa for objects
    
    def is_txid(txid):
        if not isinstance(txid, string_types):
            return False
        if len(txid) == 64:
            return bool(RE_TXID.match(txid))
        elif len(txid) == 32:
            try:
                binascii.hexlify(txid)
                return True
            except:
                return False
    
    def is_hex(s):
        return bool(RE_HEX_CHARS.match(s)) 

    def is_txhex(txhex):
        if not isinstance  (txhex, basestring):
              return False
        elif not re.match(RE_HEX_CHARS, txhex):
            txhex = binascii.hexlify(txhex)
        return bool(RE_TXHEX.match(txhex))
 
    def is_txobj(txobj):
        if not isinstance(txobj, dict):
            return False
        return set(['locktime', 'version']).issubset(set(txobj.keys()))

    def is_tx(txobj):
        if isinstance(txobj, dict):
            return is_txobj(txobj)
        elif isinstance(txobj, string_types):
            return is_txhex(txobj)
        return False
            
    def is_blockhash(hash):
        if not isinstance(hash, string_types):
            return False
        return bool(RE_BLOCKHASH.match(hash))


    def json_is_base(obj, base):
        if not is_python2 and isinstance(obj, bytes):
            return False
        alpha = get_code_string(base)
        if isinstance(obj, string_types):
            for i in range(len(obj)):
                if alpha.find(obj[i]) == -1:
                    return False
            return True
        elif isinstance(obj, int_types) or obj is None:
            return True
        elif isinstance(obj, list):
            for i in range(len(obj)):
                if not json_is_base(obj[i], base):
                    return False
            return True
        else:
            for x in obj:
                if not json_is_base(obj[x], base):
                    return False
            return True

    def json_changebase(obj, changer):
        if isinstance(obj, string_types):
            return changer(obj)
        elif isinstance(obj, int_types) or obj is None:
            return obj
        elif isinstance(obj, list):
            return [json_changebase(x, changer) for x in obj]
        return dict((x, json_changebase(obj[x], changer)) for x in obj)

    def json_hexlify(obj):
        return json_changebase(obj, lambda x: binascii.hexlify(x))

    def json_unhexlify(obj):
        return json_changebase(obj, lambda x: binascii.unhexlify(x))

    def bin_dbl_sha256(s):
        bytes_to_hash = from_str_to_bytes(s)
        return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

    def lpad(msg, symbol, length):
        if len(msg) >= length:
            return msg
        return symbol * (length - len(msg)) + msg

    def get_code_string(base):
        if int(base) in code_strings:
            return code_strings[int(base)]
        else: raise ValueError("Invalid base!")

    def changebase(string, frm, to, minlen=0):
        if frm == to:
            return lpad(string, get_code_string(frm)[0], minlen)
        elif frm in (16, 256) and to == 58:
            if frm == 16:
                nblen = len(re.match('^(00)*', string).group(0))//2
            else:
                nblen = len(re.match('^(\x00)*', string).group(0))
            padding = lpad('', '1', nblen)
            return padding + encode(decode(string, frm), 58)
        elif frm == 58 and to in (16, 256):
            nblen = len(re.match('^(1)*', string).group(0))
            if to == 16:
                padding = lpad('', '00', nblen)
            else:
                padding = lpad('', '\0', nblen)
            return padding + encode(decode(string, 58), to)
        return encode(decode(string, frm), to, minlen)


    def bin_to_b58check(inp, magicbyte=0):
        inp_fmtd = from_int_to_byte(int(magicbyte)) + inp
        checksum = bin_dbl_sha256(inp_fmtd)[:4]
        return changebase(inp_fmtd + checksum, 256, 58)


    def safe_hexlify(b):
        if isinstance(b, string_or_bytes_types):
            return binascii.hexlify(b)
        elif isinstance(b, dict):
            return json_hexlify(b)
        else:
            raise TypeError("%s must be str/bytes or a dict of bytes" % type(b))


    def safe_unhexlify(s):
        if isinstance(s, string_or_bytes_types):
            return binascii.unhexlify(s)
        elif isinstance(s, dict):
            return json_unhexlify(s)
        else:
            raise TypeError("Not bytes or a dict of bytes")

    safe_from_hex = unhexlify = safe_unhexlify
    hexlify = safe_hexlify

    def from_int_repr_to_bytes(a):
        return str(a)

    def from_int_to_le_bytes(i, length=1):
        return from_int_to_bytes(i, length, 'little')

    def from_int_to_bytes(v, length=1, byteorder='little'):
        blen = len(encode(int(v), 256))
        length = length if (blen <= length) else blen
        l = bytearray()
        for i in range(length):
            mod = v & 255
            v >>= 8
            l.append(mod)
        if byteorder == 'big':
            l.reverse()
        return bytes(l)

    def from_int_to_byte(a):
        # return bytes([a])
        return chr(a)

    def from_byte_to_int(a):
        return ord(a)

    def from_le_bytes_to_int(bstr):
        return from_bytes_to_int(bstr, byteorder='little', signed=False)

    def from_bytes_to_int(bstr, byteorder='big', signed=False):
        if byteorder != 'big':
            bstr = bstr[::-1]
        v = 0
        bytes_to_ints = (lambda x: [ord(c) for c in x])
        for c in bytes_to_ints(bstr):
            v <<= 8
            v += c
        if signed and ord(bstr[0]) & 0x80:
            v = v - (1 << (8*len(bstr)))
        return v

    def from_str_to_bytes(a):
        return a #by(a)

    def from_bytes_to_str(a):
        return a #st(a)

    from_string_to_bytes = from_str_to_bytes
    from_bytes_to_string = from_bytes_to_str

    def short_hex(hexstr):
        if not re.match('^[0-9a-fA-F]*$', hexstr):
            return hexstr
        t = by(hexstr)
        return t[0:4]+"..."+t[-4:] if len(t)>=11 else t
	
    def encode(val, base, minlen=0):
        base, minlen = int(base), int(minlen)
        code_string = get_code_string(base)
        result = ""
        while val > 0:
            result = code_string[val % base] + result
            val //= base
        return code_string[0] * max(minlen - len(result), 0) + result

    def decode(string, base):
        base = int(base)
        code_string = get_code_string(base)
        result = 0
        if base == 16:
            string = string.lower()
        while len(string) > 0:
            result *= base
            result += code_string.find(string[0])
            string = string[1:]
        return result

    def random_string(x):
        return os.urandom(x)


#   PYTHON 3
elif sys.version_info.major > 2:

    xrange = range
    string_types = str
    string_or_bytes_types = (str, bytes)
    int_types = (int, float)

    st = lambda s: str(s, 'utf-8') if not isinstance(s, str) else s
    by = lambda b: bytes(b, 'utf-8') if not isinstance(b, bytes) else b

    # Base switching
    code_strings = {
        2: '01',
        10: '0123456789',
        16: '0123456789abcdef',
        32: 'abcdefghijklmnopqrstuvwxyz234567',
        58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
        256: ''.join([chr(x) for x in range(256)])
    }

    ### Hex to bin converter and vice versa for objects

    def json_is_base(obj, base):
        alpha = get_code_string(base)
        if isinstance(obj, string_types):
            for i in range(len(obj)):
                if alpha.find(obj[i]) == -1:
                    return False
            return True
        elif isinstance(obj, int_types) or obj is None:
            return True
        elif isinstance(obj, list):
            for i in range(len(obj)):
                if not json_is_base(obj[i], base):
                    return False
            return True
        else:
            for x in obj:
                if not json_is_base(obj[x], base):
                    return False
            return True

    def json_changebase(obj, changer):
        if isinstance(obj, string_types):
            return changer(obj)
        elif isinstance(obj, int_types) or obj is None:
            return obj
        elif isinstance(obj, list):
            return [json_changebase(x, changer) for x in obj]
        return dict((x, json_changebase(obj[x], changer)) for x in obj)

    def json_hexlify(obj):
        return json_changebase(obj, lambda x: binascii.hexlify(x))

    def json_unhexlify(obj):
        return json_changebase(obj, lambda x: binascii.unhexlify(x))

    def bin_dbl_sha256(s):
        bytes_to_hash = from_string_to_bytes(s)
        return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

    def lpad(msg, symbol, length):
        if len(msg) >= length:
            return msg
        return symbol * (length - len(msg)) + msg

    def get_code_string(base):
        if int(base) in code_strings:
            return code_strings[int(base)]
        else:
            raise ValueError("Invalid base!")

    def changebase(string, frm, to, minlen=0):
        string = by(string)
        if frm == to:
            return lpad(string, by(get_code_string(frm)[0]), minlen)
        elif frm in (16, 256) and to == 58:
            nblen = len(re.match(b'^(00)*', string).group(0))//2 if frm == 16 else \
                    len(re.match(b'^(\0)*', string).group(0))
            return lpad('', '1', nblen) + encode(decode(string, frm), 58)
        elif frm == 58 and to in (16, 256):
            nblen = len(re.match(b'^(1)*', string).group(0))
            padding = lpad(b'', b'00', nblen) if to == 16 else \
                      lpad(b'', b'\0', nblen)
            return padding + encode(decode(string, 58), to)
        return encode(decode(string, frm), to, minlen)

    def bin_to_b58check(inp, magicbyte=0):
        inp_fmtd = from_int_to_byte(int(magicbyte)) + inp
        checksum = bin_dbl_sha256(inp_fmtd)[:4]
        leadingzbytes = 0
        for x in inp_fmtd:
            if x != 0:
                break
            leadingzbytes += 1
        return '1' * leadingzbytes + changebase(inp_fmtd+checksum, 256, 58)

    def safe_hexlify(b):
        if isinstance(b, string_or_bytes_types):
            return st(binascii.hexlify(b))
        elif isinstance(b, dict):
            return json_hexlify(b)
        elif isinstance(b, int_types) or (b is None):
            return b
        elif isinstance(b, list):
            return [hexlify(x) for x in b]

    def safe_unhexlify(s):
        if isinstance(s, string_or_bytes_types):
            return binascii.unhexlify(s)
        elif isinstance(s, dict):
            return json_unhexlify(s)
        elif isinstance(s, int_types) or (s is None):
            return s
        elif isinstance(s, list):
            return [unhexlify(x) for x in s]


    safe_from_hex = unhexlify = safe_unhexlify
    hexlify = safe_hexlify

    def from_int_repr_to_bytes(a):
        return by(str(a))

    def from_int_to_le_bytes(i, length=1):
        return from_int_to_bytes(i, length, 'little')

    def from_int_to_bytes(v, length=1, byteorder='little'):
        return int.to_bytes(v, length, byteorder)

    def from_int_to_byte(a):
        return bytes([a])

    def from_byte_to_int(a):
        return a

    def from_le_bytes_to_int(bstr):
        return from_bytes_to_int(bstr, byteorder='little', signed=False)

    def from_bytes_to_int(bstr, byteorder='little', signed=False):
        return int.from_bytes(bstr, byteorder=byteorder, signed=signed)

    def from_str_to_bytes(a):
        return by(a)

    def from_bytes_to_str(a):
        return st(a)

    from_string_to_bytes = from_str_to_bytes
    from_bytes_to_string = from_bytes_to_str

    def short_hex(hexstr):
        if len(hexstr) < 11 or not re.match('^[0-9a-fA-F]*$', st(hexstr)):
            return hexstr
        t = by(hexstr)
        return t[0:4]+"..."+t[-4:]

    def encode(val, base, minlen=0):
        base, minlen = int(base), int(minlen)
        code_string = get_code_string(base)
        result_bytes = bytearray()
        while val > 0:
            curcode = code_string[val % base]
            result_bytes.insert(0, ord(curcode))
            val //= base

        pad_size = minlen - len(result_bytes)

        padding_element = b'\x00' if base == 256 else b'1' if base == 58 else b'0'
        if (pad_size > 0):
            result_bytes = bytes(bytearray(padding_element*pad_size) + result_bytes)

        result_string = ''.join([chr(y) for y in result_bytes])
        result = result_bytes if base == 256 else result_string

        return result

    def decode(string, base):
        if base == 256 and isinstance(string, str):
            string = bytes.fromhex(string)
        base = int(base)
        code_string = get_code_string(base)
        if base == 256:
            def extract(d, cs):
                return d
        else:
            def extract(d, cs):
                return cs.find(d if isinstance(d, str) else chr(d))

        if base == 16:
            string = string.lower()
        result = 0
        while len(string) > 0:
            result *= base
            result += extract(string[0], code_string)
            string = string[1:]
        return result

    def random_string(x):
        return str(os.urandom(x))

else:
    raise ImportError("pyspecials import error!")
