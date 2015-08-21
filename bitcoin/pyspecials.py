import sys
import re
import binascii
import os
import hashlib
import struct


is_python2 = (str == bytes) or sys.version_info.major == 2
is_ios = "Pythonista" in os.environ.get("XPC_SERVICE_NAME", "")		# for Pythonista iOS

# PYTHON 2 FUNCTIONS
if is_python2:
    
    python2 = bytes == str
    st = lambda u: str(u)
    by = lambda v: bytes(v)

    string_types = basestring
    string_or_bytes_types = (str, unicode)
    int_types = (int, float, long)

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
        
    def hexify(b):
        if isinstance(b, string_types):
            return binascii.hexlify(b)
        elif isinstance(b, dict):
            return json_hexlify(b)
        elif isinstance(b, int_types) or b is None:
            return b
        elif isinstance(b, list):
            return [hexify(x) for x in b]

    def unhexify(s):
        if isinstance(s, string_or_bytes_types):
            return binascii.unhexlify(s)
        elif isinstance(s, dict):
            return json_unhexlify(s)
        elif isinstance(s, int_types) or s is None:
            return s
        elif isinstance(s, list):
            return [unhexify(x) for x in s]

    safe_unhexlify = unhex_it = unhexify
    safe_hexlify   = hex_it   = hexify

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
elif sys.version_info.major == 3:

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

    def hexify(b):
        if isinstance(b, string_or_bytes_types):
            return st(binascii.hexlify(b))
        elif isinstance(b, dict):
            return json_hexlify(b)
        elif isinstance(b, int_types) or (b is None):
            return b
        elif isinstance(b, list):
            return [hexify(x) for x in b]

    def unhexify(s):
        if isinstance(s, string_or_bytes_types):
            return binascii.unhexlify(s)
        elif isinstance(s, dict):
            return json_unhexlify(s)
        elif isinstance(s, int_types) or (s is None):
            return s
        elif isinstance(s, list):
            return [unhexify(x) for x in s]

    safe_unhexlify = unhex_it = unhexify
    safe_hexlify   = hex_it   = hexify

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
