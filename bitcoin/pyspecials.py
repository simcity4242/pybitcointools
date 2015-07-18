import sys
import re
import binascii
import os
import hashlib
import struct

is_python2 = (str == bytes) and (sys.version_info.major == 2)

#   PYTHON 2 FUNCTIONS
#
if is_python2:
    
    python2 = bytes == str
    st = lambda u: str(u)
    by = lambda v: bytes(v)

    string_types = (str, unicode)
    string_or_bytes_types = (str, unicode)
    bytestring_types = bytearray
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

    def bin_dbl_sha256(s):
        bytes_to_hash = from_string_to_bytes(s)
        return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

    def lpad(msg, symbol, length):
        if len(msg) >= length:
            return msg
        return symbol * (length - len(msg)) + msg

    def get_code_string(base):
        if base in code_strings:
            return code_strings[base]
        else:
            raise ValueError("Invalid base!")

    def changebase(string, frm, to, minlen=0):
        if frm == to:
            return lpad(string, get_code_string(frm)[0], minlen)
        return encode(decode(string, frm), to, minlen)

    def bin_to_b58check(inp, magicbyte=0):
        inp_fmtd = chr(int(magicbyte)) + inp
        leadingzbytes = len(re.match('^\x00*', inp_fmtd).group(0))
        checksum = bin_dbl_sha256(inp_fmtd)[:4]
        return '1' * leadingzbytes + changebase(inp_fmtd+checksum, 256, 58)
        
    def safe_hexlify(b):
        return binascii.hexlify(b)

    def safe_unhexlify(s):
        return binascii.unhexlify(s)
        
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
        # return a
        return ord(a)

    def from_le_bytes_to_int(bstr):
        return from_bytes_to_int(bstr, byteorder='little', signed=False)

    def from_bytes_to_int(bstr, byteorder='big', signed=False):
        if byteorder != 'big':
            bstr = reversed(bstr)
        v = 0
        bytes_to_ints = (lambda x: [ord(c) for c in x]) if bytes == str else lambda x: x
        for c in bytes_to_ints(bstr):
            v <<= 8
            v += c
        if signed and bstr[0] & 0x80:
            v = v - (1 << (8*len(bstr)))
        return v

    def from_str_to_bytes(a):
        return by(a)

    def from_bytes_to_str(a):
        return st(a)

    from_bytestring_to_str = from_bytes_to_str
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
#
elif sys.version_info.major == 3:
    #is_python2 = bytes == str

    xrange = range
    string_types = str
    string_or_bytes_types = (str, bytes)
    bytestring_types = (bytes, bytearray)
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
        #128: ''.join([chr(x) for x in range(128)]),
        256: ''.join([chr(x) for x in range(256)])
    }

    def bin_dbl_sha256(s):
        bytes_to_hash = from_string_to_bytes(s)
        return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

    def lpad(msg, symbol, length):
        if len(msg) >= length:
            return msg
        return symbol * (length - len(msg)) + msg

    def get_code_string(base):
        if base in code_strings:
            return code_strings[base]
        else:
            raise ValueError("Invalid base!")

    def changebase(string, frm, to, minlen=0):
        if frm == to:
            return lpad(string, get_code_string(frm)[0], minlen)
        return encode(decode(string, frm), to, minlen)

    def bin_to_b58check(inp, magicbyte=0):
        inp_fmtd = from_int_to_byte(int(magicbyte))+inp
        leadingzbytes = 0
        for x in inp_fmtd:
            if x != 0: break
            leadingzbytes += 1
        checksum = bin_dbl_sha256(inp_fmtd)[:4]
        return '1' * leadingzbytes + changebase(inp_fmtd+checksum, 256, 58)

    def safe_hexlify(a):
        return st(binascii.hexlify(a))

    def safe_unhexlify(b):
        # 'abcde' / b'abcd' => b'\xab\xcd'
        return bytes.fromhex(b) if isinstance(b, str) else binascii.unhexlify(b)

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

    from_bytestring_to_str = from_bytes_to_str
    from_string_to_bytes = from_str_to_bytes
    from_bytes_to_string = from_bytes_to_str

    def short_hex(hexstr):
        if len(hexstr) < 11 or not re.match('^[0-9a-fA-F]*$', hexstr):
            return hexstr
        t = by(hexstr)
        return t[0:4]+"..."+t[-4:]
	
    def encode(val, base, minlen=0):
        base, minlen = int(base), int(minlen)
        code_string = get_code_string(base)
        result_bytes = bytes()
        while val > 0:
            curcode = code_string[val % base]
            result_bytes = bytes([ord(curcode)]) + result_bytes
            val //= base

        pad_size = minlen - len(result_bytes)

        padding_element = b'\x00' if base == 256 else b'1' \
            if base == 58 else b'0'
        if (pad_size > 0):
            result_bytes = padding_element*pad_size + result_bytes

        result_string = ''.join([chr(y) for y in result_bytes])
        result = result_bytes if base == 256 else result_string

        return result

    def decode(string, base):
        if base == 256 and isinstance(string, str):
            string = bytes(bytearray.fromhex(string))
        base = int(base)
        code_string = get_code_string(base)
        result = 0
        if base == 256:
            def extract(d, cs):
                return d
        else:
            def extract(d, cs):
                return cs.find(d if isinstance(d, str) else chr(d))

        if base == 16:
            string = string.lower()
        while len(string) > 0:
            result *= base
            result += extract(string[0], code_string)
            string = string[1:]
        return result

    def random_string(x):
        return str(os.urandom(x))

else:
    raise ImportError("pyspecials import error!")
