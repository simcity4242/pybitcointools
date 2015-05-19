import sys
import re
import binascii
import os
import hashlib

is_python2 = str == bytes

#   PYTHON 2 FUNCTIONS
#
if sys.version_info.major == 2:
    
    python2 = bytes == str
    st = lambda u: str(u) if is_python2 else str(u, 'utf-8')
    by = lambda v: bytes(v) if is_python2 else bytes(v, 'utf-8')

    string_types = (str, unicode) if is_python2 else (str)
    string_or_bytes_types = string_types if is_python2 else (str, bytes)
    bytestring_types = bytearray if is_python2 else (bytes, bytearray)
    int_types = (int, float, long) if is_python2 else (int, float)

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
        inp_fmtd = chr(int(magicbyte)) + inp
        leadingzbytes = len(re.match('^\x00*', inp_fmtd).group(0))
        checksum = bin_dbl_sha256(inp_fmtd)[:4]
        return '1' * leadingzbytes + changebase(inp_fmtd+checksum, 256, 58)
        
    def bytes_to_hex_string(b):
        return b.encode('hex')

    def safe_from_hex(s):
        return s.decode('hex')

    safe_unhexlify = safe_from_hex
        
    def from_int_representation_to_bytes(a):
        return str(a)

    def from_int_to_le_bytes(i, length=1):
        import struct
        lx = lambda x, v: struct.pack("<"+x, int(v))
        if length == 1:
            return lx('B', i)
        elif length == 2:
            return lx('H', i)
        elif length == 4:
            return lx('I', i)
        elif length == 8:
            return lx('L', i)
        else: raise Exception("bad length or int value")

    def from_int_to_byte(a):
        # return bytes([a])
        return chr(a)

    def from_byte_to_int(a):
        # return a
        return ord(a)

    def from_le_bytes_to_int(bstr):
        import struct
        lx = lambda x, v: struct.unpack('<'+x, bstr)
        blen = len(bstr)
        if blen == 1: return lx('B', bstr)
        elif blen == 2: return lx('H', bstr)
        elif blen == 4: return lx('I', bstr)
        elif blen == 8: return lx('L', bstr)
        else: raise Exception("Bad byte-string input")

    def from_string_to_bytes(a):
        return a

    def from_bytestring_to_string(a):
        return st(a)

    from_bytes_to_string = from_bytestring_to_string
        
    def safe_hexlify(a):
        return binascii.hexlify(a)

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
    is_python2 = bytes == str

    st = lambda u: str(u) if is_python2 else str(u, 'utf-8')
    by = lambda v: bytes(v) if is_python2 else bytes(v, 'utf-8')

    string_types = (str, unicode) if is_python2 else (str)
    string_or_bytes_types = string_types if is_python2 else (str, bytes)
    bytestring_types = bytearray if is_python2 else (bytes, bytearray)
    int_types = (int, float, long) if is_python2 else (int, float)

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

    def bytes_to_hex_string(b):
        if isinstance(b, str):
            return b
        return ''.join('{:02x}'.format(y) for y in b)

    def safe_from_hex(b):
        return bytes.fromhex(b)

    safe_unhexlify = safe_from_hex

    def from_int_representation_to_bytes(a):
        return by(str(a))

    def from_int_to_le_bytes(i, length=1):
        if length == 1:
            return from_int_to_byte(i)
        return int.to_bytes(i, length=length, 'little')

    def from_int_to_byte(a):
        return bytes([a])

    def from_byte_to_int(a):
        return a

    def from_le_bytes_to_int(bstr):
        return int.from_bytes(bstr, 'little')

    def from_string_to_bytes(a):
        return a if isinstance(a, bytes) else by(a)

    def from_bytestring_to_string(a):
        return a if isinstance(a, string_types) else st(a)

    from_bytes_to_string = from_bytestring_to_string

    def safe_hexlify(a):
        return st(binascii.hexlify(a))

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
    from btc.py2specials import *
    from btc.py3specials import *
