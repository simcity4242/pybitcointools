import io, struct, os, sys
from binascii import crc32, unhexlify, hexlify
from bitcoin import *
from bitcoin.pyspecials import safe_hexlify, safe_unhexlify

global OP_CHECKSIG, OP_CHECKMULTISIG, OP_PUSHDATA1, OP_DUP, OP_HASH160, OP_EQUALVERIFY
OP_CHECKSIG =       b'\xac'
OP_CHECKMULTISIG =  b'\xae'
OP_PUSHDATA1 =      b'\x4c'
OP_DUP =            b'\x76'
OP_HASH160 =        b'\xa9'
OP_EQUALVERIFY =    b'\x88'

def mk_multisig_scriptpubkey(fo):
    # takes file_object fo and returns scriptpubkey as hex

    data = fo.read(65*3)
    if not data:
        return None

    script_pubkeys = []
    while data:
        chunk = data[:65]
        data = data[65:]

        # pad right side with null bytes
        if len(chunk) < 33:
            chunk += b'\x00' * (33-len(chunk))
        elif len(chunk) < 65:
            chunk += b'\x00' * (65-len(chunk))
        script_pubkeys.append(chunk)

    pubz = list(map(safe_hexlify, script_pubkeys))
    return mk_multisig_script(pubz, 1)
 
def mk_txouts(fo, value=None, jsonfmt=0):
    """Make Tx Outputs (hex or json)"""
    if value is None:
        value = 547    # DUST
    if value is not None:
        value = int(value)
    txouts = []
    while True:
        scriptPubKey = mk_multisig_scriptpubkey(fo)
        if scriptPubKey is None:
            break
        txouts.append( {'script': scriptPubKey, 'value': value} )
    if jsonfmt:
        return txouts
    return ''.join([(safe_hexlify(struct.pack('<Q', value))+str(x['script'])) for x in txouts])

def file_insert(filename, jsonfmt=0):
    """Encode filename into the blockchain using multisig addresses"""
    try:
        fileobj = open(filename, 'rb').read()
    except:
        raise Exception("can't find file!")

    data = struct.pack('<L', len(fileobj)) + \
           struct.pack('<L', crc32(fileobj)) + fileobj
    fd = io.BytesIO(data)
    TXOUTS = mk_txouts(fd, jsonfmt)
    if jsonfmt:
        return list(TXOUTS)
    VARINT = safe_hexlify(num_to_var_int(len(TXOUTS.split(
              safe_hexlify(struct.pack('<Q', value))))-1))
    return VARINT + TXOUTS + '00000000'
