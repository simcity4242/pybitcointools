import io, struct, os, sys
from binascii import crc32, unhexlify, hexlify
from bitcoin.main import *
from bitcoin.transaction import mk_multisig_script
from bitcoin.pyspecials import safe_hexlify, safe_unhexlify, st, by

def mk_multisig_scriptpubkey(fo):
    # takes file_object fo and returns scriptpubkey as hex
    data = fo.read(65*3)

    if not data:
        return None
    
    script_pubkeys = []
    while data:
        chunk = data[:65]; data = data[65:]
        # pad right side with null bytes
        if len(chunk) < 33:   chunk += b'\x00' * (33-len(chunk))
        elif len(chunk) < 65: chunk += b'\x00' * (65-len(chunk))
        script_pubkeys.append(chunk)

    pubz = list(map(safe_hexlify, script_pubkeys))
    return mk_multisig_script(pubz, 1)
 
def mk_txouts(fo, value=None, jsonfmt=1):
    """Make Tx Outputs as json (or hex)"""
    value = 547 if not value else int(value)
    txouts = []
    while True:
        scriptPubKey = mk_multisig_scriptpubkey(fo)
        if scriptPubKey is None: break
        txouts.append( {'script': scriptPubKey, 'value': value} )
    if jsonfmt:
        return txouts
    return ''.join([(safe_hexlify(struct.pack('<Q', value)) +
                     str(wrap_script(x['script']))) for x in txouts])

def file_insert(filename, value=None, jsonfmt=1):
    """Encode filename into the blockchain using multisig addresses"""
	# TODO: sum (outsputs*547) + (10000*kBytes)
    try:
        fileobj = open(filename, 'rb').read()
    except:
        raise Exception("can't find file!")

    data = struct.pack('<L', len(fileobj)) + \
           struct.pack('<L', crc32(fileobj)) + fileobj
    fd = io.BytesIO(data)
    TXOUTS = mk_txouts(fd, value, jsonfmt)
    if jsonfmt:
        return list(TXOUTS)
    #safe_hexlify(num_to_var_int(len(TXOUTS.split(safe_hexlify(struct.pack('<Q', value))))-1))
    return wrap_varint(TXOUTS)
