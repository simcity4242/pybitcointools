import io, struct, os, sys, math
from binascii import crc32, unhexlify, hexlify
from bitcoin.main import *
from bitcoin.bci import unspent, blockr_unspent, blockr_pushtx, blockr_fetchtx, eligius_pushtx, helloblock_unspent, bci_unspent
from bitcoin.transaction import mk_multisig_script, select, multiaccess, access, sum, mktx, mksend, mk_pubkey_script, sign, multisign
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

def mk_binary_txouts(filename, value=None, jsonfmt=1):
    """Encode file into the blockchain (with prepended file length, crc32) using multisig addresses"""
    try: fileobj = open(filename, 'rb').read()
    except: raise Exception("can't find file!")

    data = struct.pack('<I', len(fileobj)) + \
           struct.pack('<I', crc32(fileobj) & 0xffffffff) + fileobj
    fd = io.BytesIO(data)
    TXOUTS = mk_txouts(fd, value, jsonfmt)
    if jsonfmt:
        return list(TXOUTS)
    return wrap_varint(TXOUTS)

def encode_file(filename, privkey, value=None, input_address=None, network=None):
    """Takes binary file, returns signed Tx"""
    if not network:
        network = 'testnet'

    if input_address is None:
        input_address = privtoaddr(privkey, 111) if network == 'testnet' else privtoaddr(privkey)

    u = blockr_unspent(input_address, 'testnet') if network == 'testnet' else unspent(input_address)
    value = 547 if value is None else int(value)

    TXFEE = math.ceil(1.1 * (10000*os.path.getsize(filename)/1000))
    OUTS = mk_binary_txouts(filename, value)
    TOTALFEE = TXFEE + int(value)*len(OUTS)
    INS = select(u, TOTALFEE)

    rawtx = mksend(INS, OUTS, input_address, TXFEE)
    signedtx = sign(rawtx, 0, privkey, 1)
    return signedtx


def decode_file(txid, network='testnet'):
    # TODO: check for 
    rawtx = blockr_fetchtx(txid, network)
    txo = deserialize(rawtx)
    outs1 = map(deserialize_script, multiaccess(txo['outs'], 'script'))
    
    # get hex key data from multisig scripts
    # TODO: need to check for non-p2sh outputs
    outs2 = map(lambda l: l[1:int(l.index(174))-1], map(deserialize_script, multiaccess(txo['outs'], 'script')))

    bdata = safe_unhexlify("".join(outs2))	# base 256 of encoded data
    
    # TODO: need to check if the length and crc32 are appended
    length = struct.unpack('<I', bdata[0:4])[0]		# TODO: need to check length matches len(txo['outs'])
    checksum = struct.unpack('<L', bdata[4:8])[0]
    data = bdata[8:8+length]
	
    assert checksum == crc32(data) & 0xffffffff	 

    # TODO: write return to file object
    return safe_hexlify(data)
	
# if __name__ == '__main__':
#     import sys, os
#     if len(sys.argv) < 2: 
#         print("mk_binary_txouts.py FILENAME OUTPUT_VALUE [INPUT_ADDRESS]")
#     elif len(sys.argv) == 3:
#         filename = sys.argv[-1]     # TODO: check file exists
#     elif len(sys.argv) == 4:
