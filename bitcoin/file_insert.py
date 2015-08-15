import io, struct, os, sys, math
from binascii import crc32, unhexlify, hexlify
from bitcoin.main import *
from bitcoin.bci import *
from bitcoin.transaction import *
#from bitcoin.pyspecials import hexify, unhexify, by


def _mk_multisig_scriptpubkey(fo):
    # make a single output's redeemScript
    data = fo.read(65*3)

    if not data:
        return None

    script_pubkeys = []
    while data:
        chunk = data[:65]
        data = data[65:]
        # pad right side with null bytes

        if len(chunk) < 33:   
            chunk += by(bytearray(33-len(chunk)))
        elif len(chunk) < 65: 
            chunk += by(bytearray(65-len(chunk)))
        script_pubkeys.append(chunk)

    pubz = list(map(hexify, script_pubkeys))
    return mk_multisig_script(pubz, 1)

def _mk_txouts(fo, value=None):
    value = 547 if not value else int(value)
    hexval = hexify(struct.pack('<Q', value))	# make 8 byte LE value
    txouts = []
    while True:
        scriptPubKey = _mk_multisig_scriptpubkey(fo)
        if scriptPubKey is None: break
        txouts.append( {'script': scriptPubKey, 'value': value} )
    return txouts
    #return ''.join([(hexval + str(wrap_script(x['script']))) for x in txouts])

#Encode file into the blockchain (with prepended file length, crc32) using multisig addresses
def _mk_binary_txouts(filename, value=None):
    try: fileobj = open(filename, 'rb').read()
    except: raise Exception("can't find file!")

    data = struct.pack('<I', len(fileobj)) + \
           struct.pack('<I', crc32(fileobj) & 0xffffffff) + fileobj
    fd = io.BytesIO(data)
    TXOUTS = _mk_txouts(fd, value)
    return list(TXOUTS)
    #return wrap_varint(TXOUTS)

def encode_file(filename, privkey, *args):
    """"""
    #filename, privkey, value, change_address, network, signtx
    if len(args) == 0:
        value, input_address, network, signtx = None, None, None, False
    elif len(args) == 3:
        value, input_address, network = args
        signtx = False
    elif len(args) == 4:
        value, input_address, network, signtx = args
    else:
        raise SyntaxError("params = filename, privkey, value, change_address, network, signtx")

    if not network:
        network = 'testnet'

    if input_address is None:
        input_address = privtoaddr(privkey, 111) if network == 'testnet' else privtoaddr(privkey)

    u = unspent(input_address, 'testnet', source='blockr') if network == 'testnet' else unspent(input_address)
    value = 547 if value is None else int(value)

    TXFEE = int(math.ceil(1.1 * (10000*os.path.getsize(filename)/1000)))
    OUTS = _mk_binary_txouts(filename, value)
    TOTALFEE = TXFEE + int(value)*len(OUTS)
    INS = select(u, TOTALFEE)

    rawtx = mksend(INS, OUTS, input_address, TXFEE)
    if signtx:
        signedtx = sign(rawtx, 0, privkey, 1)
        return signedtx
    return rawtx


def decode_file(txid, network='btc'):
    """Returns decoded blockchain binary file as bytes, ready to write to a file"""
    # TODO: multiple TxIDs? verify encode_file output? 
    assert network in ('btc', 'testnet')
    
    txh = fetchtx(txid, network, source='blockr')
    txo = deserialize(txh)
    outs1 = map(deserialize_script, multiaccess(txo['outs'], 'script'))
    
    # get hex key data from multisig scripts
    outs2 = filter(lambda l: l[-1] == 174, outs1)	# TODO: check for _non-p2sh_ outputs
    outs3 = map(lambda l: l[1:-2], outs2)

    data = unhexify(''.join([item for sublist in outs3 for item in sublist]))	# base 256 of encoded data
    
    # TODO: are length & crc32 prepended?
    length = struct.unpack('<I', data[0:4])[0]		# TODO: check length == len(data)
    checksum = struct.unpack('<I', data[4:8])[0]
	
    data = data[8:8+length]
    
    assert checksum == crc32(data) & 0xffffffff	 
    return data # TODO: write return to file object?

# def decode_files(txids, network='btc'):
#     if isinstance(txids, string_types):
#         return decode_file(txids, network)
#     elif isinstance(txids, list) and len(txids) == 1:
#         return decode_file(txids[0], network)
#     return ''.join([decode_file(x) for x in txids])
