from bitcoin.main import *
from bitcoin.pyspecials import by, st, hexify, unhexify

# test.webbtc.com/block/00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee.json
# http://webbtc.com/block/00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee.json
# http://webbtc.com/block/00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee.bin

def serialize_header(inp):
    o = encode(inp['version'], 256, 4)[::-1] + \
        unhexify(inp['prevhash'])[::-1] + \
        unhexify(inp['merkle_root'])[::-1] + \
        encode(inp['timestamp'], 256, 4)[::-1] + \
        encode(inp['bits'], 256, 4)[::-1] + \
        encode(inp['nonce'], 256, 4)[::-1]
    h = hexify(bin_sha256(bin_sha256(o))[::-1])
    assert h == inp['hash'], (sha256(o), inp['hash'])
    return hexify(o)


def deserialize_header(inp):
    inp = unhexify(inp)
    return {
        "version": decode(inp[:4][::-1], 256),
        "prevhash": hexify(inp[4:36][::-1]),
        "merkle_root": hexify(inp[36:68][::-1]),
        "timestamp": decode(inp[68:72][::-1], 256),
        "bits": decode(inp[72:76][::-1], 256),
        "nonce": decode(inp[76:80][::-1], 256),
        "hash": hexify(bin_sha256(bin_sha256(inp))[::-1])
    }


def mk_merkle_proof(header, hashes, index):
    nodes = [unhexify(h)[::-1] for h in hashes]
    if len(nodes) % 2 and len(nodes) > 2:
        nodes.append(nodes[-1])
    layers = [nodes]
    while len(nodes) > 1:
        newnodes = []
        for i in range(0, len(nodes) - 1, 2):
            newnodes.append(bin_sha256(bin_sha256(nodes[i] + nodes[i+1])))
        if len(newnodes) % 2 and len(newnodes) > 2:
            newnodes.append(newnodes[-1])
        nodes = newnodes
        layers.append(nodes)
    # Sanity check, make sure merkle root is valid
    assert hexify(nodes[0][::-1]) == header['merkle_root']
    merkle_siblings = \
        [layers[i][(index >> i) ^ 1] for i in range(len(layers)-1)]
    return {
        "hash": hashes[index],
        "siblings": [hexify(x[::-1]) for x in merkle_siblings],
        "header": header
    }
