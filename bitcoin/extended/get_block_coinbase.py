def get_block_coinbase(txval):
    j = _get_block(txval)
    cb = bytes(bytearray.fromhex(j['tx'][0]['inputs'][0]['script']))
    pos = [0]

    def read_var_int():
        pos[0] += 1
        val = from_byte_to_int(cb[pos[0] - 1])
        assert val < 0xfd
        return val

    def read_bytes(bytez):
        pos[0] += bytez
        return cb[pos[0]-bytez:pos[0]]

    def read_var_string():
        size = read_var_int()
        return read_bytes(size)

    try:
        CB = []
        while pos < [len(cb)]:
            CB.append(read_var_string())
    except:
        alpha = ''.join(map(chr, list(range(32, 126))))
        ret = ''.join([x for x in cb if x in alpha])