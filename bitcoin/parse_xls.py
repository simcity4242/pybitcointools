from bitcoin import *

def parse_cell(input_script):
    scr_arr = deserialize_script(input_script)
    ders = [x for x in scr_arr if is_der(str(x))]
    return ders[0] if len(ders) == 1 else ders
    # if len(ders) == 1:
    #     return deserialize_der(ders[0])[-1]
    # else:
    #     sighashes = [deserialize_der(x)[-1] for x in ders]
    #     return sighashes

def deserialize_der(sig):
    sig = safe_unhexlify(sig)
    totallen = decode(sig[1], 256) + 2
    rlen = decode(sig[3], 256)
    slen = decode(sig[5 + rlen], 256)
    sighashlen = len(sig) - totallen
    r = changebase(sig[4:4 + rlen], 256, 16, rlen * 2)
    s = changebase(sig[6 + rlen:6 + slen + rlen], 256, 16, slen * 2)
    sighash = changebase(sig[6 + rlen + slen:], 256, 16, sighashlen * 2)
    return [r, s, sighash]

def is_der(sig):
    if sig[:2] == '30':
        return True
    else:
        n = 0
        while True:
            try:
                thirty_index = sig.index('30', n)
                twenty_index = sig.index('20', n)
                if twenty_index - thirty_index == 5:
                    break
                n += 1
            except:
                return False
    return False