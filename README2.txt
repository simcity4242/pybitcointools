
txin, vout = '97e48d20ef52d12c1d58a0aa865d12b9db5faa52fbefe597e50448e01ee17c92', 0


ins = ["%s:%d" % (txin, vout)]
>>> ins = ['97e48d20ef52d12c1d58a0aa865d12b9db5faa52fbefe597e50448e01ee17c92:0', '97e48d20ef52d12c1d58a0aa865d12b9db5faa52fbefe597e50448e01ee17c92:1']

to_addr, value = 'n1hjyVvYQPQtejJcANd5ZJM5rmxHCCgWL7', 259000000
outs = ["%s:%d" % (to_addr, value)]
>>> ['n1hjyVvYQPQtejJcANd5ZJM5rmxHCCgWL7:259000000']

rawtx = mktx(ins, outs)		# [in0, in1], [out0, out1]

signedtx = sign(rawtx, 0, tpriv)

sig1 = multisign(rawtx, 0, mk_pubkey_script(taddr), tpriv)
>>> '304402201f42edd36a24a9d144315d833f149615b8878d17c8cd0941ebcd08d57b4aa140022044e014432d0cf8af82067d5086b8a6daffc6c461d49acff7dba4095519db97c701'

verify_tx_input(signedtx, 0, mk_pubkey_script(taddr), sig1, tpub)
>>> True

# check low s, is_bip66
is_bip66(sig1[:-2])
>>> True

v,r,s = der_decode_sig(sig1)
s > N//2
>>> False

