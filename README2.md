1JCAugEs1ETUKRXMBpxeCPERS6xPymP3ZM 14zWNsgUMmHhYx4suzc2tZD6HieGbkQi5s 14MDR5y8nHpqN7VtCKoDMMyfbeAD1HP9EW 1E8JPJRav51yGrCYXKtCQr4k9o93MvprdQ

**BIP32**

`bip32_master_key` takes entropy seed as hex or mnemonic

*mnemonic to master key*
`bip32_master_key("unique page trust liar alarm vehicle swap time all cloud say later")`


**BIP39**

`bip39_check(mnemonic)`
`bip39_to_entropy(mnemonic)`
`bip39_to_mn(entropy)`
`bip39_to_seed(mnemonic)`


`hdmn = "unique page trust liar alarm vehicle swap time all cloud say later"`

*check mnemonic is bip39*
`bip39_check(hdmn)    # True`

*retrieve entropy seed*
`bip39_to_entropy(hdmn)    # ed93dfa6c0605de3f6d71206657effbe`

*round trip...*
`bip39_to_mn(bip39_to_entropy(hdmn))`

**bip44**




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
