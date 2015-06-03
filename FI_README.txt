FILE_INSERT encodes a binary file as multisig (1 of n) outputs.

For example, https://blockchain.info/tx/54e48e5f5c656b26c3bca14a8c95aa583d07ebe84dde3b7dd4a78f4e4186e713 encodes the whitepaper in 946x 1-of-3 outputs. Further discussion can be found at http://bitcoin.stackexchange.com/a/35970.

1. download/unzip the zip @ https://github.com/simcity4242/pybitcointools/archive/master.zip
2. Download Python 2.7 (Python 3.4 ISN'T SUPPORTED YET) & use pip to install iPython (pip install ipython)
3. Run: 
   PTH = "c:/DIRNAME/pybitcointools-master"
   exec("""import os;os.chdir(PTH);from bitcoin import *""")
4. Copy bitcoin.pdf to PTH (pybitcointools unzip dir)
5. First inputs:
   INS = select( unspent(ADDR), 547*len(OUTS) + \
                  int(1.1 * (10000*os.path.getsize("bitcoin.pdf")/1000)) )   # where ADDR is an unspent address. 
   Now outputs:
   OUTS = file_insert('bitcoin.pdf', 547)     # 547 Satoshis = dust threshold
!) If you need a change output run: 
   OUTS.append(  {"script": mk_pubkeyhash_script(change_address, "value": 12345678}  )
6. ...make the hex tx structure: 
   rawtx = mktx(INS, OUTS)     # compose unsigned hex Tx 
7. Now sign it (using hex/SEC format, NOT WIF! Again, DO NOT use WIF here) 
   signedTx = sign(rawtx, privkey_as_hex, 0)   # where privkey_as_hex is 32 byte hex string, 0 is input num to sign
8. Finally, push the signed Tx to Eligius (mainnet) or blockr (both testnet & mainnet)
   eligius_pushtx(signedTx)
   # _OR_
   blockr_pushtx(signedTx, "testnet") 

* Steps 6-8 can freeze for big Txs like the whitepaper Tx. Stay tuned for a workaround
* "Standard transaction" limitations are lifted on testnet. 
* Use TESTNET for Blockchain-bloating Txs like these!
* Use TESTNET for Blockchain-bloating Txs like these!
