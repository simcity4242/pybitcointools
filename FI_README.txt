FILE_INSERT encodes a binary file as multisig (1 of n) outputs.

For example, https://blockchain.info/tx/54e48e5f5c656b26c3bca14a8c95aa583d07ebe84dde3b7dd4a78f4e4186e713 encodes the whitepaper in 946x 1-of-3 outputs. Further discussion can be found at http://bitcoin.stackexchange.com/a/35970.

1. download the zip
2. Unzip to /pybitcointools
3. In (i)Python 2.7, run: 
   PTH = "c:/DIRNAME/pybitcointools-master"
   exec("""import os;os.chdir(PTH);from bitcoin import *""")
4. Copy bitcoin.pdf to PTH
5. run:
   OUTS = file_insert("bitcoin.pdf", 547)    # where 547 is dust threshold in Satoshis 
   INS = select( unspent(ADDR), 547*len(OUTS["outs"]) + \
                  10000*os.path.getsize("bitcoin.pdf")/1000 )     # where ADDR is an unspent address. 
                # ideally select just one input to cover the fee of 547*outputs + 10000*kB 
   If you need a change output:   OUTS.append({"script": mk_pubkeyhash_script(change_address, "value": 12345678})
6. Run 
   rawtx = mktx(INS, OUTS)     # compose unsigned hex Tx 
7. Run 
   signedTx = sign(rawtx, privkey_as_hex, 0)   # where privkey_as_hex is 32 byte hex string, 0 is input to sign
8. Run
   eligius_pushtx(signedTx) or blockr_pushtx(signedTx, "testnet")

* Steps 6-8 can freeze for big Txs like the whitepaper Tx. Stay tuned for a workaround
* "Standard transaction" limitations are lifted on testnet. 
* Use TESTNET for Blockchain-bloating Txs like these!
* Use TESTNET for Blockchain-bloating Txs like these!
