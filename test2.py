import json
import os
import random
import unittest
import pdb

from bitcoin.ripemd import *
from bitcoin import *
from bitcoin.transaction import serialize_script

#from bitcoin.pyspecials import *
#from bitcoin.transaction import *
#from bitcoin.mnemonic import *
#from bitcoin.deterministic import *
#from bitcoin.utils import *

OPS = {'OP_0': 0,
 'OP_0NOTEQUAL': 146,
 'OP_1': 81,
 'OP_10': 90,
 'OP_11': 91,
 'OP_12': 92,
 'OP_13': 93,
 'OP_14': 94,
 'OP_15': 95,
 'OP_16': 96,
 'OP_1ADD': 139,
 'OP_1NEGATE': 79,
 'OP_1SUB': 140,
 'OP_2': 82,
 'OP_2DIV': 142,
 'OP_2DROP': 109,
 'OP_2DUP': 110,
 'OP_2MUL': 141,
 'OP_2OVER': 112,
 'OP_2ROT': 113,
 'OP_2SWAP': 114,
 'OP_3': 83,
 'OP_3DUP': 111,
 'OP_4': 84,
 'OP_5': 85,
 'OP_6': 86,
 'OP_7': 87,
 'OP_8': 88,
 'OP_9': 89,
 'OP_ABS': 144,
 'OP_ADD': 147,
 'OP_AND': 132,
 'OP_BOOLAND': 154,
 'OP_BOOLOR': 155,
 'OP_CAT': 126,
 'OP_CHECKLOCKTIMEVERIFY': 177,
 'OP_CHECKMULTISIG': 174,
 'OP_CHECKMULTISIGVERIFY': 175,
 'OP_CHECKSIG': 172,
 'OP_CHECKSIGVERIFY': 173,
 'OP_CODESEPARATOR': 171,
 'OP_DEPTH': 116,
 'OP_DIV': 150,
 'OP_DROP': 117,
 'OP_DUP': 118,
 'OP_ELSE': 103,
 'OP_ENDIF': 104,
 'OP_EQUAL': 135,
 'OP_EQUALVERIFY': 136,
 'OP_FALSE': 0,
 'OP_FROMALTSTACK': 108,
 'OP_GREATERTHAN': 160,
 'OP_GREATERTHANOREQUAL': 162,
 'OP_HASH160': 169,
 'OP_HASH256': 170,
 'OP_IF': 99,
 'OP_IFDUP': 115,
 'OP_INVALIDOPCODE': 255,
 'OP_INVERT': 131,
 'OP_LEFT': 128,
 'OP_LESSTHAN': 159,
 'OP_LESSTHANOREQUAL': 161,
 'OP_LSHIFT': 152,
 'OP_MAX': 164,
 'OP_MIN': 163,
 'OP_MOD': 151,
 'OP_MUL': 149,
 'OP_NEGATE': 143,
 'OP_NIP': 119,
 'OP_NOP': 97,
 'OP_NOP1': 176,
 'OP_NOP10': 185,
 'OP_NOP2': 177,
 'OP_NOP3': 178,
 'OP_NOP4': 179,
 'OP_NOP5': 180,
 'OP_NOP6': 181,
 'OP_NOP7': 182,
 'OP_NOP8': 183,
 'OP_NOP9': 184,
 'OP_NOT': 145,
 'OP_NOTIF': 100,
 'OP_NUMEQUAL': 156,
 'OP_NUMEQUALVERIFY': 157,
 'OP_NUMNOTEQUAL': 158,
 'OP_OR': 133,
 'OP_OVER': 120,
 'OP_PICK': 121,
 'OP_PUBKEY': 254,
 'OP_PUBKEYHASH': 253,
 'OP_PUSHDATA1': 76,
 'OP_PUSHDATA2': 77,
 'OP_PUSHDATA4': 78,
 'OP_RESERVED': 80,
 'OP_RESERVED1': 137,
 'OP_RESERVED2': 138,
 'OP_RETURN': 106,
 'OP_RIGHT': 129,
 'OP_RIPEMD160': 166,
 'OP_ROLL': 122,
 'OP_ROT': 123,
 'OP_RSHIFT': 153,
 'OP_SHA1': 167,
 'OP_SHA256': 168,
 'OP_SIZE': 130,
 'OP_SUB': 148,
 'OP_SUBSTR': 127,
 'OP_SWAP': 124,
 'OP_TOALTSTACK': 107,
 'OP_TRUE': 81,
 'OP_TUCK': 125,
 'OP_VER': 98,
 'OP_VERIF': 101,
 'OP_VERIFY': 105,
 'OP_VERNOTIF': 102,
 'OP_WITHIN': 165,
 'OP_XOR': 134
       }

OPCODES_BY_NAME = dict([(k, v) for k, v in OPS.items()])
OPCODES_BY_NAME.update(dict([(k[3:], v) for k, v in OPS.items()]))
OPint = dict([(v,k) for k,v in OPS.items()])

if len(OPCODES_BY_NAME) == 234:
    print("OPCODES loaded")
    raw_input("???")


def get_op(s):
    """Returns OP_CODE for integer, or integer for OP_CODE"""
    getop = lambda o: OPCODES_BY_NAME.get(o.upper() if not o.startswith("OP_") else str(o[2:]).upper(), 0)
    if isinstance(s, int):
        return OPint.get(s, "")
    elif isinstance(s, string_types):
        return getop(s)
		
	
def parse_script(s):
    def ishex(s):
        return set(s).issubset(set('0123456789abcdefABCDEF'))

    r = []

    opcodes_by_name = {}
    for name, code in OPCODES_BY_NAME.items():
        opcodes_by_name[name] = code
        opcodes_by_name[name[3:]] = code

    for word in s.split():
        if word.isdigit() or (word[0] == '-' and word[1:].isdigit()):
            r.append(int(word))
        elif word.startswith('0x') and ishex(word[2:]):
            if int(word[2:], 16) <= 0x4e:
                continue
            else:
                r.append(word[2:])
        elif len(word) >= 2 and word[0] == "'" and word[-1] == "'":
            r.append(word[1:-1])
        elif word in opcodes_by_name:
            r.append(opcodes_by_name[word])  # r.append(get_op(v[3:]))
        else:
            raise ValueError("could not parse script! (word=\t%s)" % str(word))

    try:
        sc = serialize_script(r)
    except:
        sys.stderr.write("Didnt work!\nr = %s" % repr(r))	# 7,12,13,24 don't work
    return sc


def load_txs():
    with open('tests/tx_valid.json', 'r') as fo:
        for tv in json.load(fo):
            if len(tv) == 1: continue
            assert len(tv) == 3

            tx = str(tv[1])
            yield tx

def load_txvalid():
    with open('tests/tx_valid.json', 'r') as fo:
        for tv in json.load(fo):
            if len(tv) == 1: continue
            assert len(tv) == 3

            prevouts = {}
            for json_prevout in tv[0]:
                assert len(json_prevout) == 3
                n = 0xffffffff if json_prevout[1] == -1 else json_prevout[1]
                prevout = "%s:%d" % (json_prevout[0], n)
                try:
                    prevouts[prevout] = parse_script(json_prevout[2])
                except Exception as e:
                    sys.stderr.write(str(e))
                    prevouts['ERRORS'] = json_prevout[2]

                tx = str(tv[1])
                flags = tv[2]

                yield (prevouts, tx, flags)

class BitcoinCore_TransactionValid(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("Testing BitcoinCore Transactions (Valid)")

    def test_all(self):

        for i, tx in enumerate(load_txs()):
            print("Checking Tx (Valid) Test Vector #%d" % i)
            self.assertTrue(check_transaction(tx),
                            "Check Tx Failed:\nIndex: %d\nTx hex: %s" % (i, str(tx)))

        for i, (prevs, txhex, flags) in enumerate(load_txvalid()):
            print("Checking Tx (Valid) Test Vector #%d" % i)
            self.assertTrue(check_transaction(tx),
                            "Check Tx Failed:\nIndex: %d\nTx hex: %s" % (i, str(tx)))

            # [[[prevout_txid, prevout_vout, prevout_spk], ... ], serialized_tx]


        tx_valid_test_vectors = [

            [[["60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1", 0, "514104cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4410461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af52ae"]], "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba26000000000490047304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000"],

            [[["406b2b06bcd34d3c8733e6b79f7a394c8a431fbf4ff5ac705c93f4076bb77602", 0, "76a914dc44b1164188067c3a32d4780f5996fa14a4f2d988ac"]], "01000000010276b76b07f4935c70acf54fbf1f438a4c397a9fb7e633873c4dd3bc062b6b40000000008c493046022100d23459d03ed7e9511a47d13292d3430a04627de6235b6e51a40f9cd386f2abe3022100e7d25b080f0bb8d8d5f878bba7d54ad2fda650ea8d158a33ee3cbd11768191fd004104b0e2c879e4daf7b9ab68350228c159766676a14f5815084ba166432aab46198d4cca98fa3e9981d0a90b2effc514b76279476550ba3663fdcaff94c38420e9d5000000000100093d00000000001976a9149a7b0f3b80c6baaeedce0a0842553800f832ba1f88ac00000000"],

            [[["0000000000000000000000000000000000000000000000000000000000000100", 0,  "76a9145b6462475454710f3c22f5fdf0b40704c92f25c388ad51"]], "01000000010001000000000000000000000000000000000000000000000000000000000000000000006a473044022067288ea50aa799543a536ff9306f8e1cba05b9c6b10951175b924f96732555ed022026d7b5265f38d21541519e4a1e55044d5b9e17e15cdbaf29ae3792e99e883e7a012103ba8c8b86dea131c22ab967e6dd99bdae8eff7a1f75a2c35f1f944109e3fe5e22ffffffff010000000000000000015100000000"],

            [[["b464e85df2a238416f8bdae11d120add610380ea07f4ef19c5f9dfd472f96c3d", 0, "76a914bef80ecf3a44500fda1bc92176e442891662aed288ac"], ["b7978cc96e59a8b13e0865d3f95657561a7f725be952438637475920bac9eb21", 1, "76a914bef80ecf3a44500fda1bc92176e442891662aed288ac"]], "01000000023d6cf972d4dff9c519eff407ea800361dd0a121de1da8b6f4138a2f25de864b4000000008a4730440220ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e022049cffa1cdc102a0b56e0e04913606c70af702a1149dc3b305ab9439288fee090014104266abb36d66eb4218a6dd31f09bb92cf3cfa803c7ea72c1fc80a50f919273e613f895b855fb7465ccbc8919ad1bd4a306c783f22cd3227327694c4fa4c1c439affffffff21ebc9ba20594737864352e95b727f1a565756f9d365083eb1a8596ec98c97b7010000008a4730440220503ff10e9f1e0de731407a4a245531c9ff17676eda461f8ceeb8c06049fa2c810220c008ac34694510298fa60b3f000df01caa244f165b727d4896eb84f81e46bcc4014104266abb36d66eb4218a6dd31f09bb92cf3cfa803c7ea72c1fc80a50f919273e613f895b855fb7465ccbc8919ad1bd4a306c783f22cd3227327694c4fa4c1c439affffffff01f0da5200000000001976a914857ccd42dded6df32949d4646dfa10a92458cfaa88ac00000000"]

        ]
        # TODO: lose the tx_valid_test_vectors ??
        for item in tx_valid_test_vectors:
            prevouts = item[0]
            txh = item[1]
            for i, prevout_item in enumerate(prevouts):
                prevout_txin, prevout_vout, prevout_spk = prevout_item
                calculated = get_outpoints(txh, i)
                actual = "%s:%d" % (prevout_txin, prevout_vout)
                self.assertEqual(actual, calculated, "get_outpoint at index %d failed" % int(i))
                #assert actual == calculated

                final_scriptsig = deserialize_script(deserialize(txh)['ins'][i]['script'])

                txtype = None
                if all([x in deserialize_script(prevout_spk) for x in [118, 169, 136]]):
                    txtype = 'p2pkh'
                elif 0xae in deserialize_script(prevout_spk):
                    txtype = 'p2sh'

                if txtype == 'p2pkh':
                    der, pub = final_scriptsig
                    #assert verify_tx_input(txh, int(i), prevout_spk, der, pub)
                    self.assertTrue(
                        verify_tx_input(txh, int(i), prevout_spk, *final_scriptsig),
                        "Tx Verif'n Failed:\nRawTx %s\nTxID In %s:%s\n"
                        "ScriptPubKey %s\nSigning Index %s\nDER %s\nPub(s) %s" % (
                            txh, prevout_txin, str(prevout_vout),
                            prevout_spk, str(i), final_scriptsig[0], final_scriptsig[1])
                    )
                elif txtype == 'p2sh':
                    der = final_scriptsig[1]
                    pubs = [x for x in deserialize_script(prevout_spk) if is_pubkey(x)]
                    #assert any([verify_tx_input(txh, int(i), prevout_spk, der, x) for x in pubs])
                    self.assertTrue(
                        any([verify_tx_input(txh, int(i), prevout_spk, der, x) for x in pubs]),
                        "Tx Verif'n Failed:\nRawTx %s\nTxID In %s\n"
                        "Index %s\nScriptPubKey %s\nDER %s\nPub(s) %s" % (
                            txh, prevout_txin, str(prevout_vout), prevout_spk, der, repr(pubs)
                        )
                    )
                else:
                    raise Exception("Unknown Tx Type")

if __name__ == '__main__':
    unittest.main()