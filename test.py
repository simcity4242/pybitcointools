import json
import os
import random
import unittest
import string

import bitcoin.ripemd as ripemd
from bitcoin import *


class TestECCArithmetic(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print('Starting ECC arithmetic tests')

    def test_all(self):
        for i in range(8):
            print('### Round %d' % (i+1))
            x, y = random.randrange(2**256), random.randrange(2**256)
            self.assertEqual(
                multiply(multiply(G, x), y)[0],
                multiply(multiply(G, y), x)[0]
            )
            self.assertEqual(

                add_pubkeys(multiply(G, x), multiply(G, y))[0],
                multiply(G, add_privkeys(x, y))[0]
            )

            hx, hy = encode(x % N, 16, 64), encode(y % N, 16, 64)
            self.assertEqual(
                multiply(multiply(G, hx), hy)[0],
                multiply(multiply(G, hy), hx)[0]
            )
            self.assertEqual(
                add_pubkeys(multiply(G, hx), multiply(G, hy))[0],
                multiply(G, add_privkeys(hx, hy))[0]
            )
            self.assertEqual(
                b58check_to_hex(pubtoaddr(privtopub(x))),
                b58check_to_hex(pubtoaddr(multiply(G, hx), 23))
            )

            p = privtopub(sha256(str(x)))
            if i % 2 == 1:
                p = changebase(p, 16, 256)
            self.assertEqual(p, decompress(compress(p)))
            self.assertEqual(G[0], multiply(divide(G, x), x)[0])


class TestBases(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print('Starting base change tests')

    def test_all(self):
        data = [
            [10, '65535', 16, 'ffff'],
            [16, 'deadbeef', 10, '3735928559'],
            [10, '0', 16, ''],
            [256, b'34567', 10, '219919234615'],
            [10, '444', 16, '1bc'],
            [256, b'\x03\x04\x05\x06\x07', 10, '12952339975'],
            [16, '3132333435', 256, b'12345']
        ]
        for prebase, preval, postbase, postval in data:
            self.assertEqual(changebase(preval, prebase, postbase), postval)

        for i in range(100):
            x = random.randrange(1, 9999999999999999)
            frm = random.choice([2, 10, 16, 58, 256])
            to = random.choice([2, 10, 16, 58, 256])
            self.assertEqual(decode(encode(x, to), to), x)
            self.assertEqual(changebase(encode(x, frm), frm, to), encode(x, to))
            self.assertEqual(decode(changebase(encode(x, frm), frm, to), to), x)


class TestElectrumWalletInternalConsistency(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print('Starting Electrum wallet internal consistency tests')

    def test_all(self):
        for i in range(3):
            electrum_mpk = electrum_masterprivkey
            seed = sha256(str(random.randrange(2**40)))[:32]
            mpk = electrum_mpk(seed)
            for i in range(5):
                pk = electrum_privkey(seed, i)
                pub = electrum_pubkey((mpk, seed)[i % 2], i)
                pub2 = privtopub(pk)
                self.assertEqual(
                    pub,
                    pub2,
                    'Does not match! Details:\nseed: %s\nmpk: %s\npriv: %s\npub: %s\npub2: %s' % (
                        seed, mpk, pk, pub, pub2
                    )
                )


class TestRawSignRecover(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("Basic signing and recovery tests")

    def test_all(self):
        for i in range(20):
            k = sha256(str(i))
            s = ecdsa_raw_sign('35' * 32, k)
            self.assertEqual(
                ecdsa_raw_recover('35' * 32, s),
                decode_pubkey(privtopub(k))
            )


class TestTransactionSignVerify(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("Transaction-style signing and verification tests")

    def test_all(self):
        alphabet = "1234567890qwertyuiopasdfghjklzxcvbnm"
        for i in range(10):
            msg = ''.join([random.choice(alphabet) for i in range(random.randrange(20, 200))])
            priv = sha256(str(random.randrange(2**256)))
            pub = privtopub(priv)
            sig = ecdsa_tx_sign(msg, priv)
            self.assertTrue(
                ecdsa_tx_verify(msg, sig, pub),
                "Verification error"
            )

            self.assertIn(
                pub,
                ecdsa_tx_recover(msg, sig),
                "Recovery failed"
            )


class TestSerialize(unittest.TestCase):

    def test_serialize(self):
        tx = '0100000001239f932c780e517015842f3b02ff765fba97f9f63f9f1bc718b686a56ed9c73400000000fd5d010047304402200c40fa58d3f6d5537a343cf9c8d13bc7470baf1d13867e0de3e535cd6b4354c802200f2b48f67494835b060d0b2ff85657d2ba2d9ea4e697888c8cb580e8658183a801483045022056f488c59849a4259e7cef70fe5d6d53a4bd1c59a195b0577bd81cb76044beca022100a735b319fa66af7b178fc719b93f905961ef4d4446deca8757a90de2106dd98a014cc95241046c7d87fd72caeab48e937f2feca9e9a4bd77f0eff4ebb2dbbb9855c023e334e188d32aaec4632ea4cbc575c037d8101aec73d029236e7b1c2380f3e4ad7edced41046fd41cddf3bbda33a240b417a825cc46555949917c7ccf64c59f42fd8dfe95f34fae3b09ed279c8c5b3530510e8cca6230791102eef9961d895e8db54af0563c410488d618b988efd2511fc1f9c03f11c210808852b07fe46128c1a6b1155aa22cdf4b6802460ba593db2d11c7e6cbe19cedef76b7bcabd05d26fd97f4c5a59b225053aeffffffff0310270000000000001976a914a89733100315c37d228a529853af341a9d290a4588ac409c00000000000017a9142b56f9a4009d9ff99b8f97bea4455cd71135f5dd87409c00000000000017a9142b56f9a4009d9ff99b8f97bea4455cd71135f5dd8700000000'
        self.assertEqual(
            serialize(deserialize(tx)),
            tx,
            "Serialize roundtrip failed"
        )

    def test_serialize_script(self):
        script = '47304402200c40fa58d3f6d5537a343cf9c8d13bc7470baf1d13867e0de3e535cd6b4354c802200f2b48f67494835b060d0b2ff85657d2ba2d9ea4e697888c8cb580e8658183a801483045022056f488c59849a4259e7cef70fe5d6d53a4bd1c59a195b0577bd81cb76044beca022100a735b319fa66af7b178fc719b93f905961ef4d4446deca8757a90de2106dd98a014cc95241046c7d87fd72caeab48e937f2feca9e9a4bd77f0eff4ebb2dbbb9855c023e334e188d32aaec4632ea4cbc575c037d8101aec73d029236e7b1c2380f3e4ad7edced41046fd41cddf3bbda33a240b417a825cc46555949917c7ccf64c59f42fd8dfe95f34fae3b09ed279c8c5b3530510e8cca6230791102eef9961d895e8db54af0563c410488d618b988efd2511fc1f9c03f11c210808852b07fe46128c1a6b1155aa22cdf4b6802460ba593db2d11c7e6cbe19cedef76b7bcabd05d26fd97f4c5a59b225053ae'
        self.assertEqual(
            serialize_script(deserialize_script(script)),
            script,
            "Script serialize roundtrip failed"
        )


class TestTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("Attempting transaction creation")

    # FIXME: I don't know how to write this as a unit test.
    # What should be asserted?
    def test_all(self):
        privs = [sha256(str(random.randrange(2**256))) for x in range(4)]
        pubs = [privtopub(priv) for priv in privs]
        addresses = [pubtoaddr(pub) for pub in pubs]
        mscript = mk_multisig_script(pubs[1:], 2, 3)
        msigaddr = p2sh_scriptaddr(mscript)
        tx = mktx(['01'*32+':1', '23'*32+':2'], [msigaddr+':20202', addresses[0]+':40404'])
        tx1 = sign(tx, 1, privs[0])

        sig1 = multisign(tx, 0, mscript, privs[1])
        self.assertTrue(verify_tx_input(tx1, 0, mscript, sig1, pubs[1]), "Verification Error")

        sig3 = multisign(tx, 0, mscript, privs[3])
        self.assertTrue(verify_tx_input(tx1, 0, mscript, sig3, pubs[3]), "Verification Error")

        tx2 = apply_multisignatures(tx1, 0, mscript, [sig1, sig3])
        print("Outputting transaction: ", tx2)

    # https://github.com/vbuterin/pybitcointools/issues/71
    def test_multisig(self):
        script = mk_multisig_script(["0254236f7d1124fc07600ad3eec5ac47393bf963fbf0608bcce255e685580d16d9",
                                     "03560cad89031c412ad8619398bd43b3d673cb5bdcdac1afc46449382c6a8e0b2b"],
                                     2)

        self.assertEqual(p2sh_scriptaddr(script), "33byJBaS5N45RHFcatTSt9ZjiGb6nK4iV3")

        self.assertEqual(p2sh_scriptaddr(script, 0x05), "33byJBaS5N45RHFcatTSt9ZjiGb6nK4iV3")
        self.assertEqual(p2sh_scriptaddr(script, 5), "33byJBaS5N45RHFcatTSt9ZjiGb6nK4iV3")

        self.assertEqual(p2sh_scriptaddr(script, 0xc4), "2MuABMvWTgpZRd4tAG25KW6YzvcoGVZDZYP")
        self.assertEqual(p2sh_scriptaddr(script, 196), "2MuABMvWTgpZRd4tAG25KW6YzvcoGVZDZYP")


class TestDeterministicGenerate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("Beginning RFC6979 deterministic signing tests")

    def test_all(self):
        # Created with python-ecdsa 0.9
        # Code to make your own vectors:
        # class gen:
        #     def order(self): return 115792089237316195423570985008687907852837564279074904382605163141518161494337
        # dummy = gen()
        # for i in range(10): ecdsa.rfc6979.generate_k(dummy, i, hashlib.sha256, hashlib.sha256(str(i)).digest())
        test_vectors = [
            32783320859482229023646250050688645858316445811207841524283044428614360139869,
            109592113955144883013243055602231029997040992035200230706187150761552110229971,
            65765393578006003630736298397268097590176526363988568884298609868706232621488,
            85563144787585457107933685459469453513056530050186673491900346620874099325918,
            99829559501561741463404068005537785834525504175465914981205926165214632019533,
            7755945018790142325513649272940177083855222863968691658328003977498047013576,
            81516639518483202269820502976089105897400159721845694286620077204726637043798,
            52824159213002398817852821148973968315579759063230697131029801896913602807019,
            44033460667645047622273556650595158811264350043302911918907282441675680538675,
            32396602643737403620316035551493791485834117358805817054817536312402837398361
        ]

        for i, ti in enumerate(test_vectors):
            mine = deterministic_generate_k(bin_sha256(str(i)), encode(i, 256, 32))
            self.assertEqual(
                ti,
                mine,
                "Test vector does not match. Details:\n%s\n%s" % (
                    ti,
                    mine
                )
            )


class TestBIP0032(unittest.TestCase):
    """See: https://en.bitcoin.it/wiki/BIP_0032"""
    @classmethod
    def setUpClass(cls):
        print("Beginning BIP0032 tests")

    def _full_derive(self, key, chain):
        if len(chain) == 0:
            return key
        elif chain[0] == 'pub':
            return self._full_derive(bip32_privtopub(key), chain[1:])
        else:
            return self._full_derive(bip32_ckd(key, chain[0]), chain[1:])

    def test_all(self):
        test_vectors = [
            [[], 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'],
            [['pub'], 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'],
            [[2**31], 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'],
            [[2**31, 1], 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'],
            [[2**31, 1, 2**31 + 2], 'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'],
            [[2**31, 1, 2**31 + 2, 'pub', 2, 1000000000], 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy']
        ]

        mk = bip32_master_key(safe_from_hex('000102030405060708090a0b0c0d0e0f'))

        for tv in test_vectors:
            left, right = self._full_derive(mk, tv[0]), tv[1]
            self.assertEqual(
                left,
                right,
                "Test vector does not match. Details: \n%s\n%s\n\%s" % (
                    tv[0],
                    [safe_hexlify(x) if isinstance(x, str) else x for x in bip32_deserialize(left)],
                    [safe_hexlify(x) if isinstance(x, str) else x for x in bip32_deserialize(right)],
                )
            )

    def test_all_testnet(self):
        test_vectors = [
            [[], 'tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m'],
            [['pub'], 'tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp'],
            [[2**31], 'tprv8bxNLu25VazNnppTCP4fyhyCvBHcYtzE3wr3cwYeL4HA7yf6TLGEUdS4QC1vLT63TkjRssqJe4CvGNEC8DzW5AoPUw56D1Ayg6HY4oy8QZ9'],
            [[2**31, 1], 'tprv8e8VYgZxtHsSdGrtvdxYaSrryZGiYviWzGWtDDKTGh5NMXAEB8gYSCLHpFCywNs5uqV7ghRjimALQJkRFZnUrLHpzi2pGkwqLtbubgWuQ8q'],
            [[2**31, 1, 2**31 + 2], 'tprv8gjmbDPpbAirVSezBEMuwSu1Ci9EpUJWKokZTYccSZSomNMLytWyLdtDNHRbucNaRJWWHANf9AzEdWVAqahfyRjVMKbNRhBmxAM8EJr7R15'],
            [[2**31, 1, 2**31 + 2, 'pub', 2, 1000000000], 'tpubDHNy3kAG39ThyiwwsgoKY4iRenXDRtce8qdCFJZXPMCJg5dsCUHayp84raLTpvyiNA9sXPob5rgqkKvkN8S7MMyXbnEhGJMW64Cf4vFAoaF']
        ]

        mk = bip32_master_key(safe_from_hex('000102030405060708090a0b0c0d0e0f'), TESTNET_PRIVATE)

        for tv in test_vectors:
            left, right = self._full_derive(mk, tv[0]), tv[1]
            self.assertEqual(
                left,
                right,
                "Test vector does not match. Details:\n%s\n%s\n%s\n\%s" % (
                    left,
                    tv[0],
                    [x.encode('hex') if isinstance(x, str) else x for x in bip32_deserialize(left)],
                    [x.encode('hex') if isinstance(x, str) else x for x in bip32_deserialize(right)],
                )
            )

    def test_extra(self):
        master = bip32_master_key(safe_from_hex("000102030405060708090a0b0c0d0e0f"))

        # m/0
        assert bip32_ckd(master, "0") == "xprv9uHRZZhbkedL37eZEnyrNsQPFZYRAvjy5rt6M1nbEkLSo378x1CQQLo2xxBvREwiK6kqf7GRNvsNEchwibzXaV6i5GcsgyjBeRguXhKsi4R"
        assert bip32_privtopub(bip32_ckd(master, "0")) == "xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1"

        # m/1
        assert bip32_ckd(master, "1") == "xprv9uHRZZhbkedL4yTpidDvuVfrdUkTbhDHviERRBkbzbNDZeMjWzqzKAdxWhzftGDSxDmBdakjqHiZJbkwiaTEXJdjZAaAjMZEE3PMbMrPJih"
        assert bip32_privtopub(bip32_ckd(master, "1")) == "xpub68Gmy5EVb2BdHTYHpekwGdcbBWax19w9HwA2DaADYvuCSSgt4YAErxxSN1KWSnmyqkwRNbnTj3XiUBKmHeC8rTjLRPjSULcDKQQgfgJDppq"

        # m/0/0
        assert bip32_ckd(bip32_ckd(master, "0"), "0") == "xprv9ww7sMFLzJMzur2oEQDB642fbsMS4q6JRraMVTrM9bTWBq7NDS8ZpmsKVB4YF3mZecqax1fjnsPF19xnsJNfRp4RSyexacULXMKowSACTRc"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, "0"), "0")) == "xpub6AvUGrnEpfvJ8L7GLRkBTByQ9uBvUHp9o5VxHrFxhvzV4dSWkySpNaBoLR9FpbnwRmTa69yLHF3QfcaxbWT7gWdwws5k4dpmJvqpEuMWwnj"

        # m/0'
        assert bip32_ckd(master, 2**31) == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        assert bip32_privtopub(bip32_ckd(master, 2**31)) == "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

        # m/1'
        assert bip32_ckd(master, 2**31 + 1) == "xprv9uHRZZhk6KAJFszJGW6LoUFq92uL7FvkBhmYiMurCWPHLJZkX2aGvNdRUBNnJu7nv36WnwCN59uNy6sxLDZvvNSgFz3TCCcKo7iutQzpg78"
        assert bip32_privtopub(bip32_ckd(master, 2**31 + 1)) == "xpub68Gmy5EdvgibUN4mNXdMAcCZh4jpWiebYvh9WkKTkqvGD6tu4ZtXUAwuKSyF5DFZVmotf9UHFTGqSXo9qyDBSn47RkaN6Aedt9JbL7zcgSL"

        # m/1'
        assert bip32_ckd(master, 1 + 2**31) == "xprv9uHRZZhk6KAJFszJGW6LoUFq92uL7FvkBhmYiMurCWPHLJZkX2aGvNdRUBNnJu7nv36WnwCN59uNy6sxLDZvvNSgFz3TCCcKo7iutQzpg78"
        assert bip32_privtopub(bip32_ckd(master, 1 + 2**31)) == "xpub68Gmy5EdvgibUN4mNXdMAcCZh4jpWiebYvh9WkKTkqvGD6tu4ZtXUAwuKSyF5DFZVmotf9UHFTGqSXo9qyDBSn47RkaN6Aedt9JbL7zcgSL"

        # m/0'/0
        assert bip32_ckd(bip32_ckd(master, 2**31), "0") == "xprv9wTYmMFdV23N21MM6dLNavSQV7Sj7meSPXx6AV5eTdqqGLjycVjb115Ec5LgRAXscPZgy5G4jQ9csyyZLN3PZLxoM1h3BoPuEJzsgeypdKj"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, 2**31), "0")) == "xpub6ASuArnXKPbfEVRpCesNx4P939HDXENHkksgxsVG1yNp9958A33qYoPiTN9QrJmWFa2jNLdK84bWmyqTSPGtApP8P7nHUYwxHPhqmzUyeFG"

        # m/0'/0'
        assert bip32_ckd(bip32_ckd(master, 2**31), 2**31) == "xprv9wTYmMFmpgaLB5Hge4YtaGqCKpsYPTD9vXWSsmdZrNU3Y2i4WoBykm6ZteeCLCCZpGxdHQuqEhM6Gdo2X6CVrQiTw6AAneF9WSkA9ewaxtS"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, 2**31), 2**31)) == "xpub6ASuArnff48dPZN9k65twQmvsri2nuw1HkS3gA3BQi12Qq3D4LWEJZR3jwCAr1NhsFMcQcBkmevmub6SLP37bNq91SEShXtEGUbX3GhNaGk"

        # m/44'/0'/0'/0/0
        assert bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(master, 44 + 2**31), 2**31), 2**31), 0), 0) == "xprvA4A9CuBXhdBtCaLxwrw64Jaran4n1rgzeS5mjH47Ds8V67uZS8tTkG8jV3BZi83QqYXPcN4v8EjK2Aof4YcEeqLt688mV57gF4j6QZWdP9U"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(master, 44 + 2**31), 2**31), 2**31), 0), 0)) == "xpub6H9VcQiRXzkBR4RS3tU6RSXb8ouGRKQr1f1NXfTinCfTxvEhygCiJ4TDLHz1dyQ6d2Vz8Ne7eezkrViwaPo2ZMsNjVtFwvzsQXCDV6HJ3cV"


class TestStartingAddressAndScriptGenerationConsistency(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("Starting address and script generation consistency tests")

    def test_all(self):
        for i in range(5):
            a = privtoaddr(random_key())
            self.assertEqual(a, script_to_address(address_to_script(a)))
            self.assertEqual(a, script_to_address(address_to_script(a), 0))
            self.assertEqual(a, script_to_address(address_to_script(a), 0x00))

            b = privtoaddr(random_key(), 5)
            self.assertEqual(b, script_to_address(address_to_script(b)))
            self.assertEqual(b, script_to_address(address_to_script(b), 0))
            self.assertEqual(b, script_to_address(address_to_script(b), 0x00))
            self.assertEqual(b, script_to_address(address_to_script(b), 5))
            self.assertEqual(b, script_to_address(address_to_script(b), 0x05))


        for i in range(5):
            a = privtoaddr(random_key(), 0x6f)
            self.assertEqual(a, script_to_address(address_to_script(a), 111))
            self.assertEqual(a, script_to_address(address_to_script(a), 0x6f))

            b = privtoaddr(random_key(), 0xc4)
            self.assertEqual(b, script_to_address(address_to_script(b), 111))
            self.assertEqual(b, script_to_address(address_to_script(b), 0x6f))
            self.assertEqual(b, script_to_address(address_to_script(b), 196))
            self.assertEqual(b, script_to_address(address_to_script(b), 0xc4))


class TestRipeMD160PythonBackup(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print('Testing the pure python backup for ripemd160')

    def test_all(self):
        strvec = [
            '',
            'The quick brown fox jumps over the lazy dog',
            'The quick brown fox jumps over the lazy cog',
            'Nobody inspects the spammish repetition'
        ]

        target = [
            '9c1185a5c5e9fc54612808977ee8f548b2258d31',
            '37f332f68db77bd9d7edd4969571ad671cf9dd3b',
            '132072df690933835eb8b6ad0b77e7b6f14acad7',
            'cc4a5ce1b3df48aec5d22d1f16b894a0b894eccc'
        ]

        hash160target = [
            'b472a266d0bd89c13706a4132ccfb16f7c3b9fcb',
            '0e3397b4abc7a382b3ea2365883c3c7ca5f07600',
            '53e0dacac5249e46114f65cb1f30d156b14e0bdc',
            '1c9b7b48049a8f98699bca22a5856c5ef571cd68'
        ]

        for i, s in enumerate(strvec):
            digest = ripemd.RIPEMD160(s).digest()
            hash160digest = ripemd.RIPEMD160(bin_sha256(s)).digest()
            self.assertEqual(from_bytes_to_str(digest), target[i])
            self.assertEqual(from_bytes_to_str(hash160digest), hash160target[i])
            self.assertEqual(from_bytes_to_str(bin_hash160(from_string_to_bytes(s))), hash160target[i])
            self.assertEqual(hash160(from_str_to_bytes(s)), hash160target[i])


class TestScriptVsAddressOutputs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print('Testing script vs address outputs')

    def test_all(self):
        addr0 = '1Lqgj1ThNfwLgHMp5qJUerYsuUEm8vHmVG'
        script0 = '76a914d99f84267d1f90f3e870a5e9d2399918140be61d88ac'
        addr1 = '31oSGBBNrpCiENH3XMZpiP6GTC4tad4bMy'
        script1 = 'a9140136d001619faba572df2ef3d193a57ad29122d987'

        inputs = [{
            'output': 'cd6219ea108119dc62fce09698b649efde56eca7ce223a3315e8b431f6280ce7:0',
            'value': 158000
        }]

        outputs = [
            [{'address': addr0, 'value': 1000}, {'address': addr1, 'value': 2000}],
            [{'script': script0, 'value': 1000}, {'address': addr1, 'value': 2000}],
            [{'address': addr0, 'value': 1000}, {'script': script1, 'value': 2000}],
            [{'script': script0, 'value': 1000}, {'script': script1, 'value': 2000}],
            [addr0 + ':1000', addr1 + ':2000'],
            [script0 + ':1000', addr1 + ':2000'],
            [addr0 + ':1000', script1 + ':2000'],
            [script0 + ':1000', script1 + ':2000']
        ]

        for outs in outputs:
            tx_struct = deserialize(mktx(inputs, outs))
            self.assertEqual(tx_struct['outs'], outputs[3])


class TestConversions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.privkey_hex = (
            "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262"
        )
        cls.privkey_bin = (
            b"\xe9\x87=y\xc6\xd8}\xc0\xfbjWxc3\x89\xf4E2\x130=\xa6\x1f \xbdg\xfc#:\xa32b"
        )

        cls.pubkey_hex = (
            "04588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9f88ff2a00d7e752d44cbe16e1ebcf0890b76ec7c78886109dee76ccfc8445424"
        )
        cls.pubkey_bin = (
            b"\x04X\x8d *\xfc\xc1\xeeJ\xb5%LxG\xec%\xb9\xa15\xbb\xda\x0f+\xc6\x9e\xe1\xa7\x14t\x9f\xd7}\xc9\xf8\x8f\xf2\xa0\r~u-D\xcb\xe1n\x1e\xbc\xf0\x89\x0bv\xec|x\x88a\t\xde\xe7l\xcf\xc8DT$"
        )

    def test_privkey_to_pubkey(self):
        pubkey_hex = privkey_to_pubkey(self.privkey_hex)
        self.assertEqual(pubkey_hex, self.pubkey_hex)

    def test_changebase(self):
        self.assertEqual(
            self.pubkey_bin,
            changebase(
                self.pubkey_hex, 16, 256, minlen=len(self.pubkey_bin)
            )
        )

        self.assertEqual(
            self.pubkey_hex,
            changebase(
                self.pubkey_bin, 256, 16, minlen=len(self.pubkey_hex)
            )
        )

        self.assertEqual(
            self.privkey_bin,
            changebase(
                self.privkey_hex, 16, 256, minlen=len(self.privkey_bin)
            )
        )

        self.assertEqual(
            self.privkey_hex,
            changebase(
                self.privkey_bin, 256, 16, minlen=len(self.privkey_hex)
            )
        )


class Transaction_Misc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("Testing new transaction calls/functions...")

    def test_all(self):
        testnet_vars = [
            "45138cc9dd17b13950230cd64d75891df829ec9b4b3e8aa3b9d2efbb3710965e",
            "n2kx7k6JuA5Wy27fawaeiPX7dq8mbRDPAv",
            "00000000eb0f55acb42a17e5d3ebd6fc638a69b7d72b9a089a556b320b9f33a2"
            ]
        mainnet_vars = [
            "6df88400ab991f31be5d44be76d46ff3cb482e6417c8b472037d932424a191ff",
            "1MBngSqZbMydscpzSoehjP8kznMaHAzh9y",
            "000000004257f209a21040d1baeb99c1ea852271238ef67a124a2c5349e1d870"
        ]

        for var in testnet_vars:
            self.assertTrue(is_testnet(var), "is_testnet failed for {0}".format(str(var)))
        
        for var in mainnet_vars:
            self.assertFalse(is_testnet(var) is False, "is_testnet should fail for mainnet {0}".format(str(var)))


        print("Checking predicate/regex functions...")

        hexes = ["".join([random.choice(string.hexdigits) for x in range(64)]) for y in range(10)]
        for hx in hexes:
            txid = hx[:].lower()
            inp = "{0}:{1}".format(txid, str(random.randrange(0xffffffff)))
            self.assertRegexpMatches(
                hx,
                RE_HEX_CHARS,
                "RE_HEX_CHARS failed for {hx}".format(hx=hx)
            )
            self.assertTrue(is_hex(hx), "is_hex failed for {hx}".format(hx=hx))
            self.assertTrue(is_txid(txid), "is_txid failed for {txid}".format(txid=txid))
            self.assertTrue(is_inp(inp), "is_inp failed for {inp}".format(inp=inp))


        addresses = [privtoaddr(random_key()) for x in range(10)]
        for addr in addresses:
            outp = "{0}:{1}".format(addr, str(random.randrange(2100000000000000)))
            self.assertRegexpMatches(
                addr,
                RE_ADDR,
                "RE_ADDR failed for {address}".format(address=addr)
            )
            self.assertTrue(is_address(addr), "is_address failed for {addr}".format(addr=addr))
            self.assertTrue(is_outp(outp), "is_outp failed for {outp}".format(outp=outp))


        blockhashes = ["".join([random.choice(string.hexdigits) for x in range(56)]).zfill(64).lower()
                       for y in range(10)]
        for bh in blockhashes:
            self.assertRegexpMatches(
                bh,
                RE_BLOCKHASH,
                "RE_BLOCKHASH failed for {bh}".format(bh=bh)
            )
            self.assertTrue(is_blockhash(bh), "is_blockhash failed for {bh}".format(bh=bh))

        privkeys = [random_key()]
        privkeys.append(privkeys[0] + "01")
        privkeys.append(encode_privkey(decode_privkey(privkeys[0]), "wif"))
        privkeys.append(encode_privkey(decode_privkey(privkeys[0]), "wif_compressed"))

        for pk in privkeys:
            self.assertRegexpMatches(
                pk,
                RE_PRIVKEY,
                "RE_PRIVKEY failed for {pk}".format(pk=pk))
            self.assertTrue(is_privkey(pk), "is_privkey failed for {pk}".format(pk=pk))


        pubkeys = [privtopub(random_key()) for x in range(5)] + \
                  [compress(privtopub(random_key())) for x in range(5)]

        for pubk in pubkeys:
            self.assertRegexpMatches(
                pubk,
                RE_PUBKEY,
                "RE_PUBKEY failed for {pubk}".format(pubk=pubk)
            )
            self.assertTrue(is_pubkey(pubk), "is_pubkey failed for {pubk}".format(pubk=pubk))


        txhexes = [
            "010000000186f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c010000006"
            "b483045022100ac8c6dbc482c79e86c18928a8b364923c774bfdbd852059f6b3778f2319b59a7022029"
            "d7cc5724e2f41ab1fcfc0ba5a0d4f57ca76f72f19530ba97c860c70a6bf0a801210272d83d8a1fa323f"
            "eab1c085157a0791b46eba34afb8bfbfaeb3a3fcc3f2c9ad8ffffffff0210270000000000001976a914"
            "8066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac1027000000000000536a4c50010002063e4eb95"
            "e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e252"
            "8979311c78cb2de0d682c61e1180fc3d543b0000000000000000000000000000000000",
            
            "0100000003d5001aae8358ae98cb02c1b6f9859dc1ac3dbc1e9cc88632afeb7b7e3c510a49000000008"
            "b4830450221009e03bb6122437767e2ca785535824f4ed13d2ebbb9fa4f9becc6d6f4e1e217dc022064"
            "577353c08d8d974250143d920d3b963b463e43bbb90f3371060645c49266b90141048ef80f6bd6b0734"
            "07a69299c2ba89de48adb59bb9689a5ab040befbbebcfbb15d01b006a6b825121a0d2c546c277acb60f"
            "0bd3203bd501b8d67c7dba91f27f47ffffffff1529d655dff6a0f6c9815ee835312fb3ca4df622fde21"
            "b6b9097666e9284087d010000008a473044022035dd67d18b575ebd339d05ca6ffa1d27d7549bd993ae"
            "af430985795459fc139402201aaa162cc50181cee493870c9479b1148243a33923cb77be44a73ca554a"
            "4e5d60141048ef80f6bd6b073407a69299c2ba89de48adb59bb9689a5ab040befbbebcfbb15d01b006a"
            "6b825121a0d2c546c277acb60f0bd3203bd501b8d67c7dba91f27f47ffffffff23d5f9cf0a8c233b354"
            "43c3ae48d0bdb41bef357b8bfb972336322a34cd75c80010000008b483045022014daa5c5bbe9b3e5f2"
            "539a5cd8e22ce55bc84788f946c5b3643ecac85b4591a9022100a4062074a1df3fa0aea5ef67368d0b1"
            "f0eaac520bee6e417c682d83cd04330450141048ef80f6bd6b073407a69299c2ba89de48adb59bb9689"
            "a5ab040befbbebcfbb15d01b006a6b825121a0d2c546c277acb60f0bd3203bd501b8d67c7dba91f27f4"
            "7ffffffff02204e0000000000001976a914946cb2e08075bcbaf157e47bcb67eb2b2339d24288ac5b3c"
            "4411000000001976a914a41d15ae657ad3bfd0846771a34d7584c37d54a288ac00000000"
        ]

        for txh in txhexes:
            self.assertRegexpMatches(
                txh,
                RE_TXHEX,
                "RE_TXHEX failed for {txh}".format(txh=txh)
            )
            self.assertTrue(is_txhex(txh), "is_txhex failed for {txh}".format(txh=txh))


        txobjs = list(map(lambda x: deserialize(x), txhexes))
        txs = txhexes + txobjs

        for txo in txobjs:
            self.assertTrue(is_txobj(txo), "is_txobj failed for {txo}".format(txo=txo))
        
        for tx in txs:
            self.assertTrue(is_tx(tx), "is_tx failed for {tx}".format(tx=tx))


        mnemonics = [random_bip39_mn(random.choice((128, 192, 256))) for x in range(10)]
        for mn in mnemonics:
            self.assertRegexpMatches(
                mn,
                RE_MNEMONIC,
                "RE_MNEMONIC failed for {mn}".format(mn=mn)
            )

        prefixes = [random.choice(('xprv', 'tprv')) for x in range(10)]
        suffixes = ["".join(["%x" % random.randrange(16) for x in range(107)]) for y in range(10)]
        bip32_prvs = ["{0}{1}".format(a,b) for a in prefixes for b in suffixes]
        
        for key in bip32_prvs:
            self.assertRegexpMatches(
                key,
                RE_BIP32_PRIV,
                "RE_BIP32_PRIV failed for {key}".format(key=key)
            )

        prefixes = [random.choice(('xpub', 'tpub')) for x in range(10)]
        suffixes = ["".join(["%x" % random.randrange(16) for x in range(107)]) for y in range(10)]
        bip32_pubs = ["{0}{1}".format(a,b) for a in prefixes for b in suffixes]
        
        for pubk in bip32_pubs:
            self.assertRegexpMatches(
                pubk,
                RE_BIP32_PUB,
                "RE_BIP32_PUB failed for {pubk}".format(pubk=pubk)
            )


        print("Checking DER functions...")

        txhex = "0100000003d5001aae8358ae98cb02c1b6f9859dc1ac3dbc1e9cc88632afeb7b7e3c510a49000000008b4830450221009e03bb6122437767e2ca785535824f4ed13d2ebbb9fa4f9becc6d6f4e1e217dc022064577353c08d8d974250143d920d3b963b463e43bbb90f3371060645c49266b90141048ef80f6bd6b073407a69299c2ba89de48adb59bb9689a5ab040befbbebcfbb15d01b006a6b825121a0d2c546c277acb60f0bd3203bd501b8d67c7dba91f27f47ffffffff1529d655dff6a0f6c9815ee835312fb3ca4df622fde21b6b9097666e9284087d010000008a473044022035dd67d18b575ebd339d05ca6ffa1d27d7549bd993aeaf430985795459fc139402201aaa162cc50181cee493870c9479b1148243a33923cb77be44a73ca554a4e5d60141048ef80f6bd6b073407a69299c2ba89de48adb59bb9689a5ab040befbbebcfbb15d01b006a6b825121a0d2c546c277acb60f0bd3203bd501b8d67c7dba91f27f47ffffffff23d5f9cf0a8c233b35443c3ae48d0bdb41bef357b8bfb972336322a34cd75c80010000008b483045022014daa5c5bbe9b3e5f2539a5cd8e22ce55bc84788f946c5b3643ecac85b4591a9022100a4062074a1df3fa0aea5ef67368d0b1f0eaac520bee6e417c682d83cd04330450141048ef80f6bd6b073407a69299c2ba89de48adb59bb9689a5ab040befbbebcfbb15d01b006a6b825121a0d2c546c277acb60f0bd3203bd501b8d67c7dba91f27f47ffffffff02204e0000000000001976a914946cb2e08075bcbaf157e47bcb67eb2b2339d24288ac5b3c4411000000001976a914a41d15ae657ad3bfd0846771a34d7584c37d54a288ac00000000"

        bip66_ders = [
            '30450221009e03bb6122437767e2ca785535824f4ed13d2ebbb9fa4f9becc6d6f4e1e217dc022064577353c08d8d974250143d920d3b963b463e43bbb90f3371060645c49266b901',
            '3044022035dd67d18b575ebd339d05ca6ffa1d27d7549bd993aeaf430985795459fc139402201aaa162cc50181cee493870c9479b1148243a33923cb77be44a73ca554a4e5d601',
            '3045022014daa5c5bbe9b3e5f2539a5cd8e22ce55bc84788f946c5b3643ecac85b4591a9022100a4062074a1df3fa0aea5ef67368d0b1f0eaac520bee6e417c682d83cd043304501'
        ]

        for sig in bip66_ders:
            self.assertRegexpMatches(
                sig,
                RE_DER,
                "RE_DER failed for {sig}".format(sig=sig)
            )
            self.assertTrue(is_der(sig), "is_der failed for {0}".format(sig))
            self.assertTrue(is_bip66(sig), "is_bip66 failed for {0}".format(sig))

        self.assertListEqual(bip66_ders, extract_ders(txhex), "extract_ders failed")




if __name__ == '__main__':
    unittest.main()
