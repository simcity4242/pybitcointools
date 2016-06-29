import unittest

from bitcoin import *
from bitcoin.mnemonic import *
from bitcoin.deterministic import *
from bitcoin.utils import *

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
            seed = sha256(str(random.randrange(2**40)))[:32]
            mpk = electrum_mpubk(seed)
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


# class TestElectrumSignVerify(unittest.TestCase):
#     """Requires Electrum."""
#
#     @classmethod
#     def setUpClass(cls):
#         cls.wallet = "/tmp/tempwallet_" + str(random.randrange(2**40))
#         print("Starting wallet tests with: " + cls.wallet)
#         os.popen('echo "\n\n\n\n\n\n" | electrum -w %s create' % cls.wallet).read()
#         cls.seed = str(json.loads(os.popen("electrum -w %s getseed" % cls.wallet).read())['seed'])
#         cls.addies = json.loads(os.popen("electrum -w %s listaddresses" % cls.wallet).read())
#
#     def test_address(self):
#         for i in range(5):
#             self.assertEqual(
#                 self.addies[i],
#                 electrum_address(self.seed, i, 0),
#                 "Address does not match! Details:\nseed %s, i: %d" % (self.seed, i)
#             )
#
#     def test_sign_verify(self):
#         print("Electrum-style signing and verification tests, against actual Electrum")
#         alphabet = "1234567890qwertyuiopasdfghjklzxcvbnm"
#         for i in range(8):
#             msg = ''.join([random.choice(alphabet) for i in range(random.randrange(20, 200))])
#             addy = random.choice(self.addies)
#             wif = os.popen('electrum -w %s dumpprivkey %s' % (self.wallet, addy)).readlines()[-2].replace('"', '').strip()
#             priv = b58check_to_hex(wif)
#             pub = privtopub(priv)
#
#             sig = os.popen('electrum -w %s signmessage %s %s' % (self.wallet, addy, msg)).readlines()[-1].strip()
#             self.assertTrue(
#                 ecdsa_verify(msg, sig, pub),
#                 "Verification error. Details:\nmsg: %s\nsig: %s\npriv: %s\naddy: %s\npub: %s" % (
#                     msg, sig, priv, addy, pub
#                 )
#             )
#
#             rec = ecdsa_recover(msg, sig)
#             self.assertEqual(
#                 pub,
#                 rec,
#                 "Recovery error. Details:\nmsg: %s\nsig: %s\npriv: %s\naddy: %s\noriginal pub: %s, %s\nrecovered pub: %s" % (
#                     msg, sig, priv, addy, pub, decode_pubkey(pub, 'hex')[1], rec
#                 )
#             )
#
#             mysig = ecdsa_sign(msg, priv)
#             self.assertEqual(
#                 os.popen('electrum -w %s verifymessage %s %s %s' % (self.wallet, addy, mysig, msg)).read().strip(),
#                 "true",
#                 "Electrum verify message does not match"
#             )


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
        tx = '0100000001239f932c780e517015842f3b02ff765fba97f9f63f9f1bc718b686a56ed9c73400000000' \
             'fd5d010047304402200c40fa58d3f6d5537a343cf9c8d13bc7470baf1d13867e0de3e535cd6b4354c8' \
             '02200f2b48f67494835b060d0b2ff85657d2ba2d9ea4e697888c8cb580e8658183a801483045022056' \
             'f488c59849a4259e7cef70fe5d6d53a4bd1c59a195b0577bd81cb76044beca022100a735b319fa66af' \
             '7b178fc719b93f905961ef4d4446deca8757a90de2106dd98a014cc95241046c7d87fd72caeab48e93' \
             '7f2feca9e9a4bd77f0eff4ebb2dbbb9855c023e334e188d32aaec4632ea4cbc575c037d8101aec73d0' \
             '29236e7b1c2380f3e4ad7edced41046fd41cddf3bbda33a240b417a825cc46555949917c7ccf64c59f' \
             '42fd8dfe95f34fae3b09ed279c8c5b3530510e8cca6230791102eef9961d895e8db54af0563c410488' \
             'd618b988efd2511fc1f9c03f11c210808852b07fe46128c1a6b1155aa22cdf4b6802460ba593db2d11' \
             'c7e6cbe19cedef76b7bcabd05d26fd97f4c5a59b225053aeffffffff0310270000000000001976a914' \
             'a89733100315c37d228a529853af341a9d290a4588ac409c00000000000017a9142b56f9a4009d9ff9' \
             '9b8f97bea4455cd71135f5dd87409c00000000000017a9142b56f9a4009d9ff99b8f' \
             '97bea4455cd71135f5dd8700000000'
        self.assertEqual(
            serialize(deserialize(tx)),
            tx,
            "Serialize roundtrip failed"
        )

    def test_serialize_script(self):
        hexvals = [encode(random.randrange(0, 0xffff), 16, 4) for x in range(20)]
        script = '47304402200c40fa58d3f6d5537a343cf9c8d13bc7470baf1d13867e0de3e535cd6b4354c80220' \
                 '0f2b48f67494835b060d0b2ff85657d2ba2d9ea4e697888c8cb580e8658183a801483045022056' \
                 'f488c59849a4259e7cef70fe5d6d53a4bd1c59a195b0577bd81cb76044beca022100a735b319fa' \
                 '66af7b178fc719b93f905961ef4d4446deca8757a90de2106dd98a014cc95241046c7d87fd72ca' \
                 'eab48e937f2feca9e9a4bd77f0eff4ebb2dbbb9855c023e334e188d32aaec4632ea4cbc575c037' \
                 'd8101aec73d029236e7b1c2380f3e4ad7edced41046fd41cddf3bbda33a240b417a825cc465559' \
                 '49917c7ccf64c59f42fd8dfe95f34fae3b09ed279c8c5b3530510e8cca6230791102eef9961d89' \
                 '5e8db54af0563c410488d618b988efd2511fc1f9c03f11c210808852b07fe46128c1a6b1155aa2' \
                 '2cdf4b6802460ba593db2d11c7e6cbe19cedef76b7bcabd05d26fd97f4c5a59b225053ae'
        self.assertEqual(
            serialize_script(deserialize_script(script)),
            script,
            "Script serialize roundtrip failed"
        )
        for v in hexvals:
            self.assertEqual(
                deserialize_script(serialize_script([v])),
                [v],
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
        self.assertEqual(mscript, mk_multisig_script(pubs[1:], 2), "Implicit n=3 error")
        msigaddr = p2sh_scriptaddr(mscript)
        tx = mktx(['01'*32+':1', '23'*32+':2'], 
                  [msigaddr+':20202', addresses[0]+':40404'], 
                  locktime=2222222222
                  )

        tx1 = sign(tx, 1, privs[0])

        self.assertEqual(deserialize(tx)['locktime'], 2222222222, "Locktime incorrect")

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

    def test_preparetx(self):
        try:
            hextx = preparetx('12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX', '1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1', 13)
        except:
            hextx = '01000000011c73efeb6333e673e34aec19b484ace0bd59384a47e112cb2a003732cae0eb360100000000' \
                    'ffffffff020d000000000000001976a914b3407d4b4d1fca87fb930abe3fa6c2baed6e6fd888ac835f01' \
                    '00000000001976a914119b098e2e980a229e139a9ed01a469e518e6f2688ac00000000'
        tx = deserialize(hextx)
        self.assertEqual(tx['locktime'], 0, "Locktime incorrect")
        self.assertEqual(tx['outs'][0]['value'], 13, "Value incorrect")

#        hextx = preparetx('12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX', '1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1', 13, locktime=2222222222)
#        tx = deserialize(hextx)
#        self.assertEqual(tx['locktime'], 2222222222, "Locktime incorrect")
#        self.assertEqual(tx['outs'][0]['value'], 13, "Value incorrect")

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

    def test_all(self):

        hexmasters = ['000102030405060708090a0b0c0d0e0f',
                   'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2' \
                   '9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542']

        masters = map(lambda k: bip32_master_key(safe_unhexlify(k)), hexmasters)

        # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1
        test_vectors1 = [
           #[ path, xpub, xprv]
            ["m/",
             'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
             'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'],
            ["m/0H",
             'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
             'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'],
            ["m/0H/1",
             'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
             'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'],
            ["m/0H/1/2H",
             'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
             'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'],
            ["m/0H/1/2H/2",
             'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',
             'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334'],
            ["m/0H/1/2H/2/1000000000",
             'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
             'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76']
        ]

        # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-2
        test_vectors2 = [
            # [ path, xpub, xprv]
            ["m/",
             'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',
             'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U'],
            ["m/0",
             'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',
             'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt'],
            ["m/0/2147483647H",
             'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a',
             'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9'],
            ["m/0/2147483647H/1",
             'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon',
             'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef'],
            ["m/0/2147483647H/1/2147483646H",
             'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',
             'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc'],
            ["m/0/2147483647H/1/2147483646H/2",
             'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt',
             'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j']
        ]


        for i, test_vector in enumerate([test_vectors1, test_vectors2]):
            mk = masters[i]
            for tv in test_vector:
                path, xpub, xprv = tv
                pubpath = "M" + path[1:]
                self.assertEqual(
                        bip32_path(mk, path), 
                        xprv,
                        "Test vector PRIVKEY derivation does not match. Details: \n%s\n%s\n\%s" % (
                            path, 
                            [safe_hexlify(x) if isinstance(x, str) else x for x in bip32_deserialize(bip32_path(mk, path))],
                            [safe_hexlify(x) if isinstance(x, str) else x for x in bip32_deserialize(xprv)]
                        )
                )
                self.assertEqual(
                        bip32_path(mk, pubpath),
                        xpub,
                        "Test vector PUBKEY derivation does not match. Details: \n%s\n%s\n\%s" % (
                            pubpath, 
                            [safe_hexlify(x) if isinstance(x, str) else x for x in bip32_deserialize(bip32_path(mk, pubpath))],
                            [safe_hexlify(x) if isinstance(x, str) else x for x in bip32_deserialize(xpub)]
                        )
                )

    def test_all_testnet(self):
        test_vectors = [
            ["m/", 'tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m'],
            ['m/.pub', 'tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp'],
            ["m/0H", 'tprv8bxNLu25VazNnppTCP4fyhyCvBHcYtzE3wr3cwYeL4HA7yf6TLGEUdS4QC1vLT63TkjRssqJe4CvGNEC8DzW5AoPUw56D1Ayg6HY4oy8QZ9'],
            ["m/0H/1", 'tprv8e8VYgZxtHsSdGrtvdxYaSrryZGiYviWzGWtDDKTGh5NMXAEB8gYSCLHpFCywNs5uqV7ghRjimALQJkRFZnUrLHpzi2pGkwqLtbubgWuQ8q'],
            ["m/0H/2H/0", 'tprv8fhZcx1TVPVdmgHA2FofY9QTZMo74pN3vHRBJGxMYCnkpSjWcu95657gPUf4rhoRZKvT5EfVMVuPe1eZ3845WpEzBFRMXVwtxuGEruHbcFv'],
            ["m/0H/2H/2/1000000000.pub", 'tpubDEKHvatSC1pPvYsPGuhmQkT8YWZ8Ln25jxRzfwgs1ysJsVCHkis2UXsxntQUsDmuuvXuKTGJZFU9TCkNdbPKQpik2oSqccMCRVRpoWDsVRv']
        ]

        mk = bip32_master_key(safe_unhexlify('000102030405060708090a0b0c0d0e0f'), TESTNET_PRIVATE)

        for tv in test_vectors:
            path, result = tv[0], tv[1]
            self.assertEqual(
                bip32_ckd(mk, path),
                result,
                "Test vector does not match. Details:\n%s\n%s\n%s\n\%s" % (
                    path,
                    result,
                    [x.encode('hex') if isinstance(x, str) else x for x in bip32_deserialize(bip32_ckd(mk, path))],
                    [x.encode('hex') if isinstance(x, str) else x for x in bip32_deserialize(result)],
                )
            )

    def test_extra(self):
        master = bip32_master_key(safe_unhexlify("000102030405060708090a0b0c0d0e0f"))

        path = "m/0"
        pubpath = "M" + path[1:]
        assert bip32_ckd(master, "0") == bip32_path(master, path)
        #"xprv9uHRZZhbkedL37eZEnyrNsQPFZYRAvjy5rt6M1nbEkLSo378x1CQQLo2xxBvREwiK6kqf7GRNvsNEchwibzXaV6i5GcsgyjBeRguXhKsi4R"
        assert bip32_privtopub(bip32_ckd(master, "0")) == bip32_path(master, pubpath)
        #"xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1"

        path = "m/1"
        pubpath = "M" + path[1:]
        assert bip32_ckd(master, "1") == bip32_path(master, path)
        #"xprv9uHRZZhbkedL4yTpidDvuVfrdUkTbhDHviERRBkbzbNDZeMjWzqzKAdxWhzftGDSxDmBdakjqHiZJbkwiaTEXJdjZAaAjMZEE3PMbMrPJih"
        assert bip32_privtopub(bip32_ckd(master, "1")) == bip32_path(master, pubpath)
        #"xpub68Gmy5EVb2BdHTYHpekwGdcbBWax19w9HwA2DaADYvuCSSgt4YAErxxSN1KWSnmyqkwRNbnTj3XiUBKmHeC8rTjLRPjSULcDKQQgfgJDppq"

        path = "m/0/0"
        pubpath = "M" + path[1:]
        assert bip32_ckd(bip32_ckd(master, "0"), "0") == bip32_path(master, path)
        #"xprv9ww7sMFLzJMzur2oEQDB642fbsMS4q6JRraMVTrM9bTWBq7NDS8ZpmsKVB4YF3mZecqax1fjnsPF19xnsJNfRp4RSyexacULXMKowSACTRc"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, "0"), "0")) == bip32_path(master, pubpath)
        #"xpub6AvUGrnEpfvJ8L7GLRkBTByQ9uBvUHp9o5VxHrFxhvzV4dSWkySpNaBoLR9FpbnwRmTa69yLHF3QfcaxbWT7gWdwws5k4dpmJvqpEuMWwnj"

        path = "m/0'"
        pubpath = "M" + path[1:]
        assert bip32_ckd(master, 2**31) == bip32_path(master, path)
        #"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        assert bip32_privtopub(bip32_ckd(master, 2**31)) == bip32_path(master, pubpath)
        #"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

        path = "m/1'"
        pubpath = "M" + path[1:]
        assert bip32_ckd(master, 2**31 + 1) == bip32_path(master, path)
        #"xprv9uHRZZhk6KAJFszJGW6LoUFq92uL7FvkBhmYiMurCWPHLJZkX2aGvNdRUBNnJu7nv36WnwCN59uNy6sxLDZvvNSgFz3TCCcKo7iutQzpg78"
        assert bip32_privtopub(bip32_ckd(master, 2**31 + 1)) == bip32_path(master, pubpath)
        #"xpub68Gmy5EdvgibUN4mNXdMAcCZh4jpWiebYvh9WkKTkqvGD6tu4ZtXUAwuKSyF5DFZVmotf9UHFTGqSXo9qyDBSn47RkaN6Aedt9JbL7zcgSL"

        path = "m/0'/0"
        pubpath = "M" + path[1:]
        assert bip32_ckd(bip32_ckd(master, 2**31), "0") == bip32_path(master, path)
        #"xprv9wTYmMFdV23N21MM6dLNavSQV7Sj7meSPXx6AV5eTdqqGLjycVjb115Ec5LgRAXscPZgy5G4jQ9csyyZLN3PZLxoM1h3BoPuEJzsgeypdKj"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, 2 ** 31), "0")) == bip32_path(master, pubpath)
        #"xpub6ASuArnXKPbfEVRpCesNx4P939HDXENHkksgxsVG1yNp9958A33qYoPiTN9QrJmWFa2jNLdK84bWmyqTSPGtApP8P7nHUYwxHPhqmzUyeFG"

        path = "m/0'/0'"
        pubpath = "M" + path[1:]
        assert bip32_ckd(bip32_ckd(master, 2**31), 2**31) == bip32_path(master, path)
        #"xprv9wTYmMFmpgaLB5Hge4YtaGqCKpsYPTD9vXWSsmdZrNU3Y2i4WoBykm6ZteeCLCCZpGxdHQuqEhM6Gdo2X6CVrQiTw6AAneF9WSkA9ewaxtS"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, 2**31), 2**31)) == bip32_path(master, pubpath)
        #"xpub6ASuArnff48dPZN9k65twQmvsri2nuw1HkS3gA3BQi12Qq3D4LWEJZR3jwCAr1NhsFMcQcBkmevmub6SLP37bNq91SEShXtEGUbX3GhNaGk"

        path = "m/44'/0'/0'/0/0"
        pubpath = "M" + path[1:]
        assert bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(master, 44 + 2**31), 2**31), 2**31), 0), 0) == bip32_path(master, path)
        #"xprvA4A9CuBXhdBtCaLxwrw64Jaran4n1rgzeS5mjH47Ds8V67uZS8tTkG8jV3BZi83QqYXPcN4v8EjK2Aof4YcEeqLt688mV57gF4j6QZWdP9U"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(master, 44 + 2**31), 2**31), 2**31), 0), 0)) == bip32_path(master, pubpath)
        #"xpub6H9VcQiRXzkBR4RS3tU6RSXb8ouGRKQr1f1NXfTinCfTxvEhygCiJ4TDLHz1dyQ6d2Vz8Ne7eezkrViwaPo2ZMsNjVtFwvzsQXCDV6HJ3cV"


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
            #digest = ripemd.RIPEMD160(s).digest()
            digest = RIPEMD160(s).digest()
            hash160digest = RIPEMD160(bin_sha256(s)).digest()
            #hash160digest = ripemd.RIPEMD160(bin_sha256(s)).digest()
            self.assertEqual(safe_hexlify(digest), target[i])
            self.assertEqual(safe_hexlify(hash160digest), hash160target[i])
            self.assertEqual(safe_hexlify(bin_hash160(from_str_to_bytes(s))), hash160target[i])
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

class TestBIP39English(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print('Testing BIP39 ENGLISH vectors')

    def test_all(self):

        with open("tests/test_EN_BIP39.json", "r") as fo:
            BIP39_VECTORS = json.loads(fo.read())

        for v in BIP39_VECTORS:
            mnem, pwd, entropy, seed, xprv = v['mnemonic'], v['passphrase'], \
                                             v['entropy'], v['seed'], v['bip32_xprv']
            self.assertEqual(bip39_detect_lang(mnem), 'english', "English language detection failed")
            self.assertTrue( bip39_check(mnem))
            self.assertEqual(bip39_to_mn(entropy), mnem, "Mnemonic ==> Entropy failure")
            self.assertEqual(bip39_to_seed(mnem, pwd), seed)
            self.assertEqual(bip32_master_key(safe_unhexlify(seed)), xprv)

class TestBIP39Jap(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print('Testing BIP39 JAPANESE vectors')

    def test_all(self):

        with open("tests/test_JP_BIP39.json", "r") as fo:
            BIP39_VECTORS = json.loads(fo.read())

        for v in BIP39_VECTORS:
            mnem, pwd, entropy, seed, xprv = v['mnemonic'], v['passphrase'], \
                                             v['entropy'], v['seed'], v['bip32_xprv']
            self.assertEqual(bip39_detect_lang(mnem), 'japanese', "Japanese language detection failed")
            self.assertTrue( bip39_check(mnem))
            self.assertEqual(bip39_to_mn(entropy, lang='japanese'), mnem, "Mnemonic ==> Entropy failure")
            self.assertEqual(bip39_to_seed(mnem, pwd), seed)
            self.assertEqual(bip32_master_key(safe_unhexlify(seed)), xprv)


class TestPBKDF2HMACSHA512(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("Testing PBKDF2 HMAC SHA512....")

    def test_all(self):

        strpass = ("password", "password", "password", "passwordPASSWORDpassword")
        strsalt = ("salt", "salt", "salt", "saltSALTsaltSALTsaltSALTsaltSALTsalt")
        strcount = (1, 2, 4096, 4096)
        strdklen = (64, 64, 64, 64)
        strhash = (b'867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce', b'e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e', b'd197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5', b'8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8')

        for v in zip(strpass, strsalt, strcount, strdklen, strhash):
            password, salt, count, dklen, hash = v
            res = safe_hexlify(bin_pbkdf2_hmac("sha512", password, salt, count, dklen))
            self.assertEqual(res, hash)

class BitcoinCore_SignatureValidation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("Testing BitcoinCore signatures")

    def test_all(self):

        with open("tests/signmessage.json", "r") as fo:
            SIG_TESTS = json.loads(fo.read())

        for test in SIG_TESTS:
            #pass	# FIXME: testing
            pkwif, sig, addr = str(test['wif']), str(test['signature']), str(test['address'])
            pubkey = privtopub(pkwif)
            pub_recovered = ecdsa_recover(addr, sig)
            self.assertEqual(
                pubkey,
                pub_recovered,
                "Sig's pubkey: %s\nRecovered pubkey:%s" % (pubkey, pub_recovered)
            )

class BitcoinCore_Base58_encode_decode(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("Testing BitcoinCore Base58 Encode/Decode vectors")

    def test_all(self):

        with open("tests/base58_encode_decode.json", "r") as fo:
            BASE58_TESTS = json.loads(fo.read())

        for test in BASE58_TESTS:
            base16, base58 = test
            result_from_hex = changebase(base16, 16, 58)
            result_to_hex = changebase(base58, 58, 16)
            self.assertEqual(
                result_from_hex,
                base58,
                "Calculated: %s\nResult:%s" % (result_from_hex, base58)
            )
            self.assertEqual(
                result_to_hex,
                base16,
                "Calculated: %s\nResult:%s" % (result_to_hex, base16)
            )

class Test_DER_Sigs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("Testing DER Signatures....")

    def test_all(self):

        str_r = (0x123456,)
        str_s = (0x89abcd,)
        str_v = tuple([0] * len(str_r))
        str_der = (b'300b020312345602040089abcd', )

        for t in zip(str_v, str_r, str_s, str_der):
            v, r, s, dersig = t
            self.assertEqual(der_encode_sig(v,r,s), dersig)


class BitcoinCore_TransactionValid(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("Testing BitcoinCore Transactions (Valid)")

    def test_all(self):

        def parse_script(s):

            def ishex(s):
                return set(s).issubset(set('0123456789abcdefABCDEF'))

            r = []
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
                elif word in OPname:
                    r.append(OPname[word])  # r.append(get_op(v[3:]))
                else:
                    raise ValueError("could not parse script! (word=\t%s)" % str(word))

            try:
                sc = serialize_script(r)
            except:
                sys.stderr.write("Didnt work!\nr = %s" % repr(r))
                sc = r
            return sc

        def load_tvv():
            with open('tests/tx_valid.json', 'r') as fo:
                for tv in json.load(fo):
                    if len(tv) == 1:
                        continue
                    assert len(tv) == 3

                    prevouts = {}
                    for json_prevout in tv[0]:
                        assert len(json_prevout) == 3
                        n = 0xffffffff if json_prevout[1] == -1 else json_prevout[1]
                        prevout = "%s:%d" % (json_prevout[0], n)
                        prevouts[prevout] = parse_script(json_prevout[2])

                    tx = str(tv[1])
                    flags = tv[2]

                    yield (prevouts, tx, flags)

        for i, (po, tx, flags) in enumerate(load_tvv()):
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
                # calculated = get_outpoints(txh, i)
                # actual = "%s:%d" % (prevout_txin, prevout_vout)
                # self.assertEqual(actual, calculated, "get_outpoint at index %d failed" % int(i))
                # #assert actual == calculated

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
    unittest.main()                    import unittest

from bitcoin import *
from bitcoin.mnemonic import *
from bitcoin.deterministic import *
from bitcoin.utils import *

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
            seed = sha256(str(random.randrange(2**40)))[:32]
            mpk = electrum_mpubk(seed)
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


# class TestElectrumSignVerify(unittest.TestCase):
#     """Requires Electrum."""
#
#     @classmethod
#     def setUpClass(cls):
#         cls.wallet = "/tmp/tempwallet_" + str(random.randrange(2**40))
#         print("Starting wallet tests with: " + cls.wallet)
#         os.popen('echo "\n\n\n\n\n\n" | electrum -w %s create' % cls.wallet).read()
#         cls.seed = str(json.loads(os.popen("electrum -w %s getseed" % cls.wallet).read())['seed'])
#         cls.addies = json.loads(os.popen("electrum -w %s listaddresses" % cls.wallet).read())
#
#     def test_address(self):
#         for i in range(5):
#             self.assertEqual(
#                 self.addies[i],
#                 electrum_address(self.seed, i, 0),
#                 "Address does not match! Details:\nseed %s, i: %d" % (self.seed, i)
#             )
#
#     def test_sign_verify(self):
#         print("Electrum-style signing and verification tests, against actual Electrum")
#         alphabet = "1234567890qwertyuiopasdfghjklzxcvbnm"
#         for i in range(8):
#             msg = ''.join([random.choice(alphabet) for i in range(random.randrange(20, 200))])
#             addy = random.choice(self.addies)
#             wif = os.popen('electrum -w %s dumpprivkey %s' % (self.wallet, addy)).readlines()[-2].replace('"', '').strip()
#             priv = b58check_to_hex(wif)
#             pub = privtopub(priv)
#
#             sig = os.popen('electrum -w %s signmessage %s %s' % (self.wallet, addy, msg)).readlines()[-1].strip()
#             self.assertTrue(
#                 ecdsa_verify(msg, sig, pub),
#                 "Verification error. Details:\nmsg: %s\nsig: %s\npriv: %s\naddy: %s\npub: %s" % (
#                     msg, sig, priv, addy, pub
#                 )
#             )
#
#             rec = ecdsa_recover(msg, sig)
#             self.assertEqual(
#                 pub,
#                 rec,
#                 "Recovery error. Details:\nmsg: %s\nsig: %s\npriv: %s\naddy: %s\noriginal pub: %s, %s\nrecovered pub: %s" % (
#                     msg, sig, priv, addy, pub, decode_pubkey(pub, 'hex')[1], rec
#                 )
#             )
#
#             mysig = ecdsa_sign(msg, priv)
#             self.assertEqual(
#                 os.popen('electrum -w %s verifymessage %s %s %s' % (self.wallet, addy, mysig, msg)).read().strip(),
#                 "true",
#                 "Electrum verify message does not match"
#             )


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
        tx = '0100000001239f932c780e517015842f3b02ff765fba97f9f63f9f1bc718b686a56ed9c73400000000' \
             'fd5d010047304402200c40fa58d3f6d5537a343cf9c8d13bc7470baf1d13867e0de3e535cd6b4354c8' \
             '02200f2b48f67494835b060d0b2ff85657d2ba2d9ea4e697888c8cb580e8658183a801483045022056' \
             'f488c59849a4259e7cef70fe5d6d53a4bd1c59a195b0577bd81cb76044beca022100a735b319fa66af' \
             '7b178fc719b93f905961ef4d4446deca8757a90de2106dd98a014cc95241046c7d87fd72caeab48e93' \
             '7f2feca9e9a4bd77f0eff4ebb2dbbb9855c023e334e188d32aaec4632ea4cbc575c037d8101aec73d0' \
             '29236e7b1c2380f3e4ad7edced41046fd41cddf3bbda33a240b417a825cc46555949917c7ccf64c59f' \
             '42fd8dfe95f34fae3b09ed279c8c5b3530510e8cca6230791102eef9961d895e8db54af0563c410488' \
             'd618b988efd2511fc1f9c03f11c210808852b07fe46128c1a6b1155aa22cdf4b6802460ba593db2d11' \
             'c7e6cbe19cedef76b7bcabd05d26fd97f4c5a59b225053aeffffffff0310270000000000001976a914' \
             'a89733100315c37d228a529853af341a9d290a4588ac409c00000000000017a9142b56f9a4009d9ff9' \
             '9b8f97bea4455cd71135f5dd87409c00000000000017a9142b56f9a4009d9ff99b8f' \
             '97bea4455cd71135f5dd8700000000'
        self.assertEqual(
            serialize(deserialize(tx)),
            tx,
            "Serialize roundtrip failed"
        )

    def test_serialize_script(self):
        hexvals = [encode(random.randrange(0, 0xffff), 16, 4) for x in range(20)]
        script = '47304402200c40fa58d3f6d5537a343cf9c8d13bc7470baf1d13867e0de3e535cd6b4354c80220' \
                 '0f2b48f67494835b060d0b2ff85657d2ba2d9ea4e697888c8cb580e8658183a801483045022056' \
                 'f488c59849a4259e7cef70fe5d6d53a4bd1c59a195b0577bd81cb76044beca022100a735b319fa' \
                 '66af7b178fc719b93f905961ef4d4446deca8757a90de2106dd98a014cc95241046c7d87fd72ca' \
                 'eab48e937f2feca9e9a4bd77f0eff4ebb2dbbb9855c023e334e188d32aaec4632ea4cbc575c037' \
                 'd8101aec73d029236e7b1c2380f3e4ad7edced41046fd41cddf3bbda33a240b417a825cc465559' \
                 '49917c7ccf64c59f42fd8dfe95f34fae3b09ed279c8c5b3530510e8cca6230791102eef9961d89' \
                 '5e8db54af0563c410488d618b988efd2511fc1f9c03f11c210808852b07fe46128c1a6b1155aa2' \
                 '2cdf4b6802460ba593db2d11c7e6cbe19cedef76b7bcabd05d26fd97f4c5a59b225053ae'
        self.assertEqual(
            serialize_script(deserialize_script(script)),
            script,
            "Script serialize roundtrip failed"
        )
        for v in hexvals:
            self.assertEqual(
                deserialize_script(serialize_script([v])),
                [v],
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
        self.assertEqual(mscript, mk_multisig_script(pubs[1:], 2), "Implicit n=3 error")
        msigaddr = p2sh_scriptaddr(mscript)
        tx = mktx(['01'*32+':1', '23'*32+':2'], 
                  [msigaddr+':20202', addresses[0]+':40404'], 
                  locktime=2222222222
                  )

        tx1 = sign(tx, 1, privs[0])

        self.assertEqual(deserialize(tx)['locktime'], 2222222222, "Locktime incorrect")

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

    def test_preparetx(self):
        try:
            hextx = preparetx('12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX', '1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1', 13)
        except:
            hextx = '01000000011c73efeb6333e673e34aec19b484ace0bd59384a47e112cb2a003732cae0eb360100000000' \
                    'ffffffff020d000000000000001976a914b3407d4b4d1fca87fb930abe3fa6c2baed6e6fd888ac835f01' \
                    '00000000001976a914119b098e2e980a229e139a9ed01a469e518e6f2688ac00000000'
        tx = deserialize(hextx)
        self.assertEqual(tx['locktime'], 0, "Locktime incorrect")
        self.assertEqual(tx['outs'][0]['value'], 13, "Value incorrect")

#        hextx = preparetx('12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX', '1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1', 13, locktime=2222222222)
#        tx = deserialize(hextx)
#        self.assertEqual(tx['locktime'], 2222222222, "Locktime incorrect")
#        self.assertEqual(tx['outs'][0]['value'], 13, "Value incorrect")

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

    def test_all(self):

        hexmasters = ['000102030405060708090a0b0c0d0e0f',
                   'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2' \
                   '9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542']

        masters = map(lambda k: bip32_master_key(safe_unhexlify(k)), hexmasters)

        # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1
        test_vectors1 = [
           #[ path, xpub, xprv]
            ["m/",
             'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
             'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'],
            ["m/0H",
             'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
             'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'],
            ["m/0H/1",
             'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
             'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'],
            ["m/0H/1/2H",
             'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
             'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'],
            ["m/0H/1/2H/2",
             'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',
             'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334'],
            ["m/0H/1/2H/2/1000000000",
             'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
             'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76']
        ]

        # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-2
        test_vectors2 = [
            # [ path, xpub, xprv]
            ["m/",
             'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',
             'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U'],
            ["m/0",
             'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',
             'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt'],
            ["m/0/2147483647H",
             'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a',
             'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9'],
            ["m/0/2147483647H/1",
             'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon',
             'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef'],
            ["m/0/2147483647H/1/2147483646H",
             'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',
             'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc'],
            ["m/0/2147483647H/1/2147483646H/2",
             'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt',
             'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j']
        ]


        for i, test_vector in enumerate([test_vectors1, test_vectors2]):
            mk = masters[i]
            for tv in test_vector:
                path, xpub, xprv = tv
                pubpath = path + ".pub"
                self.assertEqual(
                        bip32_path(mk, path), 
                        xprv,
                        "Test vector PRIVKEY derivation does not match. Details: \n%s\n%s\n\%s" % (
                            path, 
                            [safe_hexlify(x) if isinstance(x, str) else x for x in bip32_deserialize(bip32_path(mk, path))],
                            [safe_hexlify(x) if isinstance(x, str) else x for x in bip32_deserialize(xprv)]
                        )
                )
                self.assertEqual(
                        bip32_path(mk, pubpath),
                        xpub,
                        "Test vector PUBKEY derivation does not match. Details: \n%s\n%s\n\%s" % (
                            pubpath, 
                            [safe_hexlify(x) if isinstance(x, str) else x for x in bip32_deserialize(bip32_path(mk, pubpath))],
                            [safe_hexlify(x) if isinstance(x, str) else x for x in bip32_deserialize(xpub)]
                        )
                )

    def test_all_testnet(self):
        test_vectors = [
            ["m/", 'tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m'],
            ['m/.pub', 'tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp'],
            ["m/0H", 'tprv8bxNLu25VazNnppTCP4fyhyCvBHcYtzE3wr3cwYeL4HA7yf6TLGEUdS4QC1vLT63TkjRssqJe4CvGNEC8DzW5AoPUw56D1Ayg6HY4oy8QZ9'],
            ["m/0H/1", 'tprv8e8VYgZxtHsSdGrtvdxYaSrryZGiYviWzGWtDDKTGh5NMXAEB8gYSCLHpFCywNs5uqV7ghRjimALQJkRFZnUrLHpzi2pGkwqLtbubgWuQ8q'],
            ["m/0H/2H/0", 'tprv8fhZcx1TVPVdmgHA2FofY9QTZMo74pN3vHRBJGxMYCnkpSjWcu95657gPUf4rhoRZKvT5EfVMVuPe1eZ3845WpEzBFRMXVwtxuGEruHbcFv'],
            ["m/0H/2H/2/1000000000.pub", 'tpubDEKHvatSC1pPvYsPGuhmQkT8YWZ8Ln25jxRzfwgs1ysJsVCHkis2UXsxntQUsDmuuvXuKTGJZFU9TCkNdbPKQpik2oSqccMCRVRpoWDsVRv']
        ]

        mk = bip32_master_key(safe_unhexlify('000102030405060708090a0b0c0d0e0f'), TESTNET_PRIVATE)

        for tv in test_vectors:
            path, result = tv[0], tv[1]
            self.assertEqual(
                bip32_ckd(mk, path),
                result,
                "Test vector does not match. Details:\n%s\n%s\n%s\n\%s" % (
                    path,
                    result,
                    [x.encode('hex') if isinstance(x, str) else x for x in bip32_deserialize(bip32_ckd(mk, path))],
                    [x.encode('hex') if isinstance(x, str) else x for x in bip32_deserialize(result)],
                )
            )

    def test_extra(self):
        master = bip32_master_key(safe_unhexlify("000102030405060708090a0b0c0d0e0f"))

        path = "m/0"
        pubpath = path + ".pub"
        assert bip32_ckd(master, "0") == bip32_ckd(master, path)
        #"xprv9uHRZZhbkedL37eZEnyrNsQPFZYRAvjy5rt6M1nbEkLSo378x1CQQLo2xxBvREwiK6kqf7GRNvsNEchwibzXaV6i5GcsgyjBeRguXhKsi4R"
        assert bip32_privtopub(bip32_ckd(master, "0")) == bip32_ckd(master, pubpath)
        #"xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1"

        path = "m/1"
        pubpath = path+ ".pub"
        assert bip32_ckd(master, "1") == bip32_ckd(master, path)
        #"xprv9uHRZZhbkedL4yTpidDvuVfrdUkTbhDHviERRBkbzbNDZeMjWzqzKAdxWhzftGDSxDmBdakjqHiZJbkwiaTEXJdjZAaAjMZEE3PMbMrPJih"
        assert bip32_privtopub(bip32_ckd(master, "1")) == bip32_ckd(master, pubpath)
        #"xpub68Gmy5EVb2BdHTYHpekwGdcbBWax19w9HwA2DaADYvuCSSgt4YAErxxSN1KWSnmyqkwRNbnTj3XiUBKmHeC8rTjLRPjSULcDKQQgfgJDppq"

        path = "m/0/0"
        pubpath = path + ".pub"
        assert bip32_ckd(bip32_ckd(master, "0"), "0") == bip32_ckd(master, path)
        #"xprv9ww7sMFLzJMzur2oEQDB642fbsMS4q6JRraMVTrM9bTWBq7NDS8ZpmsKVB4YF3mZecqax1fjnsPF19xnsJNfRp4RSyexacULXMKowSACTRc"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, "0"), "0")) == bip32_ckd(master, pubpath)
        #"xpub6AvUGrnEpfvJ8L7GLRkBTByQ9uBvUHp9o5VxHrFxhvzV4dSWkySpNaBoLR9FpbnwRmTa69yLHF3QfcaxbWT7gWdwws5k4dpmJvqpEuMWwnj"

        path = "m/0'"
        pubpath = path + ".pub"
        assert bip32_ckd(master, 2**31) == bip32_ckd(master, path)
        #"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        assert bip32_privtopub(bip32_ckd(master, 2**31)) == bip32_ckd(master, pubpath)
        #"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

        path = "m/1'"
        pubpath = path + ".pub"
        assert bip32_ckd(master, 2**31 + 1) == bip32_ckd(master, path)
        #"xprv9uHRZZhk6KAJFszJGW6LoUFq92uL7FvkBhmYiMurCWPHLJZkX2aGvNdRUBNnJu7nv36WnwCN59uNy6sxLDZvvNSgFz3TCCcKo7iutQzpg78"
        assert bip32_privtopub(bip32_ckd(master, 2**31 + 1)) == bip32_ckd(master, pubpath)
        #"xpub68Gmy5EdvgibUN4mNXdMAcCZh4jpWiebYvh9WkKTkqvGD6tu4ZtXUAwuKSyF5DFZVmotf9UHFTGqSXo9qyDBSn47RkaN6Aedt9JbL7zcgSL"

        path = "m/1'"
        pubpath = path + ".pub"
        assert bip32_ckd(master, 1 + 2**31) == bip32_ckd(master, path)
        #"xprv9uHRZZhk6KAJFszJGW6LoUFq92uL7FvkBhmYiMurCWPHLJZkX2aGvNdRUBNnJu7nv36WnwCN59uNy6sxLDZvvNSgFz3TCCcKo7iutQzpg78"
        assert bip32_privtopub(bip32_ckd(master, 1 + 2**31)) == bip32_ckd(master, pubpath)
        #"xpub68Gmy5EdvgibUN4mNXdMAcCZh4jpWiebYvh9WkKTkqvGD6tu4ZtXUAwuKSyF5DFZVmotf9UHFTGqSXo9qyDBSn47RkaN6Aedt9JbL7zcgSL"

        path = "m/0'/0"
        pubpath = path + ".pub"
        assert bip32_ckd(bip32_ckd(master, 2**31), "0") == bip32_ckd(master, path)
        #"xprv9wTYmMFdV23N21MM6dLNavSQV7Sj7meSPXx6AV5eTdqqGLjycVjb115Ec5LgRAXscPZgy5G4jQ9csyyZLN3PZLxoM1h3BoPuEJzsgeypdKj"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, 2 ** 31), "0")) == bip32_ckd(master, pubpath)
        #"xpub6ASuArnXKPbfEVRpCesNx4P939HDXENHkksgxsVG1yNp9958A33qYoPiTN9QrJmWFa2jNLdK84bWmyqTSPGtApP8P7nHUYwxHPhqmzUyeFG"

        path = "m/0'/0'"
        pubpath = path + ".pub"
        assert bip32_ckd(bip32_ckd(master, 2**31), 2**31) == bip32_ckd(master, path)
        #"xprv9wTYmMFmpgaLB5Hge4YtaGqCKpsYPTD9vXWSsmdZrNU3Y2i4WoBykm6ZteeCLCCZpGxdHQuqEhM6Gdo2X6CVrQiTw6AAneF9WSkA9ewaxtS"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(master, 2**31), 2**31)) == bip32_ckd(master, pubpath)
        #"xpub6ASuArnff48dPZN9k65twQmvsri2nuw1HkS3gA3BQi12Qq3D4LWEJZR3jwCAr1NhsFMcQcBkmevmub6SLP37bNq91SEShXtEGUbX3GhNaGk"

        path = "m/44'/0'/0'/0/0"
        pubpath = path + ".pub"
        assert bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(master, 44 + 2**31), 2**31), 2**31), 0), 0) == bip32_ckd(master, path)
        #"xprvA4A9CuBXhdBtCaLxwrw64Jaran4n1rgzeS5mjH47Ds8V67uZS8tTkG8jV3BZi83QqYXPcN4v8EjK2Aof4YcEeqLt688mV57gF4j6QZWdP9U"
        assert bip32_privtopub(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(bip32_ckd(master, 44 + 2**31), 2**31), 2**31), 0), 0)) == bip32_path(master, pubpath)
        #"xpub6H9VcQiRXzkBR4RS3tU6RSXb8ouGRKQr1f1NXfTinCfTxvEhygCiJ4TDLHz1dyQ6d2Vz8Ne7eezkrViwaPo2ZMsNjVtFwvzsQXCDV6HJ3cV"


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
            #digest = ripemd.RIPEMD160(s).digest()
            digest = RIPEMD160(s).digest()
            hash160digest = RIPEMD160(bin_sha256(s)).digest()
            #hash160digest = ripemd.RIPEMD160(bin_sha256(s)).digest()
            self.assertEqual(safe_hexlify(digest), target[i])
            self.assertEqual(safe_hexlify(hash160digest), hash160target[i])
            self.assertEqual(safe_hexlify(bin_hash160(from_str_to_bytes(s))), hash160target[i])
            self.assertEqual(hash160(from_str_to_bytes(s)), hash160target[i])


class TestScriptVsAddressOutputs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print('Testing script vs address out
