#!/usr/bin/python
from bitcoin.main import *
from bitcoin.pyspecials import *    # safe_hexlify, from_string_to_bytes
import string, unicodedata, random, hmac, re


def get_wordlists():
    # Try to access local lists, otherwise download text lists
    # Return tuple of wordlists: (ELECTRUM, BIP39)
    try:
        from bitcoin._electrum1wordlist import ELECTRUM_WORDS as ELEC
        from bitcoin._bip39wordlist import BIP0039_WORDLIST as BIP39
    except ImportError:
        from bitcoin.bci import make_request
        ELEC, BIP39 = map(
            lambda u: make_request(u).strip().split(),
            ("https://gist.githubusercontent.com/anonymous/f58f57780245db3cafc4/raw/" \
                + "1b5a9e81c0a356373e9e13aa720baef89d8fa856/electrum1_english_words",
             "https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt"))
    assert (len(BIP39) == 2048 and len(ELEC) == 1626)
    return (ELEC, BIP39)

global _ELECTRUM_WORDS, _BIP39_WORDS
_ELECTRUM_WORDS, _BIP39_WORDS = get_wordlists()

# def open_wordlist(wordlist):
#     try:
#         if wordlist in ('Electrum1', 'electrum1', 'electrum'):
#             from bitcoin._electrum1wordlist import ELECTRUM_WORDLIST
#             assert len(ELECTRUM_WORDLIST) == 1626
#             return ELECTRUM_WORDLIST
#         elif wordlist in ('bip39', 'BIP39'):
#             from bitcoin._bip39wordlist import BIP0039_WORDLIST
#             assert len(BIP0039_WORDLIST) == 2048
#             return BIP0039_WORDLIST
#         else: raise Exception("Only Electrum1 & BIP39 supported")
#     except: raise IOError
# def download_wordlist(wordlist):
#     try:
#         from bitcoin.bci import make_request
#         if wordlist in ('Electrum1', 'electrum1', 'electrum'):
#             ELECTRUM1WORDS = make_request(
#                 "https://gist.githubusercontent.com/anonymous/f58f57780245db3cafc4/raw/"
#                 "1b5a9e81c0a356373e9e13aa720baef89d8fa856/electrum1_english_words").strip().split()
#             assert len(ELECTRUM1WORDS) == 1626
#             return ELECTRUM1WORDS
#         elif wordlist in ('bip39', 'BIP39'):
#             BIP0039_WORDLIST = make_request(
#                 "https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt").strip().split('\n')
#             assert len(BIP0039_WORDLIST) == 2048
#             return BIP0039_WORDLIST
#     except: raise IOError

def bip39_hex_to_mnemonic(hexvalue):
    """
    >>> bip39_hex_to_mnemonic('eaebabb2383351fd31d703840b32e9e2')
    'turtle front uncle idea crush write shrug there lottery flower risk shell'
    """
    if isinstance(hexvalue, string_or_bytes_types) and re.match('^[0-9a-fA-F]*$', hexvalue):
        hexvalue = from_string_to_bytes(hexvalue)
    else:
        raise TypeError("Enter a hex seed!")

    if len(hexvalue) % 4 != 0:
        raise Exception("Value not a multiple of 4 bytes!")
    elif len(hexvalue) not in range(4, 125, 4):
        raise Exception("32 < entropy < 992 bits only!")

    hexvalue = safe_unhexlify(hexvalue)
    cs = hashlib.sha256(hexvalue).hexdigest() # sha256 hexdigest
    bstr = (changebase( safe_hexlify(hexvalue), 16, 2, len(hexvalue)*8) + \
            changebase( cs, 16, 2, 256)[ : len(hexvalue) * 8 // 32])

    return " ".join( [_BIP39_WORDS[int(x, 2)] for x in
                      [bstr[i:i+11] for i in range(0, len(bstr), 11)] ] )

def bip39_mnemonic_to_hex(mnemonic, saltpass=None):
    """
    >>>bip39_mnemonic_to_hex("board flee heavy tunnel powder denial science ski answer betray cargo cat")
    '18ab19a9f54a9274f03e5209a2ac8a91'
    """
    if isinstance(mnemonic, string_or_bytes_types):
        mnemonic = st(mnemonic)
        mn_wordlist = mnemonic.lower().strip().split(" ")
    elif isinstance(mnemonic, list):
        mn_wordlist = list(map(st, mnemonic))
    else:   raise TypeError("Enter a lower case, single-spaced mnemonic (or list)!!")

    mnem = ' '.join(mn_wordlist)
    assert bip39_check(mnem)
    return pbkdf2_hmac_sha512(mnem, 'mnemonic'+saltpass)

def bip39_check(mnemonic):
    """Assert mnemonic is BIP39 standard"""
    if isinstance(mnemonic, string_or_bytes_types):
        mn_array = from_string_to_bytes(mnemonic).lower().strip().split(" ")
    elif isinstance(mnemonic, list):
        mn_array = mnemonic
    else: raise TypeError

    assert len(mn_array) in range(3, 124, 3)
    assert all(map(lambda x: x in _BIP39_WORDS, mn_array)) # check all words are in list

    binstr = ''.join([ changebase(str(_BIP39_WORDS.index(x)), 10, 2, 11) for x in mn_array])
    L = len(binstr)
    bd = binstr[:L // 33 * 32]
    cs = binstr[-L // 33:]
    hexd = safe_unhexlify(changebase(bd, 2, 16, L // 33 * 8))
    hexd_cs = changebase(hashlib.sha256(hexd).hexdigest(), 16, 2, 256)[:L // 33]
    return cs == hexd_cs

def random_bip39_pair(bits=128):
    """Generates a tuple of (hex seed, mnemonic)"""
    if bits%32 != 0: raise Exception('%d not divisible by 32! Try 128 bits' % bits)
    seed = safe_hexlify(by(random_string(bits // 8)))       # CHECK FOR PY3
    return (seed, bip39_hex_to_mnemonic(seed))

def random_bip39_seed(bits=128):
    return random_bip39_pair(bits)[0]

def random_bip39_mnemonic(bits=128):
    return random_bip39_pair(bits)[-1]

def electrum1_mn_decode(mnemonic):
    """Decodes Electrum 1.x mnemonic phrase to hex seed"""
    if isinstance(mnemonic, string_or_bytes_types):
        try: mn_wordlist = from_string_to_bytes(mnemonic).lower().strip().split(" ")
        except: raise TypeError("Enter the Electrum 1.x mnemonic as a string")
    elif isinstance(mnemonic, list):
        mn_wordlist = mnemonic
    else:   raise TypeError("Bad input: reqs mnemonic string")
    #
    #   https://github.com/spesmilo/electrum/blob/
    #       1b6abf6e028cbabd5e125784cff6d4ada665e722/lib/old_mnemonic.py#L1672
    wlist, words, n = mn_wordlist, _ELECTRUM_WORDS, 1626
    output = ''
    for i in range(len(wlist)//3):
        word1, word2, word3 = wlist[3*i:3*i+3]
        w1 =  words.index(word1)
        w2 = (words.index(word2))%n
        w3 = (words.index(word3))%n
        x = w1 +n*((w2-w1)%n) +n*n*((w3-w2)%n)
        output += '%08x'%x
    return output

def electrum1_mn_encode(hexstr):
    """Encodes a hex seed as Electrum 1.x mnemonic phrase"""
    if isinstance(hexstr, string_types) and re.match('^[0-9a-fA-F]*$', hexstr):
        hexstr = from_string_to_bytes(hexstr)
    else:
        raise TypeError("Bad input: hex string req!")
    message, words, n = hexstr, _ELECTRUM_WORDS, 1626
    assert len(message) % 8 == 0
    out = []
    for i in range(len(message)//8):
        word = message[8*i:8*i+8]
        x = int(word, 16)
        w1 = (x%n)
        w2 = ((x//n) + w1)%n
        w3 = ((x//n//n) + w2)%n
        out += [ words[w1], words[w2], words[w3] ]
    return ' '.join(out)

elec1_mn_decode = electrum1_mn_decode
elec1_mn_encode = electrum1_mn_encode

def electrum2_seed(num_bits=128, prefix='01', custom_entropy=1):
    # TODO: https://github.com/spesmilo/electrum/blob/feature/newsync/lib/bitcoin.py#L155
    import random, math
    assert num_bits in (128, 256) and '01' in prefix and custom_entropy >= 1
    n = int(math.ceil(math.log(custom_entropy, 2)))
    k = len(prefix)*4                            # amount of lost entropy from '01' req
    n_added = max(16, k + num_bits - n)          # 136 - lost = 128 bits entropy
    entropy = random.randrange(pow(2, n_added))  # decode(os.urandom((1+len("%x"%pow(2,n_added))//2)),256)
    nonce = 0
    while True:     # cycle thru values until HMAC == 0x01...cdef ...
        nonce += 1
        i = custom_entropy * (entropy + nonce)
        mn_seed = electrum2_mn_encode(i)
        assert i == electrum2_mn_decode(mn_seed)
        if is_elec1_seed(mn_seed): continue         # ensure seed NOT elec1 compatible
        if is_elec2_seed(mn_seed, prefix): break
    return mn_seed

def electrum2_mn_encode(i):
    n = len(_BIP39_WORDS)
    words = []
    while i:
        x = i%n
        i = i//n
        words.append(_BIP39_WORDS[x])
    return ' '.join(words)

def electrum2_mn_decode(mn_seed):
    words = mn_seed.split()
    wordlist = _BIP39_WORDS
    n = 2048
    i = 0
    while words:
        w = words.pop()
        k = wordlist.index(w)
        i = i*n + k
    return i

def electrum2_check_seed(mn_seed, custom_entropy):
    assert is_elec2_seed(mn_seed)
    i = electrum2_mn_decode(mn_seed)
    return i % custom_entropy == 0

elec2_mn_decode = electrum2_mn_decode
elec2_mn_encode = electrum2_mn_encode

def is_elec2_seed(seed, prefix='01'):
    hmac_sha_512 = lambda x, y: hmac.new(x, y, hashlib.sha512).hexdigest()
    s = hmac_sha_512('Seed version', seed)
    return s.startswith(prefix)

def is_elec1_seed(seed):
    mn_wordlist = seed.strip().split()
    is_hex = re.match('^[0-9a-fA-F]*$', seed) and len(seed) in (32, 64, 128)
    uses_electrum_words = True if electrum1_mn_decode(seed) is not None else False
    return is_hex or (uses_electrum_words and (len(mn_wordlist) == 12 or len(mn_wordlist) == 24))

def prepare_elec2_seed(seed):
    def is_CJK(c):
        # http://www.asahi-net.or.jp/~ax2s-kmtn/ref/unicode/e_asia.html
        CJK_INTERVALS = [(0x4E00, 0x9FFF, 'CJK Unified Ideographs'), (0x3400, 0x4DBF, 'CJK Unified Ideographs Extension A'), (0x20000, 0x2A6DF, 'CJK Unified Ideographs Extension B'), (0x2A700, 0x2B73F, 'CJK Unified Ideographs Extension C'), (0x2B740, 0x2B81F, 'CJK Unified Ideographs Extension D'), (0xF900, 0xFAFF, 'CJK Compatibility Ideographs'), (0x2F800, 0x2FA1D, 'CJK Compatibility Ideographs Supplement'), (0x3190, 0x319F , 'Kanbun'), (0x2E80, 0x2EFF, 'CJK Radicals Supplement'), (0x2F00, 0x2FDF, 'CJK Radicals'), (0x31C0, 0x31EF, 'CJK Strokes'), (0x2FF0, 0x2FFF, 'Ideographic Description Characters'), (0xE0100, 0xE01EF, 'Variation Selectors Supplement'), (0x3100, 0x312F, 'Bopomofo'), (0x31A0, 0x31BF, 'Bopomofo Extended'), (0xFF00, 0xFFEF, 'Halfwidth and Fullwidth Forms'), (0x3040, 0x309F, 'Hiragana'), (0x30A0, 0x30FF, 'Katakana'), (0x31F0, 0x31FF, 'Katakana Phonetic Extensions'), (0x1B000, 0x1B0FF, 'Kana Supplement'), (0xAC00, 0xD7AF, 'Hangul Syllables'), (0x1100, 0x11FF, 'Hangul Jamo'), (0xA960, 0xA97F, 'Hangul Jamo Extended A'), (0xD7B0, 0xD7FF, 'Hangul Jamo Extended B'), (0x3130, 0x318F, 'Hangul Compatibility Jamo'), (0xA4D0, 0xA4FF, 'Lisu'), (0x16F00, 0x16F9F, 'Miao'), (0xA000, 0xA48F, 'Yi Syllables'), (0xA490, 0xA4CF, 'Yi Radicals'),]
        n = ord(c)
        for i_min, i_max, name in CJK_INTERVALS:
            if n >= i_min and n <= i_max: return True
        return False
    # normalize
    seed = unicodedata.normalize('NFKD', unicode(seed)) \
        if is_python2 else unicodedata.normalize('NFKD', seed)
    seed = seed.lower()         # lower
    seed = u''.join([c for c in seed if not unicodedata.combining(c)])  # remove accents
    seed = u' '.join(seed.split())          # normalize whitespaces
    seed = u''.join([seed[i] for i in range(len(seed)) if not (seed[i]
                    in string.whitespace and is_CJK(seed[i-1]) and is_CJK(seed[i+1]))])
    return seed
