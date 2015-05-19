#!/usr/bin/python
from bitcoin.main import *
#from bitcoin.pyspecials import *

# get wordlists

def open_wordlist(wordlist):
    try:
        if wordlist in ('Electrum1', 'electrum1', 'electrum'):
            from btc._electrum1wordlist import ELECTRUM1_WORDLIST
            assert len(ELECTRUM1_WORDLIST) == 1626
            return ELECTRUM1_WORDLIST
        elif wordlist in ('bip39', 'BIP39'):
            from btc._bip39wordlist import BIP0039_WORDLIST
            assert len(BIP0039_WORDLIST) == 2048
            return BIP0039_WORDLIST
    except: return None

def download_wordlist(wordlist):
    try:
        from btc.bci import make_request
        if wordlist in ('Electrum1', 'electrum1', 'electrum'):
            ELECTRUM1WORDS = make_request("https://gist.githubusercontent.com/anonymous" \
                  + "/f58f57780245db3cafc4/raw/1b5a9e81c0a356373e9e13aa720baef89d8fa856" \
                  + "/electrum1_english_words").decode('utf-8').strip().split()
            assert len(ELECTRUM1WORDS) == 1626
            return ELECTRUM1WORDS
        elif wordlist in ('bip39', 'BIP39'):
            BIP0039_WORDLIST = make_request("https://raw.githubusercontent.com" \
                                            + "/btc/bips/master/bip-0039/english.txt"
                                            ).decode('utf-8').strip().split('\n')
            assert len(BIP0039_WORDLIST) == 2048
            return BIP0039_WORDLIST
    except: return None

def bip39_hex_to_mnemonic(hexvalue):
    """
    Convert hex seed to BIP39 mnemonic
    https://github.com/btc/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic

    Essentially converts hex value to binary (with appended checksum),
    and splits into 11-bit binary chunks, each indexing a 2048 (=2**11)
    word list (in BIP39WORDS)

    hexseed: hexadecimal bytes or bytearray object

    >>> bip39_hex_to_mnemonic('eaebabb2383351fd31d703840b32e9e2')
    'turtle front uncle idea crush write shrug there lottery flower risk shell'
    """
    try:    BIP39WORDS = open_wordlist('bip39')
    except: BIP39WORDS = download_wordlist('bip39')
    if isinstance(hexvalue, string_or_bytes_types) and re.match('^[0-9a-fA-F]*$', from_bytestring_to_string(hexvalue)):
        hexvalue = from_string_to_bytes(hexvalue)
    else:
        raise TypeError("Enter a hex seed!")

    if len(hexvalue) % 4 != 0:
        raise Exception("Value not a multiple of 4 bytes!")
    elif len(hexvalue) not in range(4, 125, 4):
        raise Exception("32 < entropy < 992 bits only!")

    hexvalue = safe_unhexlify(hexvalue)
    cs = hashlib.sha256(hexvalue).hexdigest() # sha256 hexdigest
    bstr = (changebase( safe_hexlify(hexvalue), 16, 2, len(hexvalue)*8) +
		    changebase( cs, 16, 2, 256)[ : len(hexvalue) * 8 // 32])

    return " ".join( [BIP39WORDS[int(x, 2)] for x in
                      [bstr[i:i+11] for i in range(0, len(bstr), 11)] ] )

def bip39_mnemonic_to_hex(mnemonic, saltpass=None):
    """
    Convert BIP39 mnemonic to hex seed
    https://github.com/btc/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic

    mnemonic: single spaced, lower-case words

    >>>bip39_mnemonic_to_hex("board flee heavy tunnel powder denial science ski answer betray cargo cat")
    '18ab19a9f54a9274f03e5209a2ac8a91'
    """
    if isinstance(mnemonic, string_or_bytes_types):
        try:
            mn_string = st(mnemonic)
            mn_array = mnemonic.lower().strip().split(" ")
        except:
            raise TypeError("Bad mnemonic input. Enter lower case, string of words")
    elif isinstance(mnemonic, list):
        mn_array = map(st, mnemonic)
    else:   raise TypeError("Enter a lower case, single-spaced mnemonic!!")

    if len(mn_array) not in range(3, 124, 3):
        raise TypeError("32 < entropy < 992 bits; Input too big or too small")
    if len(mn_array) % 3 != 0:
        raise TypeError("Too many or too few words")
    #assert all(map(lambda x: x in BIP39WORDS, mnemonic_array)) # check all words are in list
    mnem = ' '.join(mn_array)

    try:
        assert bip39_check_mnemonic(mnem)
        seed = pbkdf2(mnem, 'mnemonic'+saltpass)
        return safe_hexlify(seed)
    except:
        raise IOError("Mnemonic checksum is bad!")

def bip39_check_mnemonic(mnemonic):
    """
    Assert mnemonic is BIP39 standard
    """
    try:    BIP39WORDS = open_wordlist('bip39')
    except: BIP39WORDS = download_wordlist('bip39')
    if isinstance(mnemonic, string_types):
        try:
            mn_array = from_string_to_bytes(mnemonic).lower().strip().split(" ")
        except:
            raise TypeError("Enter a lower case, single-spaced mnemonic!")
    else:   raise TypeError("Enter a lower case, single-spaced mnemonic!!")

    if len(mn_array) not in range(3, 124, 3):
        raise TypeError("32 < entropy < 992 bits; Input too big or too small")
    # if len(mn_array) % 3 != 0:
    #     raise TypeError("Too many or too few words")
    assert all(map(lambda x: x in BIP39WORDS, mn_array)) # check all words are in list

    try:    binstr = ''.join([ changebase(str(BIP39WORDS.index(x)), 10, 2, 11) for x in mn_array])
    except: raise IOError("Are the words in the right order?")

    L = len(binstr)
    bd = binstr[:L // 33 * 32]
    cs = binstr[-L // 33:]
    hexd = safe_unhexlify(changebase(bd, 2, 16, L // 33 * 8))
    hexd_cs = changebase(hashlib.sha256(hexd).hexdigest(), 16, 2, 256)[:L // 33]
    return cs == hexd_cs

def bip39_generate(bits=128):
    """Generates a tuple of (hex seed, mnemonic)"""
    if bits % 32 != 0:
        raise Exception('Should be divisible by 32, but is .. %d' % bits)
    seed = safe_hexlify(by(random_string(bits // 8)))
    return (seed, bip39_hex_to_mnemonic(seed))

def random_bip39_seed(bits=128):
    return bip39_generate(bits=bits)[0]

def random_bip39_mnemonic(bits=128):
    return bip39_generate(bits=bits)[1]

def electrum1_mnemonic_decode(mnemonic):
    """Decodes Electrum 1.x mnemonic phrase to hex seed"""
    try:    ELECTRUM1WORDS = open_wordlist('electrum1')
    except: ELECTRUM1WORDS = download_wordlist('electrum1')
    if isinstance(mnemonic, string_or_bytes_types):
        try: mn_array = from_string_to_bytes(mnemonic).lower().strip().split(" ")
        except: raise TypeError("Enter the Electrum 1.x mnemonic as a string")
    elif isinstance(mnemonic, list):
        mn_array = mnemonic[:]
    else:   raise TypeError("Bad input type")
    wlist, words, n = mn_array, ELECTRUM1WORDS, len(ELECTRUM1WORDS)
    # https://github.com/spesmilo/electrum/blob/1b6abf6e028cbabd5e125784cff6d4ada665e722/lib/old_mnemonic.py#L1672
    output = ''
    for i in range(len(wlist)/3):
        word1, word2, word3 = wlist[3*i:3*i+3]
        w1 =  words.index(word1)
        w2 = (words.index(word2))%n
        w3 = (words.index(word3))%n
        x = w1 +n*((w2-w1)%n) +n*n*((w3-w2)%n)
        output += '%08x'%x
    return output

def electrum1_mnemonic_encode(hexvalue):
    """Encodes a hex seed as Electrum 1.x mnemonic phrase"""
    try:    ELECTRUM1WORDS = open_wordlist('electrum1')
    except: ELECTRUM1WORDS = download_wordlist('electrum1')
    if isinstance(hexvalue, string_or_bytes_types) and re.match('^[0-9a-fA-F]*$', from_bytes_to_string(hexvalue)):
        hexvalue = from_string_to_bytes(hexvalue)
    else: raise TypeError("Enter a hex value!")
    message, words, n = hexvalue, ELECTRUM1WORDS, len(ELECTRUM1WORDS)
    # https://github.com/spesmilo/electrum/blob/1b6abf6e028cbabd5e125784cff6d4ada665e722/lib/old_mnemonic.py#L1660
    assert len(message) % 8 == 0
    out = []
    for i in range(len(message)/8):
        word = message[8*i:8*i+8]
        x = int(word, 16)
        w1 = (x%n)
        w2 = ((x/n) + w1)%n
        w3 = ((x/n/n) + w2)%n
        out += [ words[w1], words[w2], words[w3] ]
    return out
