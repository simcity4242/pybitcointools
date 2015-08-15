#!/usr/bin/python
import string, unicodedata, random, hmac, re, math

from bitcoin.main import *
from bitcoin.pyspecials import *
try:
    from bitcoin._wordlists import WORDS
except ImportError:
    WORDS={}

LANGS = ["English", "Japanese", "Chinese_simplified", "Chinese_traditional", "Spanish", "French"]

def _get_directory():
    return os.path.join(os.path.dirname(__file__), 'wordlist')

def get_wordlists(lang=None):
    # Try to access local lists, otherwise download text lists
    # if any((listtype, lang)):
    from bitcoin.bci import make_request
    global WORDS
    if 'electrum' in str(lang.lower()): 
        WORDS['electrum1'] = make_request("http://tinyurl.com/electrum1words").strip().split()
        return [(k, v.pop(k, "")) for k,v in WORDS]
    bips_url = "https://github.com/bitcoin/bips/raw/master/bip-0039/%s.txt"
    WORDS['electrum1'],        WORDS['english'], WORDS['japanese'], WORDS['spanish'], \
    WORDS['chinese_simplified'], WORDS['chinese_traditional'], WORDS['french'] = map(
        lambda u: make_request(u).strip().split(),
        ("http://tinyurl.com/electrum1words",
         bips_url % 'english',
         bips_url % 'japanese',
         bips_url % 'spanish',
         bips_url % 'chinese_simplified',
         bips_url % 'chinese_traditional',
         bips_url % 'french'))
    assert map(lambda d: isinstance(d, list) and len(d), WORDS.values()).count(2048) == len(WORDS.keys()) - 1
    if lang is not None:
        return WORDS[lang.lower()]
    return WORDS

#ELECWORDS, BIP39ENG, BIP39JAP = WORDS['electrum1'], WORDS['english'], WORDS['japanese']

def bip39_detect_lang(mnem_str):
    # TODO: add Electrum1?, Chinese detect not possible?
    if isinstance(mnem_str, list):
        mnem_str = u' '.join(mnem_str)
    mnem_arr = mnem_str.split()
    sme = set(mnem_arr)
    # French & English share 100 words
    #if sme < (frozenset(set(WORDS["english"]) & set(WORDS["french"]))):
    #    print Warning("Could be English OR French!\nUsing English as default")
    #    return "english"
    languages = set(WORDS.keys())
    languages.remove('electrum1')
    poss_langs = []
    for lang in list(languages):
        if sme < set(WORDS[lang]):
            poss_langs.append(lang)
    if len(poss_langs) == 1:
        return poss_langs[0]
    elif len(poss_langs) == 2:		# 2 possible langauges
        if poss_langs[0][:7] and poss_langs[1][:7] == 'chinese':
            sys.stderr.write("Cannot determine which Chinese wordlist to use!\nChinese traditional returned")
            return 'chinese_traditional'
        if poss_langs[0][:7] and poss_langs[1][:7] in ('french', 'english'):
            sys.stderr.write("Cannot determine if English or French.\nEnglish returned")
            return 'english '
    else:
        sys.stderr.write("Unable to determine language.\nReturning English")
        return 'english'

def bip39_to_mn(hexstr, lang=None):
    """BIP39 entropy to mnemonic (language optional)"""
    if not isinstance(hexstr, string_or_bytes_types) or not re.match('^[0-9a-fA-F]*$', hexstr):
        raise TypeError("Enter a hex string!")

    if len(hexstr) not in xrange(4, 125, 4):
        raise Exception("32 < entropy < 992 bits only!")

    lang = 'english' if lang is None else str(lang)
    BIP39 = WORDS[lang.lower()]

    hexstr = unhexify(hexstr)
    cs = sha256(hexstr)     # sha256 hexdigest
    bstr = (changebase(hexify(hexstr), 16, 2, len(hexstr)*8) +
            changebase(cs, 16, 2, 256)[ : len(hexstr) * 8 // 32])
    wordarr = []
    for i in range(0, len(bstr), 11):
        wordarr.append( BIP39[ int(bstr[i:i+11], 2)] )
    return u'\u3000'.join(wordarr) if lang == 'japanese' else u' '.join(wordarr)

def bip39_to_seed(mnemonic, saltpass=b''):
    """BIP39 mnemonic (& optional password) to seed"""
    if isinstance(mnemonic, list):
        mnemonic = u' '.join(mnemonic)

    norm = lambda d: ' '.join(unicodedata.normalize('NFKD', unicode(d)).split())
    mn_norm_str = norm(mnemonic)
    norm_saltpass = norm(saltpass)

    assert bip39_check(mn_norm_str)
    return pbkdf2_hmac_sha512(mn_norm_str.encode('utf-8'), 'mnemonic'+norm_saltpass.encode('utf-8'))

def bip39_to_entropy(mnem_str):
    """BIP39 mnemonic back to entropy"""
    # https://gist.github.com/simcity4242/034fd84230864d91e146 = Java inspired code
    # changebase(''.join(map(lambda d: changebase(str(d), 10, 2, 11), [WORDS['english'].index(w) for w in mnem_str.split()]))[:128], 2, 16)
    mnem_arr = mnem_str.split()
    lang = bip39_detect_lang(mnem_str)
    BIP39 = WORDS[lang.lower()]
    assert len(mnem_arr) % 3 == 0
    
    L = len(mnem_arr) * 11
    indexes = [BIP39.index(w) for w in mnem_arr]	# word indexes (int)
    bindexes = map(lambda d: changebase(st(d), 10, 2, 11), indexes)
    binstr = ''.join(bindexes)
    
    bd = binstr[:L // 33 * 32]
    cs = binstr[-L // 33:]
    hexd = unhexify(changebase(bd, 2, 16, L // 33 * 8))
    hexd_cs = changebase(sha256(hexd), 16, 2, 256)[:L // 33]
    if hexd_cs == cs:
        return hexify(hexd)
    raise Exception("Checksums don't match!!")

def bip39_check(mnem_phrase, lang=None):
    """Assert mnemonic is BIP39 standard"""
    if isinstance(mnem_phrase, string_types):
        mn_array = unicodedata.normalize('NFKD', unicode(mnem_phrase)).split()
    elif isinstance(mnem_phrase, list):
        mn_array = mnem_phrase
    else:
        raise TypeError

    lang = bip39_detect_lang(mnem_phrase)
    lang = 'english' if lang is None else str(lang)
    BIP39 = WORDS[lang.lower()]

    assert len(mn_array) in range(3, 124, 3)

    #binstr = ''.join([changebase(st(binary_search(BIP39, x)), 10, 2, 11) for x in mn_array])
    binstr = ''.join([changebase(st(BIP39.index(x)), 10, 2, 11) for x in mn_array])
    L = len(binstr)
    bd = binstr[:L // 33 * 32]
    cs = binstr[-L // 33:]
    hexd = unhexify(changebase(bd, 2, 16, L // 33 * 8))
    hexd_cs = changebase(hashlib.sha256(hexd).hexdigest(), 16, 2, 256)[:L // 33]
    return cs == hexd_cs

def random_bip39_pair(bits=128, lang=None):
    """Generates a tuple of (entropy, mnemonic)"""
    lang = 'english' if lang is None else str(lang)
    if int(bits) % 32 != 0:
        raise Exception('%d not divisible by 32! Try 128 bits' % bits)
    hexseed = hexify(by(unhexify(
                            random_key()+random_key())[:bits // 8]))
    return hexseed, bip39_to_mn(hexseed, lang=lang)

def random_bip39_seed(bits=128):
    return random_bip39_pair(bits)[0]

def random_bip39_mn(bits=128, lang=None):
    lang = 'english' if lang is None else str(lang)
    return random_bip39_pair(bits, lang)[-1]

def elec1_mn_decode(mnem):
    """Decodes Electrum 1.x mnem phrase to hex seed"""
    if isinstance(mnem, string_types):
        mnem_list = from_str_to_bytes(mnem).lower().strip().split()
    elif isinstance(mnem, list):
        mnem_list = mnem

    wlist, words, n = mnem_list, WORDS['electrum1'], len(WORDS['electrum1'])
    output = ''
    for i in range(len(wlist)//3):
        word1, word2, word3 = wlist[3*i:3*i+3]
        w1 =  words.index(word1)
        w2 = (words.index(word2))%n
        w3 = (words.index(word3))%n
        x = w1 + n*((w2-w1)%n) + n*n*((w3-w2)%n)
        output += '%08x' % x
    return output

def elec1_mn_encode(hexstr):
    if not isinstance(hexstr, string_types) or not re.match('^[0-9a-fA-F]*$', hexstr):
        raise TypeError("Bad input: hex string req!")
    hexstr = from_str_to_bytes(hexstr)
    message, words, n = hexstr, WORDS['electrum1'], len(WORDS['electrum1'])
    assert len(message) % 8 == 0 and n == 1626
    out = []
    for i in range(len(message)//8):
        word = message[8*i:8*i+8]
        x = int(word, 16)
        w1 = (x%n)
        w2 = ((x//n) + w1)%n
        w3 = ((x//n//n) + w2)%n
        out += [words[w1], words[w2], words[w3]]
    return ' '.join(out)

# https://gist.github.com/simcity4242/94a5c32b66e52834ae71
def generate_elec2_seed(num_bits=128, prefix='01', custom_entropy=1):
    n = int(math.ceil(math.log(custom_entropy, 2)))
    k = len(prefix)*4                            # amount of lost entropy from '01' req
    n_added = max(16, k + num_bits - n)          # 136 - lost = 128 bits entropy
    entropy = random.randrange(pow(2, n_added))  # decode(os.urandom((1+len("%x"%pow(2,n_added))//2)),256)

    nonce = 0
    while True:     # cycle thru values until HMAC == 0x01...cdef ...
        nonce += 1
        i = custom_entropy * (entropy + nonce)
        mn_seed = elec2_mn_encode(i)
        assert i == elec2_mn_decode(mn_seed)
        if is_elec1_seed(mn_seed): continue         # ensure seed NOT elec1 compatible
        if is_elec2_seed(mn_seed, prefix): break
    return mn_seed

random_electrum2_seed = random_elec2_seed = generate_elec2_seed

def elec2_mn_encode(i, lang='english'):
    """Encodes int, i, as Electrum 2 mnemonic"""
    assert lang in ('english', 'japanese', 'spanish')
    n = 2048
    words = []
    while i:
        x = i%n
        i //= n
        words.append(WORDS[lang.lower()][x])
    return ' '.join(words)

def elec2_mn_decode(mn_seed, lang='english'):
    assert lang in ('english', 'japanese', 'spanish')
    words = prepare_elec2_seed(mn_seed).split()
    wordlist = WORDS[lang.lower()]
    n = len(wordlist)
    i = 0
    while words:
        w = words.pop()
        k = wordlist.index(w)
        i = i*n + k
    return i

def elec2_check_seed(mn_seed, custom_entropy=1):
    assert is_elec2_seed(mn_seed)
    i = elec2_mn_decode(mn_seed)
    return i % custom_entropy == 0

def is_elec2_seed(seed, prefix='01'):
    assert prefix in ('01', '101')
    hmac_sha_512 = lambda x, y: hmac.new(x, y, hashlib.sha512).hexdigest()
    s = hmac_sha_512('Seed version', seed)
    return s.startswith(prefix)

def is_elec1_seed(seed):
    words = seed.strip().split()
    try:
        elec1_mn_decode(words)
        uses_electrum_words = True
    except Exception:
        uses_electrum_words = False
    try:
        unhexify(seed)
        is_hex = (len(seed) == 32 or len(seed) == 64)
    except Exception:
        is_hex = False
    return is_hex or (uses_electrum_words and (len(words) == 12 or len(words) == 24))

def _prepare_seed(seed):
    CJK_INTERVALS = [
    (0x4E00, 0x9FFF, 'CJK Unified Ideographs'),
    (0x3400, 0x4DBF, 'CJK Unified Ideographs Extension A'),
    (0x20000, 0x2A6DF, 'CJK Unified Ideographs Extension B'),
    (0x2A700, 0x2B73F, 'CJK Unified Ideographs Extension C'),
    (0x2B740, 0x2B81F, 'CJK Unified Ideographs Extension D'),
    (0xF900, 0xFAFF, 'CJK Compatibility Ideographs'),
    (0x2F800, 0x2FA1D, 'CJK Compatibility Ideographs Supplement'),
    (0x3190, 0x319F , 'Kanbun'),
    (0x2E80, 0x2EFF, 'CJK Radicals Supplement'),
    (0x2F00, 0x2FDF, 'CJK Radicals'),
    (0x31C0, 0x31EF, 'CJK Strokes'),
    (0x2FF0, 0x2FFF, 'Ideographic Description Characters'),
    (0xE0100, 0xE01EF, 'Variation Selectors Supplement'),
    (0x3100, 0x312F, 'Bopomofo'),
    (0x31A0, 0x31BF, 'Bopomofo Extended'),
    (0xFF00, 0xFFEF, 'Halfwidth and Fullwidth Forms'),
    (0x3040, 0x309F, 'Hiragana'),
    (0x30A0, 0x30FF, 'Katakana'),
    (0x31F0, 0x31FF, 'Katakana Phonetic Extensions'),
    (0x1B000, 0x1B0FF, 'Kana Supplement'),
    (0xAC00, 0xD7AF, 'Hangul Syllables'),
    (0x1100, 0x11FF, 'Hangul Jamo'),
    (0xA960, 0xA97F, 'Hangul Jamo Extended A'),
    (0xD7B0, 0xD7FF, 'Hangul Jamo Extended B'),
    (0x3130, 0x318F, 'Hangul Compatibility Jamo'),
    (0xA4D0, 0xA4FF, 'Lisu'),
    (0x16F00, 0x16F9F, 'Miao'),
    (0xA000, 0xA48F, 'Yi Syllables'),
    (0xA490, 0xA4CF, 'Yi Radicals')]

    def is_CJK(c):
        # http://www.asahi-net.or.jp/~ax2s-kmtn/ref/unicode/e_asia.html
        n = ord(c)
        for i_min, i_max, name in CJK_INTERVALS:
            if i_max >= n >= i_min:
                return True
        return False

    # normalize
    seed = unicodedata.normalize('NFKD', unicode(seed))
    # lower
    seed = seed.lower()
    # remove accents
    seed = u''.join([c for c in seed if not unicodedata.combining(c)])
    # normalize whitespaces
    seed = u' '.join(seed.split())
    # remove whitespaces between CJK
    seed = u''.join([seed[i] for i in range(len(seed)) if not (seed[i] in string.whitespace and is_CJK(seed[i-1]) and is_CJK(seed[i+1]))])
    return seed

prepare_elec2_seed = _prepare_seed



# https://github.com/spesmilo/electrum/tree/master/lib/wordlist
# https://github.com/spesmilo/electrum/raw/master/lib/wordlist/portuguese.txt
# https://github.com/spesmilo/electrum/raw/master/lib/wordlist/japanese.txt
# https://github.com/spesmilo/electrum/raw/master/lib/wordlist/english.txt
# https://github.com/spesmilo/electrum/raw/master/lib/wordlist/spanish.txt
