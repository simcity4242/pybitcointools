#!/usr/bin/python

from bitcoin.pyspecials import *
#from bitcoin.constants import *

import json, re, binascii
import random
import sys
import urlparse
try:    
    from urllib.request import build_opener, Request
except: 
    from urllib2 import build_opener, Request, HTTPError
    import urllib2

FLAG_TESTNET = None

BLOCKCYPHER_API = "?token=%s" % "ba9bd23bab74fa421778a3e1f8dfbece"
BLOCKSTRAP_API = "?api_key=%s" % "66350E08-5C41-5449-8936-3EA71EC9CD2F"
CHAIN_API = "api-key-id=%s" % "211a589ce9bbc35de662ee02d51aa860"

BET_URL, BE_URL = "https://testnet.blockexplorer.com/api", "https://blockexplorer.com/api"
BLOCKRT_URL, BLOCKR_URL = "http://tbtc.blockr.io/api/v1", "http://tbtc.blockr.io/api/v1"
BLOCKSTRAPT_URL, BLOCKSTRAP_URL = "https://api.blockstrap.com/v0/btct", "https://api.blockstrap.com/v0/btc"
CHAINSOT_URL, CHAINSO_URL = "https://chain.so/api/v2/%s/BTCTEST/%s", "https://chain.so/api/v2/%s/BTC/%s"
BLOCKCYPHERT_URL, BLOCKCYPHER_URL = 'https://api.blockcypher.com/v1/btc/test3/', 'https://api.blockcypher.com/v1/btc/main/'

def set_api(svc="bci", code=""):
    """Set API code for web service"""
    if not code:
        raise ValueError("API code wasn't set")
    # TODO: call make_api_param()
    varname = "{svc}_API".format(svc=svc.strip().upper())
    #global varname
    globals()[varname] = code


def make_api_param(*args):
    '''Takes (k,v) to make URI_blah?k=v'''
    if not paramname:
        return code
    return "{qm}{pname}={code}".format(qm="?", pname=paramname, code=code)


def make_request(*args):
    opener = build_opener()
    opener.addheaders = [('User-agent',
                          'Mozilla/5.0'+str(random.randrange(1000000)))]
    try:
        return opener.open(*args).read().strip()
    except HTTPError as he:
        raise Exception(str(he))
    except Exception as e:
        try:
            p = e.read().strip()
        except:
            p = e
        raise Exception(p)



def is_testnet(inp):
    '''Checks if inp is a testnet address or if UTXO is a known testnet TxID''' 
    if len(inp) > 0 and isinstance(inp, (list, tuple)):
        res = []
        for v in inp:
            if not v or (isinstance(v, basestring) and v.lower() in ("btc", "testnet")): 
                pass
            try: 
                res.append(is_testnet(v))
            except: 
                return False
        return any(res)
    elif not isinstance(inp, basestring):    # sanity check
        raise TypeError("Cannot check %s, only string or dict" % str(type(inp)))

    ## ADDRESSES
    if inp[0] in "123mn":
        return bool(re.match("^[2mn][a-km-zA-HJ-NP-Z0-9]{26,33}$", inp))
        #sys.stderr.write("Bad address format %s")

    ## TXID
    elif re.match('^[0-9a-fA-F]{64}$', inp):
        try:
            jdata = json.loads(make_request("%s/tx/%s" % (BET_URL, inp)))    # Try Testnet
            return True 
        except:
            jdata = json.loads(make_request("%s/tx/%s" % (BE_URL, inp)))     # Try Mainnet
            return False
        sys.stderr.write("TxID %s has no match for testnet or mainnet (Bad TxID)")

    else:
        raise TypeError("{0} is unknown input".format(inp))


def set_network(*args):
    '''Decides if args for unspent/fetchtx/pushtx are mainnet or testnet'''
    if not args and FLAG_TESTNET is not None:
        return "testnet" if FLAG_TESTNET else "btc"
    r = []
    for arg in args:
        if not arg:
            pass
        if isinstance(arg, basestring):
            r.append(is_testnet(arg))
        elif isinstance(arg, (list, tuple)):
            return set_network(*arg)
    if any(r) and not all(r):
        raise Exception("Mixed Testnet/Mainnet queries")
    return "testnet" if any(r) else "btc"


def parse_addr_args(*args):
    # Valid input formats: unspent([addr1, addr2, addr3])
    #                      unspent([addr1, addr2, addr3], network)
    #                      unspent(addr1, addr2, addr3)
    #                      unspent(addr1, addr2, addr3, network)
    addr_args = args
    network = "btc"
    if len(args) == 0:
        return [], 'btc'
    if len(args) >= 1 and args[-1] in ('testnet', 'btc'):
        network = args[-1]
        addr_args = args[:-1]
    if len(addr_args) == 1 and isinstance(addr_args, list):
        network = set_network(*addr_args[0])
        addr_args = addr_args[0]
    if addr_args and isinstance(addr_args, tuple) and isinstance(addr_args[0], list):
        addr_args = addr_args[0]
    network = set_network(addr_args)
    return addr_args, network


# json.loads(make_request("https://testnet.blockexplorer.com/api/addr-validate/%s" % inp))

# Gets the unspent outputs of one or more addresses

def be_unspent(*args, **kwargs):
    try: addrs, network = parse_addr_args(*args)
    except: network = "btc", args[:-1]
    u = []
    for a in addrs:
        try:
            data = make_request('%s/addr/%s/utxo?noCache=1' % ((BET_URL if network == "testnet" else BE_URL), a))
        except Exception as e:
            if str(e) == 'No free outputs to spend': continue
            else: raise Exception(e)
        try:
            jsonobj = json.loads(data)
            for o in jsonobj:
                h = o.get('txid')
                v = o.get('vout')
                p = int(o.get('amount')*1e8 + 0.5)
                u.append({
                    "output": "%s:%d" % (h, v),
                    "value": p
                })
        except:
            print data
            sys.stderr.write("Failed to decode data: "+data)
    return u


def bci_unspent(*args):
    addrs, network = parse_addr_args(*args)
    if not network == "btc":
        raise Exception("BCI only supports mainnet, Network %s unsupported" % network)
    u = []
    for a in addrs:
        url = 'https://blockchain.info/unspent?active=%s' % a
        try:
            data = make_request(url)
        except Exception as e:
            if str(e) == 'No free outputs to spend': continue
            else: raise Exception(e)
        try:
            jsonobj = json.loads(data.decode('utf-8'))
            for o in jsonobj["unspent_outputs"]:
                h = safe_hexlify(unsafe_hexlify(o['tx_hash'])[::-1])
                u.append({
                    "output": h+':'+str(o['tx_output_n']),
                    "value": o['value']})
        except:
            raise Exception("Failed to decode data: "+data)
    return u


def blockr_unspent(*args):
    # Valid input formats: blockr_unspent([addr1, addr2,addr3])
    #                      blockr_unspent(addr1, addr2, addr3)
    #                      blockr_unspent([addr1, addr2, addr3], network)
    #                      blockr_unspent(addr1, addr2, addr3, network)
    # Where network is 'btc' or 'testnet'
    addr_args, network = parse_addr_args(*args)

    if network == 'testnet':
        blockr_url = 'http://tbtc.blockr.io/api/v1/address/unspent/'
    elif network == 'btc':
        blockr_url = 'http://btc.blockr.io/api/v1/address/unspent/'
    else:
        raise Exception('Unsupported network {0} for blockr_unspent'.format(network))

    res = make_request(blockr_url + ','.join(addrs))
    data = json.loads(res.decode('utf-8'))['data']
    o = []
    if 'unspent' in data:
        data = [data]
    for dat in data:
        for u in dat['unspent']:
            o.append({
                "output": u['tx']+':'+str(u['n']),
                "value": int(u['amount'].replace('.', ''))
            })
    return o


def biteasy_unspent(*args):
    addrs, network = parse_addr_args(*args)
    base_url = "https://api.biteasy.com/%s/v1/"
    url = base_url % ('testnet' if network == 'testnet' else base_url % "blockchain")
    offset, txs = 0, []
    for addr in addrs:
        # TODO: fix multi address search
        while True:
            data = make_request("%s/addresses/%s/unspent-outputs?per_page=20" % (url, addr))
            try:
                jsondata = json.loads(data.decode('utf-8'))
            except:
                raise Exception("Could not decode JSON data")
            txs.extend(jsondata['data']['outputs'])
            if jsondata['data']['pagination']['next_page'] is False:
                break
            offset += 20 # jsondata['data']['pagination']["per_page"]
            sys.stderr.write("Fetching more transactions... " + str(offset) + '\n')
        o = []
        for utxo in txs:
            assert utxo['to_address'] == addr and utxo['is_spent'] == 0, "Wrong address or UTXO is spent"
            o.append({
                "output": "%s:%d" % (utxo['transaction_hash'], utxo['transaction_index']),
                "value": utxo['value']
            })
        return o


unspent_getters = {
    'bci': bci_unspent,
    'blockr': blockr_unspent,
    'be': be_unspent,
    'biteasy': biteasy_unspent
}


def unspent(*args, **kwargs):
    """unspent(addr, "btc", source="blockr")"""
    svc = kwargs.get('source', '')
    f = unspent_getters.get(svc, be_unspent)
    return f(*args)


# Gets the transaction output history of a given set of addresses,
# including whether or not they have been spent
def history(*args):
    # Valid input formats: history([addr1, addr2,addr3], "btc")
    #                      history(addr1, addr2, addr3, "testnet")
    if len(args) == 0 or (len(args)==1 and args[0] in ('testnet','btc')):
        return []
    addrs, network = parse_addr_args(*args)

    if network == "btc":
        txs = []
        for addr in addrs:
            offset = 0
            while 1:
                gathered = False
                while not gathered:
                    try:
                        data = make_request('https://blockchain.info/address/%s?format=json&offset=%s' % (addr, offset))
                        gathered = True
                    except Exception as e:
                        try:
                            sys.stderr.write(e.read().strip())
                        except:
                            sys.stderr.write(str(e))
                        gathered = False
                try:
                    jsonobj = json.loads(data)
                except:
                    raise Exception("Failed to decode data: "+data)
                txs.extend(jsonobj["txs"])
                if len(jsonobj["txs"]) < 50:
                    break
                offset += 50
                sys.stderr.write("Fetching more transactions... "+str(offset)+'\n')
        outs = {}
        for tx in txs:
            for o in tx["out"]:
                if o.get('addr', None) in addrs:
                    key = str(tx["tx_index"])+':'+str(o["n"])
                    outs[key] = {
                        "address": o["addr"],
                        "value": o["value"],
                        "output": tx["hash"]+':'+str(o["n"]),
                        "block_height": tx.get("block_height", None)
                    }
        for tx in txs:      # if output is spent adds "spend": "spending_TxID:i"
            for i, inp in enumerate(tx["inputs"]):
                if "prev_out" in inp:
                    if inp["prev_out"].get("addr", None) in addrs:
                        key = str(inp["prev_out"]["tx_index"]) + \
                              ':'+str(inp["prev_out"]["n"])
                        if outs.get(key):
                            outs[key]["spend"] = tx["hash"] + ':' + str(i)
        return [outs[k] for k in outs]
        
    elif network == "testnet":
        txs = []         # using http://api.blockcypher.com/v1/btc/test3/addrs/n1hjyVvYQPQtejJcANd5ZJM5rmxHCCgWL7;n2kx7k6JuA5Wy27fawaeiPX7dq8mbRDPAv?confirmations=0&limit=50&before
        #addrs = ';'.join((addrs if isinstance(addrs, list) else [addrs]))
        for addr in addrs:    # or 
            offset = 0
            bh = last_block_height("testnet")
            while 1:
                gathered = False
                while not gathered:
                    try:
                        data = make_request("http://api.blockcypher.com/v1/btc/test3/addrs/%s?confirmations=0&limit=50&before=%d" % (addr, bh))
                        gathered = True
                    except Exception as e:
                        try:    sys.stderr.write(e.read().strip())
                        except: sys.stderr.write(str(e))
                        gathered = False
                try:
                    jsonobj = json.loads(data)
                except:
                    raise Exception("Failed to decode data: " + data)
                assert addr == jsonobj.get("address"), "Tx data doesn't match address %s" % addr
                txs.extend(jsonobj['txrefs'])
                if "hasMore" in jsonobj:
                    bh = txs[-1].get("block_height")
                if offset >= jsonobj['n_tx']: # because records=50
                    break
                offset += 50
                sys.stderr.write("Fetching more transactions... " + str(offset) + '\n')
        outs = {}
        #from bitcoin.main import hex_to_b58check, btc_to_satoshi
        for tx in txs:
            for o in tx.get("vout"):
                if o.get('scriptPubKey', None) and hex_to_b58check(o.get("scriptPubKey")["hex"], 111) == addr:
                    key = str(tx["time"]) + ':' + str(o["n"])
                    outs[key] = {
                        "address":    addr,
                        "value":      btc_to_satoshi(o["value"]),
                        "output":     "{0}:{1}".format(tx["txid"], str(o["n"])),
                    }
                    blkhash = tx.get("blockhash")
                    try:
                        bheight = get_block_height(blkhash, 'testnet')
                        outs[key].update({"block_height": int(bheight)})
                    except:
                        sys.stderr.write("Couldn't get blockheight for %s.\nUsing blocktime instead" % blkhash)
                        outs[key].update({"block_time": tx.get("time")})
        for tx in txs:
            for i, inp in enumerate(tx["inputs"]):
                if "prev_out" in inp:
                    if inp["prev_out"]["addr"] in addrs:
                        key = str(inp["prev_out"]["tx_index"]) + \
                              ':' + str(inp["prev_out"]["n"])
                        if outs.get(key):
                            outs[key]["spend"] = tx["hash"] + ':' + str(i)
        return [outs[k] for k in reversed(sorted(outs))]


# Pushes a transaction to the network using https://blockchain.info/pushtx
def bci_pushtx(tx):
    if not re.match('^[0-9a-fA-F]*$', tx): 
        tx = safe_hexlify(tx)
    return make_request('https://blockchain.info/pushtx', 'tx='+tx)


def eligius_pushtx(tx):
    if not re.match('^[0-9a-fA-F]*$', tx): 
        tx = safe_hexlify(tx)
    s = make_request(
        'http://eligius.st/~wizkid057/newstats/pushtxn.php',
        'transaction=%s&send=Push' % tx)
    strings = re.findall('string[^"]*"[^"]*"', s)
    for string in strings:
        quote = re.findall('"[^"]*"', string)[0]
        if len(quote) >= 5:
            return quote[1:-1]


def blockr_pushtx(tx, network='btc'):
    if network == 'testnet':
        blockr_url = 'http://tbtc.blockr.io/api/v1/tx/push'
    elif network == 'btc':
        blockr_url = 'http://btc.blockr.io/api/v1/tx/push'
    else:
        raise Exception('Unsupported network {0} for blockr_pushtx'.format(network))

    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = safe_hexlify(tx)
    return make_request(blockr_url, '{"hex":"%s"}' % tx)


def helloblock_pushtx(tx):
    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = safe_hexlify(tx)
    return make_request('https://mainnet.helloblock.io/v1/transactions', 'rawTxHex=%s' % tx)


def webbtc_pushtx(tx, network=""):
    network = "testnet" if is_testnet(tx) else "btc"
    if network == 'testnet':
        webbtc_url = 'http://test.webbtc.com/relay_tx.json'
    elif network == 'btc':
        webbtc_url = 'http://webbtc.com/relay_tx.json'
    else:
        raise Exception('Unsupported network {0} for blockr_pushtx'.format(network))


    return json.loads(make_request(webbtc_url, 'tx=%s' % tx))


pushtx_getters = {
    'bci': bci_pushtx,
    'blockr': blockr_pushtx,
    'webbtc': webbtc_pushtx,
    'helloblock': helloblock_pushtx
}


def pushtx(*args, **kwargs):
    svc = kwargs.get('source', '')
    f = pushtx_getters.get(svc, blockr_pushtx)
    return f(*args)


def last_block_height(network='btc'):
    if network == 'testnet':
        jsonobj = json.loads(make_request('%s/status?q=getBlockCount' % BET_URL))
        return jsonobj.get("blockcount")
    elif network == "btc":
        jsonobj = json.loads(make_request('%s/status?q=getBlockCount' % BE_URL))
        return jsonobj.get("blockcount")


# Gets a specific transaction
def bci_fetchtx(txhash):
    if isinstance(txhash, list):
        return [bci_fetchtx(h) for h in txhash]
    if not re.match('^[0-9a-fA-F]*$', txhash):
        txhash = safe_hexlify(txhash)
    data = make_request('https://blockchain.info/rawtx/%s?format=hex' % txhash)
    return data
    

def be_fetchtx(txhash):
    if isinstance(txhash, list):
        return [be_fetchtx(h) for h in txhash]
    if not re.match('^[0-9a-fA-F]*$', txhash):
        txhash = safe_hexlify(txhash)
    network = set_network(txhash)
    data = make_request("%s/tx/%s" % ((BET_URL if network=="testnet" else BE_URL), txhash))
    jsonobj = json.loads(data)
    txh = jsonobj.get("rawtx")
    return txh.encode("utf-8")


def blockr_fetchtx(txhash, network=None):
    txhash, network = parse_addr_args(txhash)
    if network not in ("btc","testnet"):
        raise Exception('Unsupported network {0} for blockr_fetchtx'.format(network))
    blockr_url = '%s/tx/raw/' % (BLOCKRT_URL if network == 'testnet' else BLOCKR_URL)
    if len(txhash) == 1 and isinstance(txhash, tuple):
        txhash = list(txhash[0])
    if isinstance(txhash, list):
        txhash = ','.join([safe_hexlify(x) if not re.match('^[0-9a-fA-F]*$', x)
                           else x for x in txhash])
        jsondata = json.loads(make_request(blockr_url + txhash))
        return [d['tx']['hex'] for d in jsondata['data']]
    else:
        if not re.match('^[0-9a-fA-F]*$', txhash):
            txhash = safe_hexlify(txhash)
        jsondata = json.loads(make_request(blockr_url + txhash))
        return jsondata['data']['tx']['hex']   


def helloblock_fetchtx(txhash, network='btc'):
    if not re.match('^[0-9a-fA-F]*$', txhash):
        txhash = safe_hexlify(txhash)
    if network == 'testnet':
        url = 'https://testnet.helloblock.io/v1/transactions/'
    elif network == 'btc':
        url = 'https://mainnet.helloblock.io/v1/transactions/'
    else:
        raise Exception('Unsupported network {0} for helloblock_fetchtx'.format(network))
    data = json.loads(make_request(url + txhash)).decode('utf-8')["data"]["transaction"]
    o = {
        "locktime": data["locktime"],
        "version": data["version"],
        "ins": [],
        "outs": []
    }
    for inp in data["inputs"]:
        o["ins"].append({
            "script": inp["scriptSig"],
            "outpoint": {
                "index": inp["prevTxoutIndex"],
                "hash": inp["prevTxHash"],
            },
            "sequence": 4294967295
        })
    for outp in data["outputs"]:
        o["outs"].append({
            "value": outp["value"],
            "script": outp["scriptPubKey"]
        })
    from bitcoin.transaction import serialize
    from bitcoin.transaction import txhash as TXHASH
    tx = serialize(o)
    assert TXHASH(tx) == txhash
    return tx


def webbtc_fetchtx(txhash, network='btc'):
    if not re.match('^[0-9a-fA-F]*$', txhash):
        txhash = safe_hexlify(txhash)
    if network == 'testnet':
        webbtc_url = 'http://test.webbtc.com/tx/'
    elif network == 'btc':
        webbtc_url = 'http://webbtc.com/tx/'
    else:
        raise Exception('Unsupported network {0} for webbtc_fetchtx'.format(network))
    hexdata = make_request(webbtc_url + txhash + ".hex")
    return st(hexdata)


fetchtx_getters = {
    'bci': bci_fetchtx,
    'blockr': blockr_fetchtx,
    'be': be_fetchtx,
    'webbtc': webbtc_fetchtx,       #   http://test.webbtc.com/tx/txid.[hex,json, bin]
    'helloblock': helloblock_fetchtx
}


def fetchtx(*args, **kwargs):
    svc = kwargs.get("source", "")
    f = fetchtx_getters.get(svc, be_fetchtx)
    return f(*args)


def firstbits(address):
    if len(address) >= 25:
        return make_request('https://blockchain.info/q/getfirstbits/'+address)
    else:
        return make_request(
            'https://blockchain.info/q/resolvefirstbits/'+address)


def get_block_at_height(height, network='btc'):
    if network == 'btc':
        j = json.loads(make_request("https://blockchain.info/block-height/%s?format=json" % str(height))).decode('utf-8')
        for b in j['blocks']:
            if b['main_chain'] is True:
                return b
        raise Exception("Block at this height not found")
    elif network == 'testnet':
        j = json.loads(make_request("https://chain.so/api/v2/block/BTCTEST/" + str(height))).decode('utf-8')
        # FIXME: add code from 'http://tbtc.blockr.io/api/v1/block/raw/%s' ??
        return ''
        #raise Exception("Block at this height not found")

get_block_by_height = get_block_at_height


def get_block_height(blockhash, network="btc"):
    url = "%s/api/block/%s" % (BET_URL if network=="testnet" else BE_URL, blockhash)
    jsonobj = json.loads(make_request(url)).decode('utf-8')
    return jsonobj.get("height")


def _get_block(inp):
    if len(str(inp)) < 64:
        return get_block_at_height(inp)
    else:
        return json.loads(make_request('https://blockchain.info/rawblock/'+inp)).decode('utf-8')

get_block = _get_block


def bci_get_block_header_data(inp):
    j = _get_block(inp)
    return {
        'version': j['ver'],
        'hash': j['hash'],
        'prevhash': j['prev_block'],
        'timestamp': j['time'],
        'merkle_root': j['mrkl_root'],
        'bits': j['bits'],
        'nonce': j['nonce'],
    }


def blockr_get_block_header_data(height, network='btc'):
    if network == 'testnet':
        blockr_url = "%s/block/raw/" % BLOCKRT_URL
    elif network == 'btc':
        blockr_url = "%s/block/raw/" % BLOCKR_URL
    else:
        raise Exception(
            'Unsupported network {0} for blockr_get_block_header_data'.format(network))

    k = json.loads(make_request(blockr_url + str(height))).decode('utf-8')
    j = k['data']
    return {
        'version': j['version'],
        'hash': j['hash'],
        'prevhash': j['previousblockhash'],
        'timestamp': j['time'],
        'merkle_root': j['merkleroot'],
        'bits': int(j['bits'], 16),
        'nonce': j['nonce'],
    }


def get_block_timestamp(height, network='btc'):
    if network == 'testnet':
        blockr_url = "%s/block/info/" % BLOCKRT_URL
    elif network == 'btc':
        blockr_url = "%s/block/info/" % BLOCKR_URL
    else:
        raise Exception('Unsupported network {0} for get_block_timestamp'.format(network))

    import time, calendar
    if isinstance(height, list):
        k = json.loads(make_request(blockr_url + ','.join([str(x) for x in height]))).decode('utf-8')
        o = {x['nb']: calendar.timegm(time.strptime(x['time_utc'],
             "%Y-%m-%dT%H:%M:%SZ")) for x in k['data']}
        return [o[x] for x in height]
    else:
        k = json.loads(make_request(blockr_url + str(height))).decode('utf-8')
        j = k['data']['time_utc']
        return calendar.timegm(time.strptime(j, "%Y-%m-%dT%H:%M:%SZ"))


block_header_data_getters = {
    'bci': bci_get_block_header_data,
    'blockr': blockr_get_block_header_data
}


def get_block_header_data(inp, **kwargs):
    svc = kwargs.get('source', '')
    f = block_header_data_getters.get(svc, blockr_get_block_header_data)
    return f(inp, **kwargs)


def get_txs_in_block(inp):
    j = _get_block(inp)
    hashes = [t['hash'] for t in j.get('tx')]
    return hashes


#def get_block_height(txid, network='btc'):
#    base_url = 'https://bitcoin.toshi.io/api/v0/blocks/1' % \
#               ('tbtc' if network == 'testnet' else 'btc')
#    j = json.loads(make_request(base_url + str(txid)))
#    return j['data']['block']


def get_block_coinbase(txval):
    j = _get_block(txval)
    cb = bytearray.fromhex(j['tx'][0]['inputs'][0]['script'])
    alpha = set(map(chr, list(range(32, 126))))
    res = ''.join([x for x in str(cb) if x in alpha])
    if ord(res[0]) == len(res)-1:
        return res[1:]
    return res


def biteasy_search(*args):
    q, network = parse_addr_args(*args)
    url = 'https://api.biteasy.com/%s/v1/search?q=%s' % \
               (('blockchain' if network == 'btc' else 'testnet', q))
    data = json.loads(make_request(url))     # we're left with {'results': [...], 'type': BLOCK}
    # TODO: parse different types, eg BLOCK
    return data.get('data', repr(data))


def smartbits_search(q, network='btc'):
    if network == 'testnet':
        raise Exception("Testnet NOT supported")
    base_url = "https://api.smartbit.com.au/v1/blockchain/search?q="
    data = make_request(base_url + str(q))
    jsonobj = json.loads(data.decode('utf-8'))
    assert jsonobj.get("success", False), \
        "Input:\t%s\nSearched:\t%s" % (str(q), jsonobj.get("search", "??"))
    return jsonobj.get("results", [])   # [x.get('data', '') for x in jsonobj.get('results', '')]


def estimate_fee_by_nblocks(nblocks=6, network="btc"):
    url = "%s/utils/estimatefee?nbBlocks=%d" % \
          (BET_URL if network == "testnet" else BE_URL, int(nblocks))
    data = json.loads(make_request(url))
    btc_to_satoshi = lambda b: int(b*1e8 + 0.5)
    btcfee = data.get(str(nblocks))
    return btc_to_satoshi(btcfee)

fee_estimate_by_nblocks = estimate_fee_by_nblocks


def get_fee_estimate(priority="medium", network="btc"):
    assert priority in ("low", "medium", "high")
    url = "http://api.blockcypher.com/v1/btc/%s/" % ("test3" if network=="testnet" else "main")
    jdata = json.loads(make_request(url))
    fee = jdata.get("%s_fee_per_kb" % priority.lower(), "medium_fee_per_kb")
    return fee

def get_stats(days=1, network="btc", **kwargs):
    assert network in ("testnet", "btc")
    svc = kwargs.get("source", ("smartbit" if network == "btc" else "webbtc"))
    if svc == "smartbit":
        if network == "testnet":
            raise Exception("No %s functionality for %s" % (network, svc))
        sb_url = "https://api.smartbit.com.au/v1/blockchain/stats?%d" % int(days)
        stats = json.loads(make_request(sb_url))
    elif svc == "webbtc":
        if network == "testnet":
            wb_url = "http://test.webbtc.com/stats.json"
        else:
            wb_url = "http://webbtc.com/stats.json"
        stats = json.loads(make_request(wb_url))
        sys.stderr.write("Current network statistics only available, %d days disregarded" % int(days))
    return stats
    
#stats = get_stats()

def address_txlist(*args):
    addrs, network = parse_addr_args(*args)
    txs = {}
    for addr in addrs:
        url = "%s/addr/%s" % (BET_URL if network == "testnet" else BE_URL, addr)
        jsonobj = json.loads(make_request(url)).decode('utf-8')
        assert jsonobj.get("addrStr") == addr 
        txs[str(addr)] = jsonobj
    return txs


def get_txid_height(*args):
    # Takes     TxID, network    returns block height for that TxID
    q, network = parse_addr_args(*args)
    if not re.match('^[0-9a-fA-F]*$', txid) or len(txid) != 64:
        raise TypeError("%s is not a valid TxID" % txid)
    url = "%s/api/tx/%s" % (BET_URL if network == "testnet" else BE_URL, txid)
    try:
        d = json.loads(make_request(url))
    except:     # GET EXCEPTION NAME
        network = 'testnet' if network == 'btc' else 'btc' if network == "testnet" else str(network)    # swap network
        sys.stderr.write("%s is not a valid TxID...trying %s network" % (txid, network))
        url = "%s/api/tx/%s" % (BET_URL if network == "testnet" else BE_URL, txid)
        try: 
            d = json.loads(make_request(url)).decode('utf-8')
        except: 
            raise ValueError("TxID %s not found for either network" % txid)
    bh = d.get("blockhash")
    bhurl = "%s/api/block/%s" % (BET_URL if network == "testnet" else BE_URL, bh)
    bdata = json.loads(make_request(bhurl)).decode('utf-8')
    return bdata.get("height")

def get_price(val=100000000, currency="usd", exchange="coinbase"):
    """v is Satoshi value (default = 1 BTC), default currency = USD$, exchange can be all"""
    if isinstance(v, float):
        v = int(val*1e8 + 0.5)
    url = "https://chain.so/api/v2/get_price/BTC/%s" % currency.upper()
    jsonobj = json.loads(make_request(url)).decode('utf-8').get("data")
    prices = {}
    for d in jsonobj.get("prices"):
        #d.pop("price_base")
        #d.pop("time")
        prices[str(d.get("exchange", "unknown"))] = float(d.get("price"))
    return prices.get(exchange.lower()) if exchange.lower() != "all" else prices
    

def get_mempool_txs(tx_count=100, network="btc"):
    tx_count = 1000 if tx_count > 1000 else tx_count
    url = "http://api.blockcypher.com/v1/btc/%s/txs?limit=%d" % (("test3" if network== "testnet" else "main"), int(tx_count))
    #sb_url = "https://api.smartbit.com.au/v1/blockchain/transactions/unconfirmed?limit=%d" % int(tx_count)
    jdata = json.loads(make_request(url))
    txs = []
    for tx in jdata.get('transactions'):
        txs.append({
                    "first_seen": tx.get('first_seen'), 
                    "size": tx.get('size'), 
                    "txid": tx.get('txid'), 
                    "fee": float(tx.get('fee'))
                    })
    
    return txs


def get_unconfirmed_txs(*args):
    '''Takes '''
    addrs_args, network = parse_addr_args(*args)
    addrs = ';'.join(list(*addrs_args)) if not isinstance(addrs_args, list) else addrs_args
    url = "%s/addrs/%s/balance" % ((BLOCKCYPHERT_URL if network == 'testnet' else BLOCKCYPHER_URL), addrs)
    jdata = json.loads(make_request(url))
    d = {}
    for o in ([jdata] if not isinstance(jdata, list) else jdata):
        addr = o.get('address') 
        assert addr in addrs_args
        n_txs = o.get('unconfirmed_n_tx')
        balance = o.get('unconfirmed_balance')
        if n_txs or balance:
            # TODO: fetch uncionfirmed Txs
            d[addr] = dict(n_txs=n_txs, balance=balance)
            #sys.stderr.write("%s has %d unconfirmed Txs worth %d!" % (n_txs, balance))
    return d
    
def is_unconfirmed(*args):
    res = get_unconfirmed_txs(*args)
    return bool(res)

def get_decoded_tx(rawtx, network=None):
    """Return deserialised raw Tx from Blockcypher API (decode, POST)"""
    if isinstance(rawtx, basestring) and not re.match('^[0-9a-fA-F]*$', rawtx):
        return get_decoded_tx(binascii.hexlify(rawtx), network=network)
    url = "http://api.blockcypher.com/v1/btc/%s/txs/decode" % (
        "test3" if network=="testnet" else "main" if network=="btc" else "main"
        )
    assert rawtx[:8] == "01000000", "Not a Tx! Txs begin with '01000000'"
    if network not in (None, "btc", "testnet"):
        raise Exception("Network {0} unsupported".format(str(network)))
    body = {"tx": rawtx}
    jdata = json.loads(make_request(url, body))
    if network is None:
        jdata.pop("addresses")
        for i in jdata["inputs"]:  o.pop("addresses")
        for o in jdata["outputs"]: o.pop("addresses")
    return jdata
