#!/usr/bin/python

###
###    https://gist.github.com/wizardofozzie/96713e871c3e71e5c87f
###

from bitcoin.pyspecials import *
import json, re
import random
import sys
try:
    from urllib.request import build_opener
except:
    from urllib2 import build_opener
    
API_CODES = ( 
                #("BCI_API" = ""),
                ("BITEASY_API", ""),
                ("BLOCKSTRAP_API", "?api_key=66350E08-5C41-5449-8936-3EA71EC9CD2F"),
                ("CHAIN_API", "?api-key-id=211a589ce9bbc35de662ee02d51aa860"),
                ("BLOCKCYPHER_API", "?token=ba9bd23bab74fa421778a3e1f8dfbece")    #  https://api.blockcypher.com/v1/btc/main?
           ) 
           
TOKENS = dict([(k,v) for k,v in API_CODES if v])

SERVICES = ("bci", "blockstrap", "biteasy", "chain.so", "chain", "blockexplorer", 
                "webbtc", "blockcypher", "blockr", "blocktrail", "smartbit", "toshi"
                )

BLOCKCYPHER_API = "?token=ba9bd23bab74fa421778a3e1f8dfbece"
BLOCKSTRAP_API = "?api_key=%s" % "66350E08-5C41-5449-8936-3EA71EC9CD2F"
CHAIN_API = "api-key-id=211a589ce9bbc35de662ee02d51aa860"

BEURL = "https://blockexplorer.com/api"
BETURL = "https://testnet.blockexplorer.com/api"


#SERVICES = {"btc": ("bci", "blockstrap", "biteasy", "chain.so", "chain", "blockexplorer", 
#                    "webbtc", "blockcypher", 
#                    "blockr", "blocktrail", "smartbit", "toshi"),
#            "testnet": ("chain.so", "blockexplorer", "blockr", "webbtc")
#            }


def set_api(svc="bci", code=""):
    """Set API code for web service"""
    if svc == "bci":
        global BCI_API
        BCI_API = code
    if svc == "blockstrap":
        global CHAIN_API
        CHAIN_API = code


# Makes a request to a given URL (first arg) and optional params (second arg)
def make_request(*args):
    opener = build_opener()
    opener.addheaders = [('User-agent', 'Mozilla/5.0%d' % random.randrange(1000000))]
    try:
        return opener.open(*args).read().strip().encode('utf-8')
    except Exception as e:
        try:
            p = e.read().strip().encode('utf-8')
        except:
            p = e
        raise Exception(p)



def is_testnet(inp):
    '''Checks if inp is a testnet address, TXID or Push TxHex''' 
    if isinstance(inp, dict):
        from bitcoin.transaction import serialize
        return is_testnet(serialize(inp))
    elif not isinstance(inp, basestring):    # sanity check
        raise TypeError("Cannot check %s, only string or dict" % str(type(inp)))

    ## ADDRESSES
    if inp[0] in "123mn":
        if re.match("^[2mn][a-km-zA-HJ-NP-Z0-9]{26,33}$", inp):
            return True 
        elif re.match("^[13][a-km-zA-HJ-NP-Z0-9]{26,33}$", inp):
            return False
        sys.stderr.write("Bad address format %s")
        return None
    ## TXID
    elif re.match('^[0-9a-fA-F]{64}$', inp):
        try:
            jdata = json.loads(make_request("%s/tx/%s" % (BETURL, inp)))    # Try Testnet
            return True 
        except:
            jdata = json.loads(make_request("%s/tx/%s" % (BEURL, inp)))     # Try Mainnet
            return False
        sys.stderr.write("TxID %s has no match for testnet or mainnet (Bad TxID)")
        return None

    ## PUSHTX
    #elif (inp[:8] == '01000000' or inp[:4] == b'\x01\x00\x00\x00'):
    #    return False
    else:
        return None


def set_network(*args):
    '''Decides if args are mainnet or testnet and returns network name'''
    if not args:
        return "btc"
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
    #                      unspent(addr1, addr2, addr3, network)
    
    #if len(args) >= 1 and args[-1] not in ('testnet', 'btc'):
    #    addr_args = args
    addr_args = args
    network = None
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
def bci_unspent(*args, **kwargs):
    addrs, network = parse_addr_args(*args)
    if not network == "btc":
        raise Exception("BCI only supports mainnet, Network %s unsupported" % network)
    u = []
    for a in addrs:
        try:
            data = make_request('https://blockchain.info/unspent?address=%s' % a)
        except Exception as e:
            if str(e) == 'No free outputs to spend':
                continue
            else:
                raise Exception(e)
        try:
            jsonobj = json.loads(data)
            for o in jsonobj["unspent_outputs"]:
                h = hexify(unhexify(o['tx_hash'])[::-1])
                u.append({
                    "output": h+':'+str(o['tx_output_n']),
                    "value": o['value']
                })
        except:
            raise Exception("Failed to decode data: "+data)
    return u


def be_unspent(*args, **kwargs):
    addrs, _ = parse_addr_args(*args)
    network == kwargs.get("network", set_network(*args))
    u = []
    for a in addrs:
        try:
            data = make_request('%s/addr/%s/utxo?noCache=1' % ((BETURL if network == "testnet" else BEURL), a))
        except Exception as e:
            if str(e) == 'No free outputs to spend':    # TODO: fix e
                continue
            else:
                raise Exception(e)
        try:
            jsonobj = json.loads(data)
            for o in jsonobj:
                h = o['txid']
                u.append({
                    "output": '%s:%d' % (o["txid"], o["vout"]),
                    "value": int(o['amount']*1e8 + 0.5)
                })
        except:
            raise Exception("Failed to decode data: "+data)
    return u

def blockr_unspent(*args):
    # Valid input formats: blockr_unspent([addr1, addr2,addr3])
    #                      blockr_unspent(addr1, addr2, addr3)
    #                      blockr_unspent([addr1, addr2, addr3], network)
    #                      blockr_unspent(addr1, addr2, addr3, network)
    # Where network is 'btc' or 'testnet'
    network, addr_args = parse_addr_args(*args)

    if network == 'testnet':
        blockr_url = 'http://tbtc.blockr.io/api/v1/address/unspent/'
    elif network == 'btc':
        blockr_url = 'http://btc.blockr.io/api/v1/address/unspent/'
    else:
        raise Exception(
            'Unsupported network {0} for blockr_unspent'.format(network))

    if len(addr_args) == 0:
        return []
    elif isinstance(addr_args[0], list):
        addrs = addr_args[0]
    else:
        addrs = addr_args
    res = make_request(blockr_url+','.join(addrs))
    data = json.loads(res)['data']
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
    url = base_url % 'testnet' if network == 'testnet' else base_url % "blockchain"
    offset, txs = 0, []
    for addr in addrs:
        # TODO: fix multi address search
        while True:
            data = make_request(url + "/addresses/%s/unspent-outputs?per_page=20" % addr)
            try:
                jsondata = json.loads(data)
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
    if len(args) == 0:
        return []
    elif len(args) == 2 and isinstance(args[0], list):
        addrs, network = args[0], args[-1]
    elif len(args) > 2:
        addrs, network = args[:-1], args[-1]
    else:
        addrs = args
        network = "btc"

    if network == "testnet":

        #utxos = []  # using https://chain.so/api/v2/get_tx_unspent/BTCTEST/%s
        #stxos = []            # spent utxos: https://chain.so/api/v2/get_tx_spent/BTCTEST/_ADDR_
        # Txs received: https://chain.so/api/v2/get_tx_received/BTCTEST/
        txs = []    # using https://api.biteasy.com/blockchain/v1/transactions?address=_ADDR_
        api = '' #"?api_key=%s" % BLOCKSTRAP_API if BLOCKSTRAP_API else ''
        for addr in addrs:
            offset = 0
            while 1:
                gathered = False
                while not gathered:
                    try:
                        data = make_request(
                            "https://api.blockstrap.com/v0/btct/address/unspents/%s?showtxn=1?records=300%s" % (addr, api))
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
                    raise Exception("Failed to decode data: " + data)
                assert addr in str(jsonobj['data']['address']['address']), \
                    "Tx data doesn't match address %s" % addr
                txs.extend(jsonobj['data']['address']['transactions'])
                if len(jsonobj['data']['address']['inout_count_total']) >= 300: # because records=300
                    break
                offset += 100
                sys.stderr.write("Fetching more transactions... " + str(offset) + '\n')
        outs = {}
        for tx in txs:
            for o in tx["out"]:
                if o.get('addr', None) in addrs:
                    key = str(tx["tx_index"]) + ':' + str(o["n"])
                    outs[key] = {
                        "address": o["addr"],
                        "value": o["value"],
                        "output": tx["hash"] + ':' + str(o["n"]),
                        "block_height": tx.get("block_height", None)
                    }
            # key = str(tx.get("time", "")) + ':' + str(tx.get("input_number", ''))
            # outs[key] = {
            #     "address": addr,
            #     "value": int(1e8*(float(tx["value"]) + 5e-9)),
            #     "output": tx["hash"] + ':' + str(tx["input_number"]),
            #     "time": tx['time'],
            #     "block_height":
            # }
        # for tx in txs:
        #     for i, inp in enumerate(tx["inputs"]):
        #         if "prev_out" in inp:
        #             if inp["prev_out"]["addr"] in addrs:
        #                 key = str(inp["prev_out"]["tx_index"]) + \
        #                       ':' + str(inp["prev_out"]["n"])
        #                 if outs.get(key):
        #                     outs[key]["spend"] = tx["hash"] + ':' + str(i)
            return [outs[k] for k in reversed(sorted(outs))]
    elif network == "btc":
        txs = []
        for addr in addrs:
            offset = 0
            while 1:
                gathered = False
                while not gathered:
                    try:
                        data = make_request(
                            'https://blockchain.info/address/%s?format=json&offset=%s' %
                            (addr, offset))
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


# Pushes a transaction to the network using https://blockchain.info/pushtx
def bci_pushtx(tx):
    if not re.match('^[0-9a-fA-F]*$', tx): 
        tx = hexify(tx)
    return make_request('https://blockchain.info/pushtx', 'tx='+tx)


def eligius_pushtx(tx):
    if not re.match('^[0-9a-fA-F]*$', tx): tx = hexify(tx)
    s = make_request(
        'http://eligius.st/~wizkid057/newstats/pushtxn.php',
        'transaction='+tx+'&send=Push')
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
        raise Exception(
            'Unsupported network {0} for blockr_pushtx'.format(network))

    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = hexify(tx)
    return make_request(blockr_url, '{"hex":"%s"}' % tx)


def helloblock_pushtx(tx):
    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = hexify(tx)
    return make_request('https://mainnet.helloblock.io/v1/transactions',
                        'rawTxHex='+tx)

def webbtc_pushtx(tx, network='btc'):
    if network == 'testnet':
        webbtc_url = 'http://test.webbtc.com/relay_tx.json'
    elif network == 'btc':
        webbtc_url = 'http://webbtc.com/relay_tx.json'
    else:
        raise Exception(
            'Unsupported network {0} for blockr_pushtx'.format(network))

    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = hexify(tx)
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
        data = make_request('https://testnet.blockexplorer.com/api/status?q=getBlockCount')
        jsonobj = json.loads(data)
        return jsonobj["blockcount"]
    data = make_request('https://blockexplorer.com/api/status?q=getBlockCount')
    jsonobj = json.loads(data)
    return jsonobj["blockcount"]


# Gets a specific transaction
def bci_fetchtx(txhash):
    if isinstance(txhash, list):
        return [bci_fetchtx(h) for h in txhash]
    if not re.match('^[0-9a-fA-F]*$', txhash):
        txhash = hexify(txhash)
    data = make_request('https://blockchain.info/rawtx/'+txhash+'?format=hex')
    return data
    
def be_fetchtx(txhash, network="btc"):
    if isinstance(txhash, list):
        return [be_fetchtx(h) for h in txhash]
    if not re.match('^[0-9a-fA-F]*$', txhash):
        txhash = hexify(txhash)
    data = make_request('https://%sblockexplorer.com/api/rawtx/%s' % \
                        ("testnet." if network == "testnet" else "", txhash)
                        )
    jsonobj = json.loads(data)
    txh = jsonobj.get("rawtx")
    return txh.encode("utf-8")


def blockr_fetchtx(txhash, network='btc'):
    if network == 'testnet':
        blockr_url = 'https://tbtc.blockr.io/api/v1/tx/raw/'
    elif network == 'btc':
        blockr_url = 'https://btc.blockr.io/api/v1/tx/raw/'
    else:
        raise Exception(
            'Unsupported network {0} for blockr_fetchtx'.format(network))
    if isinstance(txhash, list):
        txhash = ','.join([hexify(x) if not re.match('^[0-9a-fA-F]*$', x)
                           else x for x in txhash])
        jsondata = json.loads(make_request(blockr_url + txhash))
        return [d['tx']['hex'] for d in jsondata['data']]
    else:
        if not re.match('^[0-9a-fA-F]*$', txhash):
            txhash = hexify(txhash)
        jsondata = json.loads(make_request(blockr_url+txhash))
        return st(jsondata['data']['tx']['hex'])    # added st() to repair unicode return hex strings for python 2


def helloblock_fetchtx(txhash, network='btc'):
    if not re.match('^[0-9a-fA-F]*$', txhash):
        txhash = hexify(txhash)
    if network == 'testnet':
        url = 'https://testnet.helloblock.io/v1/transactions/'
    elif network == 'btc':
        url = 'https://mainnet.helloblock.io/v1/transactions/'
    else:
        raise Exception(
            'Unsupported network {0} for helloblock_fetchtx'.format(network))
    data = json.loads(make_request(url + txhash))["data"]["transaction"]
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
    if network == 'testnet':
        webbtc_url = 'http://test.webbtc.com/tx/'
    elif network == 'btc':
        webbtc_url = 'http://webbtc.com/tx/'
    else:
        raise Exception(
            'Unsupported network {0} for webbtc_fetchtx'.format(network))
    if not re.match('^[0-9a-fA-F]*$', txhash):
        txhash = hexify(txhash)
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
    f = fetchtx_getters.get(svc, blockr_fetchtx)
    return f(*args)


def firstbits(address):
    if len(address) >= 25:
        return make_request('https://blockchain.info/q/getfirstbits/'+address)
    else:
        return make_request(
            'https://blockchain.info/q/resolvefirstbits/'+address)


def get_block_at_height(height, network='btc'):
    if network == 'btc':
        j = json.loads(st(make_request("https://blockchain.info/block-height/" +
                       str(height)+"?format=json")))
        for b in j['blocks']:
            if b['main_chain'] is True:
                return b
        raise Exception("Block at this height not found")
    elif network == 'testnet':
        j = json.loads(make_request("https://chain.so/api/v2/block/BTCTEST/" + str(height)))
        # FIXME: add code from 'http://tbtc.blockr.io/api/v1/block/raw/%s' ??
        return ''
        #raise Exception("Block at this height not found")

get_block_by_height = get_block_at_height


def get_block_height(blockhash, network="btc"):
    url = "https://%sblockexplorer.com/api/block/%s" % ("testnet." if network=="testnet" else "", blockhash)
    jsonobj = json.loads(make_request(url))
    return jsonobj.get("height")


def _get_block(inp):
    if len(str(inp)) < 64:
        return get_block_at_height(inp)
    else:
        return json.loads(make_request(
                          'https://blockchain.info/rawblock/'+inp))


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
        blockr_url = "http://tbtc.blockr.io/api/v1/block/raw/"
    elif network == 'btc':
        blockr_url = "http://btc.blockr.io/api/v1/block/raw/"
    else:
        raise Exception(
            'Unsupported network {0} for blockr_get_block_header_data'.format(network))

    k = json.loads(make_request(blockr_url + str(height)))
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
        blockr_url = "http://tbtc.blockr.io/api/v1/block/info/"
    elif network == 'btc':
        blockr_url = "http://btc.blockr.io/api/v1/block/info/"
    else:
        raise Exception(
            'Unsupported network {0} for get_block_timestamp'.format(network))

    import time, calendar
    if isinstance(height, list):
        k = json.loads(make_request(blockr_url + ','.join([str(x) for x in height])))
        o = {x['nb']: calendar.timegm(time.strptime(x['time_utc'],
             "%Y-%m-%dT%H:%M:%SZ")) for x in k['data']}
        return [o[x] for x in height]
    else:
        k = json.loads(make_request(blockr_url + str(height)))
        j = k['data']['time_utc']
        return calendar.timegm(time.strptime(j, "%Y-%m-%dT%H:%M:%SZ"))

block_header_data_getters = {
    'bci': bci_get_block_header_data,
    'blockr': blockr_get_block_header_data
}

def get_block_header_data(inp, **kwargs):
    f = block_header_data_getters.get(kwargs.get('source', ''),
                                      blockr_get_block_header_data)
    return f(inp, **kwargs)


def get_txs_in_block(inp):
    j = _get_block(inp)
    hashes = [t['hash'] for t in j['tx']]
    return hashes


def get_block_height(txid, network='btc'):
    base_url = 'https://bitcoin.toshi.io/api/v0/blocks/1' % \
               ('tbtc' if network == 'testnet' else 'btc')
    j = json.loads(make_request(base_url + str(txid)))
    return j['data']['block']


def get_block_coinbase(txval):
    j = _get_block(txval)
    cb = bytearray.fromhex(j['tx'][0]['inputs'][0]['script'])
    alpha = set(map(chr, list(range(32, 126))))
    res = ''.join([x for x in str(cb) if x in alpha])
    if ord(res[0]) == len(res)-1:
        return res[1:]
    return res


def biteasy_search(*args):
    if len(args) == 2 and args[-1] in ('btc', 'testnet'):
        q, network = args
    else:
        q, network = args[0], 'btc'
    base_url = 'https://api.biteasy.com/%s/v1/search?q=' % \
               ('blockchain' if network == 'btc' else 'testnet')
    data = make_request(base_url + str(q))
    data = json.loads(data)     # we're left with {'results': [...], 'type': BLOCK}
    # TODO: parse different types, eg BLOCK
    return data.get('data', repr(data))


def smartbits_search(q, network='btc'):
    if network == 'testnet':
        raise Exception("Testnet NOT supported")
    base_url = "https://api.smartbit.com.au/v1/blockchain/search?q="
    data = make_request(base_url + str(q))
    jsonobj = json.loads(data)
    assert jsonobj.get("success", False), \
        "Input:\t%s\nSearched:\t%s" % (str(q), jsonobj.get("search", "??"))
    return jsonobj.get("results", [])   # [x.get('data', '') for x in jsonobj.get('results', '')]


def estimate_fee(nblocks, network="btc"):
    url = "https://%sblockexplorer.com/api/utils/estimatefee?nbBlocks=%d" % \
          (".testnet" if network == "testnet" else "", int(nblocks))
    data = json.loads(make_request(url))
    btc_to_satoshi = lambda b: int(b*1e8 + 0.5)
    btcfee = data.get(str(nblocks), None)
    return btc_to_satoshi(btcfee)

fee_estimate = estimate_fee

def get_stats(days=1, network="btc", **kwargs):
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
        url = "https://%sblockexplorer.com/api/addr/%s" % ("testnet." if network == "testnet" else "", addr)
        data = make_request(url)
        jsonobj = json.loads(data)
        assert jsonobj.get("addrStr") == addr 
        txs[str(addr)] = jsonobj
    return txs

def get_txid_height(*args):
    # Takes     TxID, network    returns block height for that TxID
    network = args[-1] if len(args) == 2 else "btc"
    txid = args[:-1] if args[-1] in ("btc", "testnet") else str(args[0])
    if not re.match('^[0-9a-fA-F]*$', txid) or len(txid) != 64:
        raise TypeError("%s is not a valid TxID" % txid)
    url = "https://%sblockexplorer.com/api/tx/%s" % ("testnet." if network == "testnet" else "", txid)
    try:
        d = json.loads(make_request(url))
    except:     # GET EXCEPTION NAME
        network = 'testnet' if network == 'btc' else 'btc' if network == "testnet" else str(network)    # swap network
        sys.stderr.write("%s is not a valid TxID...trying %s network" % (txid, network))
        url = "https://%sblockexplorer.com/api/tx/%s" % ("testnet." if network == "testnet" else "", txid)
        try: 
            d = json.loads(make_request(url))
        except: 
            raise ValueError("TxID %s not found for either network" % txid)
    bh = d.get("blockhash")
    bhurl = "https://%sblockexplorer.com/api/block/%s" % ("testnet." if network == "testnet" else "", bh)
    bdata = json.loads(make_request(bhurl))
    return bdata.get("height")

def get_price(val=100000000, currency="usd", exchange="coinbase"):
    """v is Satoshi value (default = 1 BTC), default currency = USD$, exchange can be all"""
    if isinstance(v, float):
        v = int(val*1e8 + 0.5)
    url = "https://chain.so/api/v2/get_price/BTC/%s" % currency.upper()
    jsonobj = json.loads(make_request(url)).get("data")
    prices = {}
    for d in jsonobj.get("prices"):
        #d.pop("price_base")
        #d.pop("time")
        prices[str(d.get("exchange", "unknown"))] = float(d.get("price"))
    return prices.get(exchange.lower()) if exchange.lower() != "all" else prices
    

def get_mempool_txs(tx_count=100):
    assert 0 < int(tx_count) <= 1000
    sb_url = "https://api.smartbit.com.au/v1/blockchain/transactions/unconfirmed?limit=%d" % int(tx_count)
    jdata = json.loads(make_request(sb_url))
    txs = []
    for tx in jdata.get('transactions'):
        txs.append(dict(first_seen=tx.get('first_seen'), size=tx.get('size'), txid=tx.get('txid'), fee=float(tx.get('fee'))))
    return txs
