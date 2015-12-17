#!/usr/bin/python
from bitcoin.pyspecials import *
#from bitcoin.constants import *

import json, re, binascii, datetime, requests, urlparse, urllib2
import random
import sys 
from urlparse import urljoin
try:    
    from urllib.request import build_opener, Request
except: 
    from urllib2 import build_opener, Request, HTTPError

FLAG_TESTNET = None

BET_URL, BE_URL = "https://testnet.blockexplorer.com/api", "https://blockexplorer.com/api"
BLOCKRT_URL, BLOCKR_URL = "http://tbtc.blockr.io/api/v1", "http://btc.blockr.io/api/v1"
BLOCKSTRAPT_URL, BLOCKSTRAP_URL = "https://api.blockstrap.com/v0/btct", "https://api.blockstrap.com/v0/btc"
BLOCKCYPHERT_URL, BLOCKCYPHER_URL = 'https://api.blockcypher.com/v1/btc/test3/', 'https://api.blockcypher.com/v1/btc/main/'
CHAINCOM_API_ID, CHAINCOM_API_SECRET = "api-key-id=%s" % "DEMO-4a5e1e4", "DEMO-f8aef80"


def set_api(svc="blockcypher", code=""):
    """Set API code for web service"""
    if not code:
        raise ValueError("API code wasn't set")
    varname = "{svc}_API".format(svc=svc.strip().upper())
    globals()[varname] = code

        
#def request(url, data=None, headers=None, params=None, **kwargs):
#    import requests
#    is_json_str = lambda s: isinstance(s, string_types) and set(s[0]+s[-1]) < set('''\'"[]{}''')
#    nonce = random.randrange(999999)
#    method = "POST" if data is not None else str(kwargs.get("method")).upper() \
#              if kwargs.get("method", None) is not None else "GET"
#    headers = headers if isinstance(headers, dict) else kwargs.get("headers") \
#                if kwargs.get("headers", None) else {}
#    headers.update({
#                "User-agent":     "Mozilla/5.0%d" % nonce, 
#                "Accept":         "application/json", 
#                "Accept-Charset": "utf-8",
#              })
#    params, data = kwargs.get("params", None), kwargs.get("data", None)
#    params = json.dumps(params) if isinstance(params, dict) else params
#    data = json.dumps(data) if isinstance(params, dict) else data
#    if method == 'GET':
#        req = requests.get(url, headers=headers, params=params)
#    if method == "POST":
#        headers.update({"Content-Type": "application/json"})
#        req = requests.post(url, data=data, params=params)
#    if req.status_code != requests.codes.ALL_OK:
#        error_txt = req.json() if is_json_str(req.content) else req.content
#        raise Exception("%d error!\t%s\nContent:\t%s" %(req.status_code, req.reason, error_txt))
#    try:
#        return req.json()
#    except (TypeError, ValueError):
#        return req.text.encode()


def make_request(*args, **kwargs):
    opener = build_opener()
    nonce = random.randrange(999999)
    headers = kwargs.get('headers') or \
             { "User-agent":  "Mozilla/5.0%d" % nonce, 
                "Accept":     "application/json", 
              }
    if len(args) == 2:
        url, data = args
        headers.update({"Content-Type": "application/json"})
        method = "POST"
    elif len(args) == 1:
        url = args[0]
        data = None
        method = "GET"
    data = json.dumps(data) if isinstance(data, dict) else data
    req = urllib2.Request(url, data=data, headers=headers)
    try:
        return urllib2.urlopen(req).read().strip()
    except urllib2.HTTPError as e:
        raise e

def is_testnet(inp):
    '''Checks if inp is a testnet address or if input is a known testnet TxID or blockhash''' 
    if isinstance(inp, (list, tuple)) and len(inp) >= 1:
        return any([is_testnet(x) for x in inp])
    elif not isinstance(inp, basestring):    # sanity check
        raise TypeError("Input must be str/unicode, not type %s" % str(type(inp)))

    if inp in (None, "btc", "testnet"): 
        pass

    ## ADDRESSES
    if inp[0] in "123mn":
        if re.match("^[2mn][a-km-zA-HJ-NP-Z0-9]{26,35}$", inp):
            req = json.loads(make_request("https://testnet.blockexplorer.com/api/addr-validate/{addr}".format(addr=inp)))
            return req
        elif re.match("^[13][a-km-zA-HJ-NP-Z0-9]{26,35}$", inp):
            req = json.loads(make_request("https://blockexplorer.com/api/addr-validate/{addr}".format(addr=inp)))
            return req
        else:
            #sys.stderr.write("Bad address format %s")
            return None

    ## TXID 
    elif re.match('^[0-9a-fA-F]{64}$', inp) or len(inp)==32:
        base_url = "http://api.blockcypher.com/v1/btc/{network}/txs/{txid}?includesHex=false"
        try:         # try testnet fetchtx
            make_request(base_url.format(network="test3", txid=inp.lower()))
            return True
        except:      # try mainnet fetchtx
            make_request(base_url.format(network="main", txid=inp.lower()))
            return False
        #sys.stderr.write("TxID %s has no match for testnet or mainnet (Bad TxID)")
        return None
        
    elif re.match(ur'^(00000)[0-9a-f]{59}$', inp) or len(inp)==32:
        base_url = "http://api.blockcypher.com/v1/btc/{network}/blocks/{blockhash}"
        try:
            make_request(base_url.format(network="test3", blockhash=inp.lower()))
            return True
        except:
            make_request(base_url.format(network="main", blockhash=inp.lower()))
            return False
        return None
    else:
        raise TypeError("{0} is unknown input".format(inp))


def set_network(*args):
    '''Decides if args for unspent/fetchtx/pushtx are mainnet or testnet'''
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


# Gets the unspent outputs of one or more addresses

def be_unspent(*args, **kwargs):
    try: addrs, network = parse_addr_args(*args)
    except: network = "btc", args[:-1]
    u = []
    baseurl = "https://{network}blockexplorer.com/api/addr/{address}/utxo?noCache=1"
    for a in addrs:
        try:
            data = make_request(baseurl.format(network=("testnet." if network=="testnet" else ""), address=a))
        except Exception as e: 
            if str(e) == 'No free outputs to spend':     # TODO: fix bloxkexplorer exception
                continue
            else: 
                raise Exception(e)
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
    # Where network is 'btc' or 'testnet'
    addr_args, network = parse_addr_args(*args)

    if network == 'testnet':
        blockr_url = 'http://tbtc.blockr.io/api/v1/address/unspent/'
    elif network == 'btc':
        blockr_url = 'http://btc.blockr.io/api/v1/address/unspent/'
    else:
        raise Exception('Unsupported network {0} for blockr_unspent'.format(network))

    res = make_request(blockr_url + ','.join(addr_args))
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


#def biteasy_unspent(*args):
#    addrs, network = parse_addr_args(*args)
#    base_url = "https://api.biteasy.com/{network}/v1/addresses/{addr}/unspent-outputs?per_page=20"
#    offset, txs = 0, []
#    for addr in addrs:
#        url = base_url.format(network=('testnet' if network=='testnet' else 'blockchain'), addr=addr)
#        # TODO: fix multi address search
#        while True:
#            data = make_request(url)
#            try:
#                jsondata = json.loads(data.decode('utf-8'))
#            except:
#                raise Exception("Could not decode JSON data")
#            txs.extend(jsondata['data']['outputs'])
#            if jsondata['data']['pagination']['next_page'] is False:
#                break
#            offset += 20 # jsondata['data']['pagination']["per_page"]
#            sys.stderr.write("Fetching more transactions... " + str(offset) + '\n')
#        o = []
#        for utxo in txs:
#            assert utxo['to_address'] == addr and utxo['is_spent'] == 0, "Wrong address or UTXO is spent"
#            o.append({
#                "output": "%s:%d" % (utxo['transaction_hash'], utxo['transaction_index']),
#                "value": utxo['value']
#            })
#        return o


def blockcypher_unspent(*args):
    addrs, network = parse_addr_args(*args)
    url = "http://api.blockcypher.com/v1/btc/{network}/addrs/{addr_args}?unspentOnly=true&confirmations=0".format( \
        network=("test3" if network=="testnet" else "main"), 
        addr_args=";".join(list(addrs) if isinstance(addrs, tuple) else addrs)
    )
    jdata = json.loads(make_request(url))
    u, txs = [], []
    for addrobj in ([jdata] if not isinstance(jdata, list) else jdata):
        if not addrobj.get("txrefs", None):
            return None
        else:
            txs.extend(addrobj.get("txrefs"))
        for tx in txs:
            u.append({"output": "%s:%d" % (tx.get('tx_hash'), tx.get('tx_output_n')),
                      "value": tx.get('value')})
    return u
    

unspent_getters = {
    'bci': bci_unspent,
    'blockr': blockr_unspent,
    'be': be_unspent,
    'blockcypher': blockcypher_unspent,
}


def unspent(*args, **kwargs):
    """unspent(addr, "btc", source="blockr")"""
    f = unspent_getters.get(kwargs.get('source', ''), blockcypher_unspent)
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
                        data = make_request("http://api.blockcypher.com/v1/btc/test3/addrs/%s"
                                            "?confirmations=0&limit=200&before=%d&unspentOnly=false&includeScript" % (addr, bh))
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
                if 200 <= jsonobj['n_tx']: # because records=200
                    break
                if "hasMore" in jsonobj: 
                    bh = txs[-1].get("block_height")
                offset += 200
                sys.stderr.write("Fetching more transactions... " + str(offset) + '\n')
            for tx in txs:
                tx.update(dict(address=addr))
        outs = {}
        #from bitcoin.main import hex_to_b58check, btc_to_satoshi
        for tx in txs:
            if o.get('address', None) in addrs:
                key = str(tx["confirmed"])+':'+str(o["tx_output_"])
                outs[key] = {
                    "address": o["address"],
                    "value": o["value"],
                    "output": tx["hash"]+':'+str(o["tx_output_n"]),
                    "block_height": tx.get("block_height")
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


def blockr_pushtx(tx, network=None):
    base_url = 'http://{network}.blockr.io/api/v1/tx/push'
    if network is None:
        try:    make_request(base_url.format(network="btc"),   json.dumps(dict(hex=tx)))
        except: make_request(base_url.format(network="tbtc"),  json.dumps(dict(hex=tx)))
    elif network == 'testnet':
        make_request(base_url.format(network="tbtc"), '{"hex":"%s"}' % tx)
    elif network == 'btc':
        make_request(base_url.format(network="btc"), '{"hex":"%s"}' % tx)
    else:
        raise Exception('Unsupported network {0} for blockr_pushtx'.format(network))

    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = safe_hexlify(tx)
    return make_request(blockr_url, '{"hex":"%s"}' % tx)


def helloblock_pushtx(tx, network="btc"):
    assert network == "btc"
    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = safe_hexlify(tx)
    return make_request('https://mainnet.helloblock.io/v1/transactions', 'rawTxHex=%s' % tx)


def blockcypher_pushtx(tx, network=None):
    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = safe_hexlify(tx)
    if network not in ('btc', 'testnet'):
        raise Exception('Unsupported network {0} for blockcypher_fetchtx'.format(network))
    base_url = "http://api.blockcypher.com/v1/btc/{network}/txs/push" 
    if network is None:
        try:    data = make_request(base_url.format(network='main'), json.dumps(dict(tx=tx)))
        except: data = make_request(base_url.format(network='test3'), json.dumps(dict(tx=tx)))
    try:
        data = make_request(base_url.format(network=('test3' if network=='testnet' else 'main')), json.dumps(dict(tx=tx)))
    except Exception as d: 
        if hasattr(d, 'read'):  data = d.read()
    jdata = json.loads(data)
    if 'tx' in jdata:
        reply = {}
        reply['tx_hash'] = data['tx']['hash']
        reply['success'] = True
        return reply
    elif 'error' in jdata:
        raise Exception(jdata.get('error', "Could not push tx {0}".format(tx, )))


pushtx_getters = {
    'bci': bci_pushtx,
    'blockr': blockr_pushtx,
    'blockcypher': blockcypher_pushtx,
    'helloblock': helloblock_pushtx
}


def pushtx(*args, **kwargs):
    svc = kwargs.get('source', '')
    f = pushtx_getters.get(svc, blockcypher_pushtx)
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
    

def be_fetchtx(txhash, network=None):
    network = set_network(txhash) if not network else network
    if isinstance(txhash, list):
        return [be_fetchtx(h) for h in txhash]
    if not re.match('^[0-9a-fA-F]*$', txhash):
        txhash = safe_hexlify(txhash)
    data = make_request("%s/tx/%s" % ((BET_URL if network=="testnet" else BE_URL), txhash))
    jsonobj = json.loads(data)
    txh = jsonobj.get("rawtx")
    return txh


def blockr_fetchtx(txhash, network=None):
    network = set_network(txhash) if not network else network
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
    data = request(url + txhash)["data"]["transaction"]
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


def blockcypher_fetchtx(txhash, network=''):
    if not re.match('^[0-9a-fA-F]*$', txhash):
        txhash = safe_hexlify(txhash)
    network = set_network(txhash) if network=="" else network
    base_url = 'http://api.blockcypher.com/v1/btc/{network}/txs/{txid}?includeHex=true&limit=50'
    if network == 'testnet':
        url = base_url.format(network="test3", txid=txhash.lower())
    elif network == 'btc':
        url = base_url.format(network="main", txid=txhash.lower())
    else:
        raise Exception('Unsupported network {0} for blockcypher_fetchtx'.format(network))
    jdata = json.loads(make_request(url))
    txhex = jdata.get('hex')
    from bitcoin.transaction import txhash as TXHASH
    assert TXHASH(txhex) == txhash
    return txhex


fetchtx_getters = {
    'bci': bci_fetchtx,
    'blockr': blockr_fetchtx,
    'be': be_fetchtx,
    'blockcypher': blockcypher_fetchtx,       #   http://test.webbtc.com/tx/txid.[hex,json, bin]
    'helloblock': helloblock_fetchtx
}


def fetchtx(*args, **kwargs):
    svc = kwargs.get("source", "")
    f = fetchtx_getters.get(svc, blockcypher_fetchtx)
    return f(*args)


def firstbits(address):
    if len(address) >= 25:
        return make_request('https://blockchain.info/q/getfirstbits/'+address)
    else:
        return make_request(
            'https://blockchain.info/q/resolvefirstbits/'+address)


def get_block_at_height(height, network='btc'):
    if network == 'btc':
        j = json.loads(make_request("https://blockchain.info/block-height/%s?format=json" % str(height)))
        for b in j['blocks']:
            if b['main_chain'] is True:
                return b
        raise Exception("Block at this height not found")
    elif network == 'testnet':
        try:
            j = json.loads(make_request("https://api.blockcypher.com/v1/btc/test3/blocks/%s" % str(height)))
        except:
            raise Exception("Block at this height not found")
        return j

get_block_by_height = get_block_at_height


def get_block_height(blockhash, network="btc"):
    url = "%s/api/block/%s" % (BET_URL if network=="testnet" else BE_URL, blockhash)
    jsonobj = json.loads(make_request(url))
    return jsonobj.get("height")


def _get_block(inp):
    if len(str(inp)) < 64:
        return get_block_at_height(inp)
    else:
        return json.loads(make_request('https://blockchain.info/rawblock/'+inp))

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
        blockr_url = "%s/block/info/" % BLOCKRT_URL
    elif network == 'btc':
        blockr_url = "%s/block/info/" % BLOCKR_URL
    else:
        raise Exception('Unsupported network {0} for get_block_timestamp'.format(network))

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


def biteasy_search(query, network=None):
    network = set_network(query) if network is None else network
    url = 'https://api.biteasy.com/%s/v1/search?q=%s' % (('blockchain' if network == 'btc' else 'testnet', query))
    data = json.loads(make_request(url))     # we're left with {'results': [...], 'type': BLOCK}
    assert data.get("status") == 200
    return {str(data["data"].get("type")): data["data"]["results"]}


def smartbits_search(q, network='btc'):
    if network == 'testnet':
        raise Exception("Testnet NOT supported")
    base_url = "https://api.smartbit.com.au/v1/blockchain/search?q={0}"
    jsonobj = json.loads(make_request(base_url.format(str(q))))
    assert jsonobj.get("success", False), \
        "Input:\t%s\nSearched:\t%s" % (str(q), jsonobj.get("search", "??"))
    return jsonobj.get("results", [])   # [x.get('data', '') for x in jsonobj.get('results', '')]


def estimate_fee_by_nblocks(nblocks=6, network="btc"):
    url = "%s/utils/estimatefee?nbBlocks=%d" % (BET_URL if network == "testnet" else BE_URL, int(nblocks))
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
        stats = json.loads(make_request(url))
    elif svc == "webbtc":
        if network == "testnet":
            wb_url = "http://test.webbtc.com/stats.json"
        else:
            wb_url = "http://webbtc.com/stats.json"
        stats = json.loads(make_request(wb_url))
        sys.stderr.write("Current network statistics only available, %d days disregarded" % int(days))
    return stats
    
#stats = get_stats(

def address_txlist(*args):
    addrs, network = parse_addr_args(*args)
    txs = {}
    for addr in addrs:
        url = "%s/addr/%s" % (BET_URL if network == "testnet" else BE_URL, addr)
        jsonobj = json.loads(make_request(url))
        assert jsonobj.get("addrStr") == addr 
        txs[str(addr)] = jsonobj
    return txs


def get_txid_height(txid, network=None):
    # Takes     TxID, network    returns block height for that TxID
    network = set_network(txid) if not network else network
    if not re.match('^[0-9a-fA-F]*$', txid) or len(txid) != 64:
        raise TypeError("%s is not a valid TxID" % txid)
    url = "%s/tx/%s" % (BET_URL if network == "testnet" else BE_URL, txid)
    try:
        d = json.loads(make_request(url))
    except:     # GET EXCEPTION NAME
        if network=="btc":    # swap network
            network=="testnet"
        elif network=="testnet":
            network=="btc"
        #sys.stderr.write("%s is not a valid TxID...trying %s network" % (txid, network))
        url = "%s/api/tx/%s" % (BET_URL if network == "testnet" else BE_URL, txid)
        try: 
            d = json.loads(make_request(url))
        except: 
            raise ValueError("TxID %s not found for either network" % txid)
    bh = d.get("blockhash")
    bhurl = "%s/block/%s" % (BET_URL if network == "testnet" else BE_URL, bh)
    bdata = json.loads(make_request(bhurl))
    return {"tx_hash": txid, "block_height": bdata.get("height")}


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
    

def get_mempool_txs(tx_count=100, network="btc"):
    tx_count = 1000 if tx_count > 1000 else int(tx_count)
    ##bcurl = "http://api.blockcypher.com/v1/btc/%s/txs?limit=%d" % (("test3" if network== "testnet" else "main"), int(tx_count))    # returns detailed data, list
    jdata = json.loads(make_request("https://api.smartbit.com.au/v1/blockchain/transactions/unconfirmed?limit=%d" % int(tx_count)))
    txs = []
    for tx in jdata.get('transactions', jdata):
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
    url = "http://api.blockcypher.com/v1/btc/%s/txs/decode" % ( \
        "test3" if network=="testnet" else "main" if network=="btc" else "main")
    assert rawtx[:8] == "01000000", "Not a Tx! Txs begin with '01000000'"
    if network not in (None, "btc", "testnet"):
        raise Exception("Network {0} unsupported".format(str(network)))
    body = {"tx": rawtx}
    jdata = json.loads(make_request(url, json.dumps(body)))
    if network is None:
        jdata.pop("addresses")
        for i in jdata["inputs"]:  o.pop("addresses")
        for o in jdata["outputs"]: o.pop("addresses")
    return jdata


# fromAddr, toAddr, 12345, changeAddress
def get_tx_composite(inputs, outputs, output_value, change_address=None, network=None):
    """use blockcypher API to composite a Tx"""
    inputs = [inputs] if not isinstance(inputs, list) else inputs
    outputs = [outputs] if not isinstance(outputs, list) else outputs
    network = set_network(change_address or inputs) if not network else network.lower()
    url = "http://api.blockcypher.com/v1/btc/{network}/txs/new?includeToSignTx=true".format(\
        network=('test3' if network=='testnet' else 'main'))
    is_address = lambda a: bool(re.match("^[123mn][a-km-zA-HJ-NP-Z0-9]{26,33}$", a))
    if any([is_address(x) for x in inputs]):
        inputs_type = 'addresses'        # also accepts UTXOs
    if any([is_address(x) for x in outputs]):
        outputs_type = 'addresses'
    data = {
            'inputs':  [{inputs_type:  inputs}], 
            'confirmations': 0, 
            'preference': 'high', 
            'outputs': [{outputs_type: outputs, "value": output_value}]
            }
    if change_address:
        data["change_address"] = change_address    # 
    jdata = json.loads(make_request(url, data))
    hash, txh = jdata.get("tosign")[0], jdata.get("tosign_tx")[0]
    assert bin_dbl_sha256(txh.decode('hex')).encode('hex') == hash, "checksum mismatch %s" % hash
    return txh.encode("utf-8")

blockcypher_mktx = get_tx_composite


def address_to_pubkey(addr):
    """Converts an address to public key (if available)"""
    base_url = "https://blockchain.info/q/pubkeyaddr/{addr}"
    assert not is_testnet(addr), "Testnet not supported"
    try:
        jdata = json.loads(make_request(base_url.format(addr=addr)))
    except:
        return None
    return jdata


def get_new_privkey():
    """Uses BCI API to request a new (addr, privkey) pair"""
    try:
        data = make_request("https://blockchain.info/q/newkey")
        return data
    except Exception as e:
        raise e


def address_first_seen(addr):
    assert not is_testnet(addr)
    base_url = "https://blockchain.info/q/addressfirstseen/{addr}"
    data = json.loads(make_request(base_url.format(addr=addr)))
    timestamp = data if data > 0 else -1
    return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def unconfirmed_tx_count():
    """Query BCI API for number of unconfirmed Txs in the mempool"""
    data = make_request("https://blockchain.info/q/unconfirmedcount")
    return int(data) if int(data) > 0 else -1
    

def get_rejection_info(inp):
    """Use BCI API to query why the network rejected a blockhash or a TxID"""
    assert len(inp) == 64 and bool(re.match(RE_HEXCHARS, inp))
    try:
        data = make_request("https://blockchain.info/q/rejected/{0}".format(inp))
        ## TODO: so..... now what? Need a testcase
    except Exception as e:
        raise e
    return data


def get_decoded_tx(txhex):
    """Use Smartbit API to deserialize txhex"""
    jdata = json.loads(make_request("https://api.smartbit.com.au/v1/blockchain/decodetx", 
                                    json.dumps({"hex": txhex})))
    return jdata['transaction'] if jdata['success'] == True else None


def get_doublespent_txs(tx_count=100):
    tx_count = 1000 if int(tx_count) > 1000 else int(tx_count)
    url = "https://api.smartbit.com.au/v1/blockchain/transactions/double-spends?limit=%d&dir=desc" % tx_count
    jdata = json.loads(make_request(url))
    return jdata["transactions"]
    

def get_chart(*args, **kwargs):
    """Defaults to SmartBit API, chart_type, from, to, day_average, unit
    Choose from:\t ['block-interval', 'block-reward', 'block-reward-per-block', 
    'block-size', 'block-size-total', 'blocks', 'blocks-total', 'currency-total', 
    'difficulty', 'hash-rate', 'miner-revenue', 'miner-revenue-per-block', 'output-amount', 
    'output-amount-per-block', 'transaction-fees', 'transaction-fees-per-block', 
    'transaction-fees-per-transaction', 'transactions', 'transactions-per-block', 
    'transactions-per-second', 'transactions-total']
    """
    cmds = ['block-interval', 'block-reward', 'block-reward-per-block', 'block-size', 'block-size-total', 'blocks', 'blocks-total', 'currency-total', 'difficulty', 'hash-rate', 'miner-revenue', 'miner-revenue-per-block', 'output-amount', 'output-amount-per-block', 'transaction-fees', 'transaction-fees-per-block', 'transaction-fees-per-transaction', 'transactions', 'transactions-per-block', 'transactions-per-second', 'transactions-total']
    if len(args) < 1:
        print '\n'.join(cmds)
    elif len(args) == 1:
        chart_type = args[0].strip().lower()
    params = {}
    if kwargs.get('from') and kwargs.get('to'):
        assert str(kwargs.get('from')).count('-')
        assert str(kwargs.get('from')) <  str(kwargs.get('to'))
        params['from'] = kwargs.get('from')
        params['to'] = kwargs.get('to')
    if kwargs.get('day_average'):
        assert str(kwargs.get('day_average')).isdigit()
        params['day_average'] = kwargs.get('day_average')
    if kwargs.get('unit'):
        params['unit'] = kwargs.get('unit')


# CHAIN.COM

def get_opreturns_by_addr(addr):
    network = set_network(addr)
    base_url = 'https://api.chain.com/v1/{network}/addresses/{address}/op-returns?api-key-id=DEMO-4a5e1e4'
    url = base_url.format(network=('bitcoin' if network=='btc' else 'testnet3'), address=addr)
    jdata = json.loads(make_request(url))
    for tx in jdata:
        del tx['sender_addresses']
        del tx['receiver_addresses']
        del tx['hex']
    return jdata
    

def get_opreturns_by_blockheight(blockheight, network='btc'):
    lastbh = int(last_block_height(network))
    assert 0 <= int(blockheight) <= lastbh, "Invalid blockheight %d for %s network" % (blockheight, network)
    base_url = 'https://api.chain.com/v1/{network}/blocks/{blockheight}/op-returns?api-key-id=DEMO-4a5e1e4'
    url = base_url.format(network=('bitcoin' if network=='btc' else 'testnet3'), blockheight=str(blockheight))
    jdata = json.loads(make_request(url))
    return jdata
    

def get_opreturns_by_blockhash(blockhash, network='btc'):
    base_url = 'https://api.chain.com/v1/{network}/blocks/{blockhash}/op-returns?api-key-id=DEMO-4a5e1e4'
    url = base_url.format(network=('bitcoin' if network=='btc' else 'testnet3'), blockheight=blockhash)
    jdata = json.loads(make_request(url))
    return jdata
    
    
def get_opreturns_by_transaction(txid, network=None):
    network = set_network(txid)
    base_url = 'https://api.chain.com/v1/{network}/transactions/{txid}/op-returns?api-key-id=DEMO-4a5e1e4'
    url = base_url.format(network=('bitcoin' if network=='btc' else 'testnet3'), txid=txid)
    jdata = json.loads(make_request(url))
    return jdata    
    

def get_xpub_unspent_addrs(*args):
    """Takes bip32 xpub (or xprv) and returns addresses with balance"""
    from bitcoin.main import multiaccess, pubtoaddr
    from bitcoin.deterministic import bip32_descend, bip32_ckd, bip32_privtopub
    xpubs = [bip32_privtopub(x) if x.startswith("xprv") else x for x in args]
    data = {"addr": " ".join(xpubs)}
    jdata = json.loads(make_request("https://www.blockonomics.co/api/balance", json.dumps(data)))
    jdata = jdata.get("response")
    addrs, values = multiaccess(jdata,"addr"), multiaccess(jdata,"confirmed")
    d = dict.fromkeys(xpubs, {})
    for xpub in xpubs:
        c, i = 0, 0
        while c <= 1:
            addr = pubtoaddr(bip32_descend(bip32_ckd(xpub, c), i))
            if addr in addrs:
                d[xpub].update({
                                "m/%d/%d" % (c, i): "%s:%d" % (addr, values[addrs.index(addr)])
                                })
            else:
                c += 1
            i += 1
    return d


def get_xpub_addrs(*args):
    """Returns all known (used) addresses for xpub(s)"""
    from bitcoin.main import multiaccess
    xpubs = [bip32_privtopub(x) if x.startswith("xprv") else x for x in args]
    jdata = json.loads(make_request("https://www.blockonomics.co/api/balance", \
                                      json.dumps({"addr": " ".join(xpubs)}))).get("response")
    addrs = multiaccess(jdata, "addr")
    return addrs


def get_xpub_outputs(*args):
    from bitcoin.main import multiaccess
    xpubs = [bip32_privtopub(x) if x.startswith("xprv") else x for x in args]
    jdata = json.loads(make_request("https://www.blockonomics.co/api/balance", \
                                      json.dumps({"addr": " ".join(xpubs)}))).get("response")
    addrs = multiaccess(jdata, 'addrs')
    values = map(str, multiaccess(jdata, "confirmed" or "unconfirmed"))
    return [":".join(y) for y in [x for x in zip(addrs, values)]]           

    #pubtoaddr(bip32_descend(bip32_ckd(hdpub, 1), 2))
    # args = ('xpub6BjpJL49CajcQvGn5pXVpmFe5PtcHf2AtCyPJ1Tkqe6uuCTMott1NdbV49j3DA9VTSWSFDdzHxvFVfggUy3YQe5WTSZ7Q4692cCCU8Zby9D', 'xpub6BfKpqjTwvH21wJGWEfxLppb8sU7C6FJge2kWb9315oP4ZVqCXG29cdUtkyu7YQhHyfA5nt63nzcNZHYmqXYHDxYo8mm1Xq1dAC7YtodwUR', 'xpub661MyMwAqRbcGJRSqFchVsmi1RvxEb546fePRgitBdSxrxgbw9uJCkUoXWmmVmsK3oYh5mMKSqd7TZ69jKf5DeCvWYyDfpn2Yp4ubeRkUph')
#    [{u'confirmed': 0, u'addr': u'1uN4DmnMkpJdhYvNZLDKN3hofUNm9Ff6K', u'unconfirmed': 0}, {u'confirmed': 0, u'addr': u'1FrnEuikP8n2fDvFL5XixeGPS4Y6uURpPd', u'unconfirmed': 0}, {u'confirmed': 55600, u'addr': u'1MEXcYwATz7WGQoHedNS1qT4XuadYhAF7c', u'unconfirmed': 0}, {u'confirmed': 0, u'addr': u'13eWZHytgWzFuxH7nv3tpvBZRPZEAPPf4S', u'unconfirmed': 0}, {u'confirmed': 244400, u'addr': u'1GGfUGHLDoacYKcyuS8XXv3cf4qwBcxUPn', u'unconfirmed': 0}, {u'confirmed': 0, u'addr': u'1699DqGc1TRSyfBPZ9mT615JHZWonEMf84', u'unconfirmed': 0}]
