"""
Patricia tree for hashing unspents
"""

import plyvel
import ast
import os
import threading
import json

from ecdsa.keys import BadSignatureError

from lbryschema.decode import smart_decode
from lbryschema.error import DecodeError, URIParseError, CertificateError
from lbryschema.uri import parse_lbry_uri

from lbryumserver.processor import print_log, logger
from lbryumserver.utils import bc_address_to_hash_160, hex_to_int, int_to_hex, Hash
from lbryumserver import deserialize

# increase this when database needs to be updated
global GENESIS_HASH
GENESIS_HASH = '9c89283ba0f3227f6c03b70216b9f665f0118d5e0fa729cedf4fb34d6a34f463'
DB_VERSION = 4
KEYLENGTH = 56  # 20 + 32 + 4


class Node(object):
    def __init__(self, s):
        self.k = int(s[0:32].encode('hex'), 16)
        self.s = s[32:]
        if self.k == 0 and self.s:
            print "init error", len(self.s), "0x%0.64X" % self.k
            raise BaseException("z")

    def serialized(self):
        k = "0x%0.64X" % self.k
        k = k[2:].decode('hex')
        assert len(k) == 32
        return k + self.s

    def has(self, c):
        return (self.k & (1 << (ord(c)))) != 0

    def is_singleton(self, key):
        assert self.s != ''
        return len(self.s) == 40

    def get_singleton(self):
        for i in xrange(256):
            if self.k == (1 << i):
                return chr(i)
        raise BaseException("get_singleton")

    def indexof(self, c):
        assert self.k != 0 or self.s == ''
        x = 0
        for i in xrange(ord(c)):
            if (self.k & (1 << i)) != 0:
                x += 40
        return x

    def get(self, c):
        x = self.indexof(c)
        ss = self.s[x:x + 40]
        _hash = ss[0:32]
        value = hex_to_int(ss[32:40])
        return _hash, value

    def set(self, c, h, value):
        if h is None:
            h = chr(0) * 32
        vv = int_to_hex(value, 8).decode('hex')
        item = h + vv
        assert len(item) == 40
        if self.has(c):
            self.remove(c)
        x = self.indexof(c)
        self.s = self.s[0:x] + item + self.s[x:]
        self.k |= (1 << ord(c))
        assert self.k != 0

    def remove(self, c):
        x = self.indexof(c)
        self.k &= ~(1 << ord(c))
        self.s = self.s[0:x] + self.s[x + 40:]

    def get_hash(self, x, parent):
        if x:
            assert self.k != 0
        skip_string = x[len(parent) + 1:] if x != '' else ''
        x = 0
        v = 0
        hh = ''
        for i in xrange(256):
            if (self.k & (1 << i)) != 0:
                ss = self.s[x:x + 40]
                hh += ss[0:32]
                v += hex_to_int(ss[32:40])
                x += 40
        try:
            _hash = Hash(skip_string + hh)
        except:
            _hash = None
        if x:
            assert self.k != 0
        return _hash, v

    @classmethod
    def from_dict(klass, d):
        k = 0
        s = ''
        for i in xrange(256):
            if chr(i) in d:
                k += 1 << i
                h, value = d[chr(i)]
                if h is None: h = chr(0) * 32
                vv = int_to_hex(value, 8).decode('hex')
                item = h + vv
                assert len(item) == 40
                s += item
        k = "0x%0.64X" % k  # 32 bytes
        k = k[2:].decode('hex')
        assert len(k) == 32
        out = k + s
        return Node(out)


class DB(object):
    def __init__(self, path, name, cache_size):
        self.db = plyvel.DB(os.path.join(path, name), create_if_missing=True, compression=None,
                            lru_cache_size=cache_size)
        self.batch = self.db.write_batch()
        self.cache = {}
        self.lock = threading.Lock()

    def put(self, key, s):
        self.batch.put(key, s)
        self.cache[key] = s

    def get(self, key):
        s = self.cache.get(key)
        if s == 'deleted':
            return None
        if s is None:
            with self.lock:
                s = self.db.get(key)
        return s

    def delete(self, key):
        self.batch.delete(key)
        self.cache[key] = 'deleted'

    def close(self):
        self.db.close()

    def write(self):
        with self.lock:
            self.batch.write()
            self.batch.clear()
            self.cache.clear()

    def get_next(self, key):
        with self.lock:
            i = self.db.iterator(start=key)
            k, _ = i.next()
            return k


class Storage(object):
    def __init__(self, config, shared, test_reorgs):
        self.shared = shared
        self.hash_list = {}
        self.parents = {}
        self.skip_batch = {}
        self.test_reorgs = test_reorgs
        # init path
        self.dbpath = config.get('leveldb', 'path')
        if not os.path.exists(self.dbpath):
            os.mkdir(self.dbpath)
        try:
            self.db_utxo = DB(self.dbpath, 'utxo', config.getint('leveldb', 'utxo_cache'))
            self.db_hist = DB(self.dbpath, 'hist', config.getint('leveldb', 'hist_cache'))
            self.db_addr = DB(self.dbpath, 'addr', config.getint('leveldb', 'addr_cache'))
            self.db_undo = DB(self.dbpath, 'undo', None)
            self.db_claimid = DB(self.dbpath, 'claimid', config.getint('leveldb', 'claimid_cache'))
            self.db_undo_claim = DB(self.dbpath, 'undo_claim', 256 * 1024 * 1024)
            self.db_claim_values = DB(self.dbpath, 'claim_values',
                                      config.getint('leveldb', 'claim_value_cache'))
            self.db_claim_height = DB(self.dbpath, 'claim_height', 4 * 1024 * 1024)
            self.db_claim_names = DB(self.dbpath, 'claim_names', 64 * 1024 * 1024)
            self.db_claim_order = DB(self.dbpath, 'claim_order', 4 * 1024 * 1024)
            self.db_certificate_claims = DB(self.dbpath, 'certificate_claim', 128 * 1024 * 1024)
            self.db_signed_claims = DB(self.dbpath, 'signed_claims', 256 * 1024 * 1024)
            self.db_claim_addrs = DB(self.dbpath, 'claim_addresses', 64 * 1024 * 1024)
        except:
            logger.error('db init', exc_info=True)
            self.shared.stop()
        try:
            self.last_hash, self.height, db_version = ast.literal_eval(self.db_undo.get('height'))
        except:
            print_log('Initializing database')
            self.height = 0
            self.last_hash = GENESIS_HASH
            self.pruning_limit = config.getint('leveldb', 'pruning_limit')
            db_version = DB_VERSION
            self.put_node('', Node.from_dict({}))
        # check version
        if db_version != DB_VERSION:
            print_log("Your database '%s' is deprecated. Please create a new database" % self.dbpath)
            self.shared.stop()
            return
        # pruning limit
        try:
            self.pruning_limit = ast.literal_eval(self.db_undo.get('limit'))
        except:
            self.pruning_limit = config.getint('leveldb', 'pruning_limit')
            self.db_undo.put('version', repr(self.pruning_limit))
        # compute root hash
        root_node = self.get_node('')
        self.root_hash, coins = root_node.get_hash('', None)
        # print stuff
        print_log("Database version %d." % db_version)
        print_log("Pruning limit for spent outputs is %d." % self.pruning_limit)
        print_log("Blockchain height", self.height)
        print_log("UTXO tree root hash:", self.root_hash.encode('hex'))
        print_log("Coins in database:", coins)

    # convert between lbry addresses and 20 bytes keys used for storage.
    @staticmethod
    def address_to_key(addr):
        return bc_address_to_hash_160(addr)

    def get_skip(self, key):
        o = self.skip_batch.get(key)
        if o is not None:
            return o
        k = self.db_utxo.get_next(key)
        assert k.startswith(key)
        return k[len(key):]

    def set_skip(self, key, skip):
        self.skip_batch[key] = skip

    def get_proof(self, addr):
        key = self.address_to_key(addr)
        k = self.db_utxo.get_next(key)
        p = self.get_path(k)
        p.append(k)
        out = []
        for item in p:
            v = self.db_utxo.get(item)
            out.append((item.encode('hex'), v.encode('hex')))
        return out

    def get_balance(self, addr):
        key = self.address_to_key(addr)
        k = self.db_utxo.get_next(key)
        if not k.startswith(key):
            return 0
        p = self.get_parent(k)
        d = self.get_node(p)
        letter = k[len(p)]
        return d.get(letter)[1]

    def listunspent(self, addr):
        key = self.address_to_key(addr)
        if key is None:
            raise BaseException('Invalid lbrycrd address', addr)
        out = []
        with self.db_utxo.lock:
            for k, v in self.db_utxo.db.iterator(start=key):
                if not k.startswith(key):
                    break
                if len(k) == KEYLENGTH:
                    txid = k[20:52].encode('hex')
                    txpos = hex_to_int(k[52:56])
                    h = hex_to_int(v[8:12])
                    v = hex_to_int(v[0:8])
                    out.append({'tx_hash': txid, 'tx_pos': txpos, 'height': h, 'value': v})
                if len(out) == 1000:
                    print_log('max utxo reached', addr)
                    break

        out.sort(key=lambda x: x['height'])
        return out

    def get_history(self, addr):
        out = []
        o = self.listunspent(addr)
        for item in o:
            out.append((item['height'], item['tx_hash']))
        h = self.db_hist.get(addr)
        while h:
            item = h[0:80]
            h = h[80:]
            txi = item[0:32].encode('hex')
            hi = hex_to_int(item[36:40])
            txo = item[40:72].encode('hex')
            ho = hex_to_int(item[76:80])
            out.append((hi, txi))
            out.append((ho, txo))
        # uniqueness
        out = set(out)
        # sort by height then tx_hash
        out = sorted(out)
        return map(lambda x: {'height': x[0], 'tx_hash': x[1]}, out)

    def get_claim_value(self, claim_id):
        return self.db_claim_values.get(claim_id)

    def get_claim_height(self, claim_id):
        height = self.db_claim_height.get(claim_id)
        if height is not None:
            return int(height)

    def get_claim_address(self, claim_id):
        return self.db_claim_addrs.get(claim_id)

    def get_claim_name(self, claim_id):
        return self.db_claim_names.get(claim_id)

    def get_address(self, txi):
        return self.db_addr.get(txi)

    def get_undo_claim_info(self, claim_id):
        s = self.db_undo_claim.get(claim_id)
        if s is None:
            print_log('no undo info for {}'.format(claim_id))

        return eval(s)

    def write_undo_claim_info(self, height, lbrycrdd_height, claim_id, undo_info):
        if height > lbrycrdd_height - 100 or self.test_reorgs:
            self.db_undo_claim.put(claim_id, repr(undo_info))

    def get_undo_info(self, height):
        s = self.db_undo.get("undo_info_%d" % (height % 100))
        if s is None:
            print_log("no undo info for ", height)
        return eval(s)

    def write_undo_info(self, height, lbrycrdd_height, undo_info):
        if height > lbrycrdd_height - 100 or self.test_reorgs:
            self.db_undo.put("undo_info_%d" % (height % 100), repr(undo_info))

    @staticmethod
    def common_prefix(word1, word2):
        max_len = min(len(word1), len(word2))
        for i in xrange(max_len):
            if word2[i] != word1[i]:
                index = i
                break
        else:
            index = max_len
        return word1[0:index]

    def put_node(self, key, node):
        self.db_utxo.put(key, node.serialized())

    def get_node(self, key):
        s = self.db_utxo.get(key)
        if s is None:
            return
        return Node(s)

    def add_key(self, target, value, height):
        assert len(target) == KEYLENGTH
        path = self.get_path(target, new=True)
        if path is True:
            return
        # print "add key: target", target.encode('hex'), "path", map(lambda x: x.encode('hex'), path)
        parent = path[-1]
        parent_node = self.get_node(parent)
        n = len(parent)
        c = target[n]
        if parent_node.has(c):
            h, v = parent_node.get(c)
            skip = self.get_skip(parent + c)
            child = parent + c + skip
            assert not target.startswith(child)
            prefix = self.common_prefix(child, target)
            index = len(prefix)

            if len(child) == KEYLENGTH:
                # if it's a leaf, get hash and value of new_key from parent
                d = Node.from_dict({
                    target[index]: (None, 0),
                    child[index]: (h, v)
                })
            else:
                # if it is not a leaf, update its hash because skip_string changed
                child_node = self.get_node(child)
                h, v = child_node.get_hash(child, prefix)
                d = Node.from_dict({
                    target[index]: (None, 0),
                    child[index]: (h, v)
                })
            self.set_skip(prefix + target[index], target[index + 1:])
            self.set_skip(prefix + child[index], child[index + 1:])
            self.put_node(prefix, d)
            path.append(prefix)
            self.parents[child] = prefix

            # update parent skip
            new_skip = prefix[n + 1:]
            self.set_skip(parent + c, new_skip)
            parent_node.set(c, None, 0)
            self.put_node(parent, parent_node)
        else:
            # add new letter to parent
            skip = target[n + 1:]
            self.set_skip(parent + c, skip)
            parent_node.set(c, None, 0)
            self.put_node(parent, parent_node)

        # write the new leaf
        s = (int_to_hex(value, 8) + int_to_hex(height, 4)).decode('hex')
        self.db_utxo.put(target, s)
        # the hash of a leaf is the txid
        _hash = target[20:52]
        self.update_node_hash(target, path, _hash, value)

    def update_node_hash(self, node, path, _hash, value):
        c = node
        for x in path[::-1]:
            self.parents[c] = x
            c = x
        self.hash_list[node] = (_hash, value)

    def update_hashes(self):
        nodes = {}  # nodes to write

        for i in xrange(KEYLENGTH, -1, -1):

            for node in self.hash_list.keys():
                if len(node) != i:
                    continue

                node_hash, node_value = self.hash_list.pop(node)

                parent = self.parents[node] if node != '' else ''

                if i != KEYLENGTH and node_hash is None:
                    n = self.get_node(node)
                    node_hash, node_value = n.get_hash(node, parent)
                assert node_hash is not None

                if node == '':
                    self.root_hash = node_hash
                    self.root_value = node_value
                    assert self.root_hash is not None
                    break

                # read parent
                d = nodes.get(parent)
                if d is None:
                    d = self.get_node(parent)
                    assert d is not None

                # write value into parent
                letter = node[len(parent)]
                d.set(letter, node_hash, node_value)
                nodes[parent] = d

                # iterate
                grandparent = self.parents[parent] if parent != '' else None
                parent_hash, parent_value = d.get_hash(parent, grandparent)
                if parent_hash is not None:
                    self.hash_list[parent] = (parent_hash, parent_value)

        for k, v in nodes.iteritems():
            self.put_node(k, v)
        # cleanup
        assert self.hash_list == {}
        self.parents = {}
        self.skip_batch = {}

    def get_path(self, target, new=False):

        x = self.db_utxo.get(target)
        if not new and x is None:
            raise BaseException('key not in tree', target.encode('hex'))

        if new and x is not None:
            # raise BaseException('key already in tree', target.encode('hex'))
            # occurs at block 91880 (duplicate txid)
            print_log('key already in tree', target.encode('hex'))
            return True

        remaining = target
        key = ''
        path = []
        while key != target:
            node = self.get_node(key)
            if node is None:
                break
                # raise # should never happen
            path.append(key)
            c = remaining[0]
            if not node.has(c):
                break
            skip = self.get_skip(key + c)
            key = key + c + skip
            if not target.startswith(key):
                break
            remaining = target[len(key):]
        return path

    def delete_key(self, leaf):
        path = self.get_path(leaf)
        # print "delete key", leaf.encode('hex'), map(lambda x: x.encode('hex'), path)

        s = self.db_utxo.get(leaf)
        self.db_utxo.delete(leaf)

        if leaf in self.hash_list:
            self.hash_list.pop(leaf)

        parent = path[-1]
        letter = leaf[len(parent)]
        parent_node = self.get_node(parent)
        parent_node.remove(letter)

        # remove key if it has a single child
        if parent_node.is_singleton(parent):
            # print "deleting parent", parent.encode('hex')
            self.db_utxo.delete(parent)
            if parent in self.hash_list:
                self.hash_list.pop(parent)

            l = parent_node.get_singleton()
            _hash, value = parent_node.get(l)
            skip = self.get_skip(parent + l)
            otherleaf = parent + l + skip
            # update skip value in grand-parent
            gp = path[-2]
            gp_items = self.get_node(gp)
            letter = otherleaf[len(gp)]
            new_skip = otherleaf[len(gp) + 1:]
            gp_items.set(letter, None, 0)
            self.set_skip(gp + letter, new_skip)
            # print "gp new_skip", gp.encode('hex'), new_skip.encode('hex')
            self.put_node(gp, gp_items)

            # note: k is not necessarily a leaf
            if len(otherleaf) == KEYLENGTH:
                ss = self.db_utxo.get(otherleaf)
                _hash, value = otherleaf[20:52], hex_to_int(ss[0:8])
            else:
                _hash, value = None, None
            self.update_node_hash(otherleaf, path[:-1], _hash, value)

        else:
            self.put_node(parent, parent_node)
            _hash, value = None, None
            self.update_node_hash(parent, path[:-1], _hash, value)
        return s

    def get_parent(self, x):
        p = self.get_path(x)
        return p[-1]

    def get_root_hash(self):
        return self.root_hash if self.root_hash else ''

    def batch_write(self):
        for db in [self.db_utxo, self.db_addr, self.db_hist, self.db_undo, self.db_claimid,
                   self.db_claim_values, self.db_claim_height, self.db_claim_names,
                   self.db_claim_order, self.db_certificate_claims, self.db_signed_claims,
                   self.db_claim_addrs]:
            db.write()

    def close(self):
        for db in [self.db_utxo, self.db_addr, self.db_hist, self.db_undo, self.db_claimid,
                   self.db_claim_values, self.db_claim_height, self.db_claim_names,
                   self.db_claim_order, self.db_certificate_claims, self.db_signed_claims,
                   self.db_claim_addrs]:
            db.close()

    def save_height(self, block_hash, block_height):
        self.db_undo.put('height', repr((block_hash, block_height, DB_VERSION)))

    def add_to_history(self, addr, tx_hash, tx_pos, value, tx_height):
        key = self.address_to_key(addr)
        txo = (tx_hash + int_to_hex(tx_pos, 4)).decode('hex')
        # write the new history
        self.add_key(key + txo, value, tx_height)
        # backlink
        self.db_addr.put(txo, addr)

    def revert_add_to_history(self, addr, tx_hash, tx_pos, value, tx_height):
        key = self.address_to_key(addr)
        txo = (tx_hash + int_to_hex(tx_pos, 4)).decode('hex')
        # delete
        self.delete_key(key + txo)
        # backlink
        self.db_addr.delete(txo)

    def get_utxo_value(self, addr, txi):
        key = self.address_to_key(addr)
        leaf = key + txi
        s = self.db_utxo.get(leaf)
        value = hex_to_int(s[0:8])
        return value

    def set_spent(self, addr, txi, txid, index, height, undo):
        key = self.address_to_key(addr)
        leaf = key + txi
        s = self.delete_key(leaf)
        value = hex_to_int(s[0:8])
        in_height = hex_to_int(s[8:12])
        undo[leaf] = value, in_height
        # delete backlink txi-> addr
        self.db_addr.delete(txi)
        # add to history
        s = self.db_hist.get(addr)
        if s is None: s = ''
        txo = (txid + int_to_hex(index, 4) + int_to_hex(height, 4)).decode('hex')
        s += txi + int_to_hex(in_height, 4).decode('hex') + txo
        s = s[-80 * self.pruning_limit:]
        self.db_hist.put(addr, s)

    def revert_set_spent(self, addr, txi, undo):
        key = self.address_to_key(addr)
        leaf = key + txi

        # restore backlink
        self.db_addr.put(txi, addr)

        v, height = undo.pop(leaf)
        self.add_key(leaf, v, height)

        # revert add to history
        s = self.db_hist.get(addr)
        # s might be empty if pruning limit was reached
        if not s:
            return

        assert s[-80:-44] == txi
        s = s[:-80]
        self.db_hist.put(addr, s)

    # get claim id in hex from txid in hex and nout int
    def _get_claim_id(self, txid, nout):
        claim_id = deserialize.claim_id_hash(deserialize.rev_hex(txid).decode('hex'),nout)
        claim_id = deserialize.claim_id_bytes_to_hex(claim_id)
        return claim_id

    # get claim id from db from claim outpoint
    def get_claim_id_from_outpoint(self, txid, nout):
        txid_nout = txid + int_to_hex(nout, 4)
        for claim_id, tx in self.db_claimid.db:
            if txid_nout == tx:
                return claim_id

    def get_claimid_for_nth_claim_to_name(self, name, n):
        claims = self.db_claim_order.get(name)
        for claim_id, i in json.loads(claims).iteritems():
            if i == n:
                return claim_id

    def get_n_for_name_and_claimid(self, name, claim_id):
        claims = self.db_claim_order.get(name)
        for id, n in json.loads(claims).iteritems():
            if id == claim_id:
                return n

    def get_txid_nout_from_claim_id(self, claim_id):
        txid_nout = self.db_claimid.get(claim_id)
        if txid_nout is None:
            return None
        txid = txid_nout[0:64]
        nout = hex_to_int(txid_nout[64:72].decode('hex'))
        return txid, nout

    def _iter_claims_signed_by(self, certificate_id):
        for claim_id, cert_id in self.db_signed_claims.db:
            if certificate_id == cert_id:
                yield claim_id

    def get_claims_signed_by(self, certificate_id):
        return list(self._iter_claims_signed_by(certificate_id))

    def update_channel_validations(self, claim, claim_id):
        claim_address = self.db_claim_addrs.get(claim_id)
        try:
            decoded_claim = smart_decode(claim.value)
            parsed_uri = parse_lbry_uri(claim.name)
        except DecodeError:
            print_log("decode error in update for lbry://{}#{}".format(claim.name, claim_id))
            self.remove_claim(claim_id, delete_claim_data=False)
            return
        except URIParseError:
            print_log("uri parse error for lbry://{}#{}".format(claim.name, claim_id))
            self.remove_claim(claim_id, delete_claim_data=False)
            return

        if parsed_uri.is_channel and decoded_claim.is_certificate:
            if self.db_certificate_claims.get(claim_id):
                print_log("reindexing lbry://{}#{}".format(claim.name, claim_id))
                self.db_certificate_claims.delete(claim_id)
            else:
                print_log("adding channel lbry://{}#{}".format(claim.name, claim_id))
            self.db_certificate_claims.put(claim_id, claim.value)

            for claim_id_to_check in self.get_claims_signed_by(claim_id):
                address_to_check = self.db_claim_addrs.get(claim_id)
                name = self.get_claim_name(claim_id_to_check)
                decoded_claim_to_check = smart_decode(self.db_claim_values.get(claim_id_to_check))
                try:
                    is_valid = decoded_claim_to_check.validate_signature(address_to_check,
                                                                         decoded_claim)
                    if is_valid:
                        self.db_signed_claims.delete(claim_id_to_check)
                        self.db_signed_claims.put(claim_id_to_check, claim_id)
                        print_log("validated lbry://{}#{}/{}".format(claim.name,
                                                                     decoded_claim.certificate_id,
                                                                     name))
                    else:
                        raise BadSignatureError()
                except BadSignatureError:
                    print_log("revoked lbry://{}#{}/{}".format(claim.name, claim_id, name))
                    self.db_signed_claims.delete(claim_id_to_check)
        elif decoded_claim.has_signature:
            raw_certificate = self.db_certificate_claims.get(decoded_claim.certificate_id)
            if not raw_certificate:
                print_log("certificate error, revoking lbry://{}#{}".format(claim.name, claim_id))
                self.db_signed_claims.delete(claim_id)
            elif decoded_claim.has_signature:
                certificate = smart_decode(raw_certificate)
                channel_name = self.get_claim_name(decoded_claim.certificate_id)
                try:
                    is_valid = decoded_claim.validate_signature(claim_address, certificate)
                except BadSignatureError:
                    is_valid = False
                if is_valid:
                    print_log("validated lbry://{}#{}/{}".format(channel_name,
                                                                 decoded_claim.certificate_id,
                                                                 claim.name))
                    self.db_signed_claims.put(claim_id, decoded_claim.certificate_id)
                else:
                    print_log("revoked lbry://{}#{}/{}".format(channel_name,
                                                               decoded_claim.certificate_id,
                                                               claim.name))
                    self.db_signed_claims.delete(claim_id)
        elif self.db_signed_claims.get(claim_id):
            print_log("update to lbry://{}#{} is missing a signature, invalidating".format(claim.name, claim_id))
            self.db_signed_claims.delete(claim_id)
        elif self.db_certificate_claims.get(claim_id):
            print_log("update to lbry://{}#{} no longer contains a certificate, removing the channel".format(claim.name, claim_id))
            for channel_claim_id in self.get_claims_signed_by(claim_id):
                name = self.get_claim_name(channel_claim_id)
                print_log("invalidated lbry://{}#{}/{}".format(claim.name, claim_id, name))
                self.db_signed_claims.delete(channel_claim_id)
            self.db_certificate_claims.delete(claim_id)

    def import_claim(self, claim, txid, nout, block_height, claim_address):
        txid_nout = txid+int_to_hex(nout, 4)
        is_update = type(claim) == deserialize.ClaimUpdate

        if type(claim) not in [deserialize.NameClaim, deserialize.ClaimUpdate]:
            raise Exception("No claim given to import")
        if is_update:
            claim_id = deserialize.claim_id_bytes_to_hex(claim.claim_id)
            print_log("importing update to %s#%s" % (claim.name, claim_id))
        else:
            claim_id = self._get_claim_id(txid, nout)
            print_log("importing claim %s#%s" % (claim.name, claim_id))

        claims_in_db = self.db_claim_order.get(claim.name)
        claims_for_name = {} if not claims_in_db else json.loads(claims_in_db)
        if not claims_for_name:
            claim_n = 1
        else:
            claim_n = max(i for i in claims_for_name.itervalues()) + 1

        claims_for_name[claim_id] = claim_n
        self.db_claim_order.delete(claim.name)
        self.db_claim_order.put(claim.name, json.dumps(claims_for_name))

        self.db_claimid.put(claim_id, txid_nout)
        self.db_claim_names.put(claim_id, claim.name)
        self.db_claim_values.put(claim_id, claim.value)
        self.db_claim_height.put(claim_id, str(block_height))
        self.db_claim_addrs.put(claim_id, claim_address)

        self.update_channel_validations(claim, claim_id)

    def remove_claim(self, claim_id, delete_claim_data=True):
        name = self.get_claim_name(claim_id)
        if delete_claim_data:
            print_log("remove %s#%s" % (name, claim_id))
            self.db_claimid.delete(claim_id)
            self.db_claim_values.delete(claim_id)
            self.db_claim_height.delete(claim_id)
            self.db_claim_addrs.delete(claim_id)
            self.db_claim_names.delete(claim_id)
            self.batch_write()
        else:
            print_log("found non channel claim %s#%s" % (name, claim_id))

        if self.db_certificate_claims.get(claim_id):
            claims_signed_by_this_cert = self.get_claims_signed_by(claim_id)
            for revoked_signed_claim in claims_signed_by_this_cert:
                print_log("revoke %s#%s/%s" % (name, claim_id, self.get_claim_name(revoked_signed_claim)))
                self.db_signed_claims.delete(revoked_signed_claim)
            self.db_certificate_claims.delete(claim_id)
        elif self.db_signed_claims.get(claim_id):
            self.db_signed_claims.delete(claim_id)

    def revert_claim(self, claim, txid, nout, undo_claim=None):
        if type(claim) == deserialize.NameClaim:
            claim_id = self._get_claim_id(txid, nout)
            self.db_claimid.delete(claim_id)
            self.db_claim_values.delete(claim_id)
            self.db_claim_height.delete(claim_id)
            print_log('Removing name claim {}'.format(claim_id))
        elif type(claim) == deserialize.ClaimUpdate:
            if not isinstance(undo_claim, dict):
                print_log("Not given a value to revert claim to")

            prev_txid_nout = undo_claim.pop('prev_txid_nout')
            prev_claim_height = undo_claim.pop('prev_claim_height')
            prev_claim_value = undo_claim.pop('prev_claim_value')

            # delete the update and put the original claim back in
            claim_id = deserialize.claim_id_bytes_to_hex(claim.claim_id)
            self.db_claimid.delete(claim_id)
            self.db_claim_values.delete(claim_id)
            self.db_claim_height.delete(claim_id)

            self.db_claimid.put(claim_id, prev_txid_nout)
            self.db_claim_height.put(claim_id, prev_claim_height)
            self.db_claim_values.put(claim_id, prev_claim_value)
            print_log('Reverting update for claim {} to {}'.format(claim_id, prev_txid_nout))

        assert undo_claim == {}

    def import_transaction(self, txid, tx, block_height, touched_addr):
        undo = {
            'prev_addr': []}  # contains the list of pruned items for each address in the tx; also, 'prev_addr' is a list of prev addresses
        prev_addr = []
        for i, x in enumerate(tx.get('inputs')):
            txi = (x.get('prevout_hash') + int_to_hex(x.get('prevout_n'), 4)).decode('hex')
            addr = self.get_address(txi)
            if addr is not None:
                self.set_spent(addr, txi, txid, i, block_height, undo)
                touched_addr.add(addr)
            prev_addr.append(addr)

        undo['prev_addr'] = prev_addr

        # here I add only the outputs to history; maybe I want to add inputs too (that's in the other loop)
        for x in tx.get('outputs'):
            addr = x.get('address')
            if addr is None: continue
            self.add_to_history(addr, txid, x.get('index'), x.get('value'), block_height)
            touched_addr.add(addr)
        return undo

    def revert_transaction(self, txid, tx, block_height, touched_addr, undo):
        # print_log("revert tx", txid)
        for x in reversed(tx.get('outputs')):
            addr = x.get('address')
            if addr is None: continue
            self.revert_add_to_history(addr, txid, x.get('index'), x.get('value'), block_height)
            touched_addr.add(addr)

        prev_addr = undo.pop('prev_addr')
        for i, x in reversed(list(enumerate(tx.get('inputs')))):
            addr = prev_addr[i]
            if addr is not None:
                txi = (x.get('prevout_hash') + int_to_hex(x.get('prevout_n'), 4)).decode('hex')
                self.revert_set_spent(addr, txi, undo)
                touched_addr.add(addr)

        assert undo == {}
