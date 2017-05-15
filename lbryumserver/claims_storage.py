"""
this file contains ClaimsStorage class which contains
functions to manipulate the claim information
"""

import pickle

from lbryschema.decode import smart_decode
from lbryschema.error import DecodeError, URIParseError, CertificateError
from lbryschema.uri import parse_lbry_uri

from lbryumserver import deserialize
from lbryumserver.storage import Storage
from lbryumserver.processor import logger
from lbryumserver.utils import int_to_hex,hex_to_int

class ClaimsStorage(Storage):
    def __init__(self, config, shared, test_reorgs):
        Storage.__init__(self, config, shared, test_reorgs)

    def get_claimid_for_nth_claim_to_name(self, name, n):
        claims = self.db_claim_order.get(name)
        if claims is None:
            return None
        for claim_id, i in pickle.loads(claims).iteritems():
            if i == n:
                return claim_id

    def get_n_for_name_and_claimid(self, name, claim_id):
        claims = self.db_claim_order.get(name)
        if claims is None:
            return None
        for id, n in pickle.loads(claims).iteritems():
            if id == claim_id:
                return n

    def get_claim_id_from_outpoint(self, txid, nout):
        #TODO: may want to look into keeping a db of txid nout to outpoint
        # if too slow here
        for claim_id, txid_nout_amount in self.db_claim_outpoint.db.iterator():
            c_txid = txid_nout_amount[0:64]
            c_nout = hex_to_int(txid_nout_amount[64:72].decode('hex'))
            logger.warn('get_claim_id_from_outpoint:{}:{}, {}:{}'.format(txid,nout,c_txid,c_nout))
            if txid == c_txid and nout == c_nout:
                return claim_id

    def get_outpoint_from_claim_id(self, claim_id):
        txid_nout = self.db_claim_outpoint.get(claim_id)
        if txid_nout is None:
            return None
        txid = txid_nout[0:64]
        nout = hex_to_int(txid_nout[64:72].decode('hex'))
        amount = hex_to_int(txid_nout[72:88].decode('hex'))
        return txid, nout, amount

    def write_outpoint_from_claim_id(self, claim_id, txid, nout, amount):
        txid_nout_amount = txid+int_to_hex(nout, 4)+int_to_hex(amount,8)
        self.db_claim_outpoint.put(claim_id, txid_nout_amount)

    def get_claims_for_name(self, name):
        claims = self.db_claim_order.get(name)
        if claims is None:
            return {}
        return pickle.loads(claims)

    def write_claims_for_name(self, name, claims):
        if len(claims) == 0:
            self.db_claim_order.delete(name)
        else:
            claims = pickle.dumps(claims)
            self.db_claim_order.put(name, claims)

    def get_claims_signed_by(self, certificate_id):
        claims = self.db_cert_to_claims.get(certificate_id)
        if claims is None:
            return []
        return pickle.loads(claims)

    def write_claims_signed_by(self, certificate_id, claims):
        if len(claims) == 0:
            self.db_cert_to_claims.delete(certificate_id)
        else:
            self.db_cert_to_claims.put(certificate_id,pickle.dumps(claims))

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


    def get_undo_claim_info(self, height):
        s = self.db_undo_claim.get("undo_info_%d"%(height%100))
        if s is None:
            print_log('no undo info for {}'.format(height))
            return None
        return pickle.loads(s)

    def write_undo_claim_info(self, height, lbrycrdd_height, undo_info):
        if height > lbrycrdd_height - 100 or self.test_reorgs:
            self.db_undo_claim.put("undo_info_%d" % (height % 100), pickle.dumps(undo_info))


    def _get_claim_id(self, txid, nout):
        """ get claim id in hex from txid in hex and nout int """
        claim_id = deserialize.claim_id_hash(deserialize.rev_hex(txid).decode('hex'),nout)
        claim_id = deserialize.claim_id_bytes_to_hex(claim_id)
        return claim_id


    def _get_undo_info(self, claim_type, claim_id, claim_name):
        undo_info={"claim_id":claim_id,"claim_type":claim_type,"claim_name":claim_name}
        if claim_type != 'claim':
            undo_info['claim_outpoint'] = self.db_claim_outpoint.get(claim_id)
            undo_info['claim_names'] = claim_name
            undo_info['claim_values']= self.db_claim_values.get(claim_id)
            undo_info['claim_height']= self.db_claim_height.get(claim_id)
            undo_info['claim_addrs']= self.db_claim_addrs.get(claim_id)

        undo_info['claim_order']= self.db_claim_order.get(claim_name)
        return undo_info

    def _is_valid_claim(self, claim, tx):
        """
        TODO: must be the first update (for the claim) in tx if there is more than one
        """
        if type(claim) == deserialize.ClaimUpdate:
            claim_id = deserialize.claim_id_bytes_to_hex(claim.claim_id)
            claim_name = self.get_claim_name(claim_id)
            # claim is invalid if its name does not match
            # what its updating
            if claim_name != claim.name:
                return False
            # claim is invalid if it does not spend the claim it
            # is updating
            for i in tx.get('inputs'):
                txid = i['prevout_hash']
                nout = i['prevout_n']
                if claim_id == self.get_claim_id_from_outpoint(txid, nout):
                    return True
            logger.warn("found invalid update {} for {}".format(claim_id, claim.name))
            return False
        else:
            return True

    def revert_claim_transaction(self, undo_infos):
        """ revert claim transaction using undo information"""
        for undo_info in undo_infos:
            claim_id = undo_info['claim_id']
            claim_name = undo_info['claim_name']
            claim_type = undo_info['claim_type']
            if claim_type == 'update':
                self.db_claim_outpoint.put(claim_id, undo_info['claim_outpoint'])
                self.db_claim_names.put(claim_id, undo_info['claim_names'])
                self.db_claim_values.put(claim_id, undo_info['claim_values'])
                self.db_claim_height.put(claim_id, undo_info['claim_height'])
                self.db_claim_addrs.put(claim_id, undo_info['claim_addrs'])
                self.db_claim_order.put(claim_name, undo_info['claim_order'])

                if 'cert_to_claims' in undo_info:
                    cert_id = undo_info['cert_to_claims'][0]
                    claims = undo_info['cert_to_claims'][1]
                    self.write_claims_signed_by(cert_id, claims)
                    prev_cert_id = undo_info['prev_cert_to_claims'][0]
                    prev_claims = undo_info['prev_cert_to_claims'][1]
                    self.write_claims_signed_by(prev_cert_id,prev_claims)
                    self.db_claim_to_cert.put(claim_id,undo_info['claim_to_cert'])

            elif claim_type == 'claim':
                self.db_claim_outpoint.delete(claim_id)
                self.db_claim_names.delete(claim_id)
                self.db_claim_values.delete(claim_id)
                self.db_claim_height.delete(claim_id)
                self.db_claim_addrs.delete(claim_id)
                if undo_info['claim_order'] is not None:
                    self.db_claim_order.put(claim_name, undo_info['claim_order'])
                else:
                    self.db_claim_order.delete(claim_name)

                if 'cert_to_claims' in undo_info:
                    cert_id = undo_info['cert_to_claims'][0]
                    claims = undo_info['cert_to_claims'][1]
                    self.write_claims_signed_by(cert_id, claims)
                    self.db_claim_to_cert.delete(claim_id)

            elif claim_type == 'abandon':
                self.db_claim_outpoint.put(claim_id, undo_info['claim_outpoint'])
                self.db_claim_names.put(claim_id, undo_info['claim_names'])
                self.db_claim_values.put(claim_id, undo_info['claim_values'])
                self.db_claim_height.put(claim_id, undo_info['claim_height'])
                self.db_claim_addrs.put(claim_id, undo_info['claim_addrs'])
                self.db_claim_order.put(claim_name, undo_info['claim_order'])

                if 'cert_to_claims' in undo_info:
                    cert_id = undo_info['cert_to_claims'][0]
                    claims = undo_info['cert_to_claims'][1]
                    self.write_claims_signed_by(cert_id, claims)
                    self.db_claim_to_cert.put(claim_id, undo_info['claim_to_cert'])

            else:
                raise Exception('unhandled claim_type:{}'.format(claim_type))

    def _analyze_tx(self, txid, tx):
        """ analyze transaction to get list of abandons and claims """
        #dict of abandons where key = claim_id , value = {'txid', 'nout',}
        abandons = dict()
        #list of claims : [{'claim': , 'nout':, 'claim_id', 'claim_address': 'amount':}, ]
        list_claims = []
        for x in tx.get('inputs'):
            claim_id = self.get_claim_id_from_outpoint(x['prevout_hash'], x['prevout_n'])
            if claim_id:
                abandons[claim_id] = {'txid':x['prevout_hash'],'nout':x['prevout_n']}

        for x in tx.get('outputs'):
            script = x.get('raw_output_script').decode('hex')
            nout = x.get('index')
            amount = x.get('value')
            decoded_script = [s for s in deserialize.script_GetOp(script)]
            out = deserialize.decode_claim_script(decoded_script)
            if out is False:
                continue
            claim, claim_script = out
            claim_address = deserialize.get_address_from_output_script(script)
            if not self._is_valid_claim(claim, tx):
                continue
            if type(claim) in [ deserialize.NameClaim, deserialize.ClaimSupport]:
                claim_id = self._get_claim_id(txid,nout)
            else:#ClaimUpdate
                claim_id = deserialize.claim_id_bytes_to_hex(claim.claim_id)
                del abandons[claim_id]

            claim_info= {'claim':claim,'nout':nout,'claim_id':claim_id,'claim_address':claim_address,'amount':amount}
            list_claims.append(claim_info)

        return {'abandons':abandons,'claims':list_claims,}


    def import_claim_transaction(self, txid, tx, block_height):
        out = self._analyze_tx(txid, tx)
        undo_infos =[]
        for claim_id,claim_info in out['abandons'].iteritems():
            undo_infos.append(
                self.import_abandon(claim_info['txid'], claim_info['nout']))

        for c in out['claims']:
            if type(c['claim']) == deserialize.NameClaim:
                undo_infos.append(
                    self.import_claim(c['claim'], c['claim_id'], c['claim_address'],
                                  txid, c['nout'], c['amount'], block_height))
            elif type(c['claim']) == deserialize.ClaimUpdate:
                undo_infos.append(
                    self.import_update(c['claim'], c['claim_id'], c['claim_address'],
                                  txid, c['nout'], c['amount'], block_height))
            else: #support
                pass

        undo_infos.reverse()
        return undo_infos

    def import_claim(self, claim, claim_id, claim_address, txid, nout, amount, block_height):
        logger.info("importing claim {}, claim id:{}, txid:{}, nout:{} ".format(claim, claim_id, txid, nout))

        undo_info = self._get_undo_info('claim', claim_id, claim.name)

        claims_for_name = self.get_claims_for_name(claim.name)
        if not claims_for_name:
            claim_n = 1
        else:
            claim_n = max(i for i in claims_for_name.itervalues()) + 1

        claims_for_name[claim_id] = claim_n
        self.write_claims_for_name(claim.name, claims_for_name)

        self.write_outpoint_from_claim_id(claim_id, txid, nout, amount)
        self.db_claim_names.put(claim_id, claim.name)
        self.db_claim_values.put(claim_id, claim.value)
        self.db_claim_height.put(claim_id, str(block_height))
        self.db_claim_addrs.put(claim_id, claim_address)

        undo_info = self.import_signed_claim(claim, claim_id, undo_info)
        return undo_info


    def import_update(self, claim, claim_id, claim_address, txid, nout, amount, block_height):
        logger.info("importing update {}, claim id:{}, txid:{}, nout:{} ".format(claim, claim_id, txid, nout))

        undo_info = self._get_undo_info('update', claim_id, claim.name)

        self.write_outpoint_from_claim_id(claim_id, txid, nout, amount)
        self.db_claim_values.put(claim_id, claim.value)
        self.db_claim_height.put(claim_id, str(block_height))
        self.db_claim_addrs.put(claim_id, claim_address)

        undo_info = self.import_signed_claim(claim, claim_id, undo_info)
        return undo_info



    def import_abandon(self, txid, nout):
        """ handle abandoned claims """
        claim_id = self.get_claim_id_from_outpoint(txid, nout)
        claim_name = self.get_claim_name(claim_id)
        if claim_id is None:
            return

        undo_info = self._get_undo_info('abandon', claim_id, claim_name)
        self.db_claim_outpoint.delete(claim_id)
        self.db_claim_values.delete(claim_id)
        self.db_claim_height.delete(claim_id)
        self.db_claim_addrs.delete(claim_id)
        self.db_claim_names.delete(claim_id)

        claims_in_db = self.db_claim_order.get(claim_name)
        claims_for_name = {} if not claims_in_db else pickle.loads(claims_in_db)
        claim_n = claims_for_name[claim_id]
        del claims_for_name[claim_id]

        for cid,cn in claims_for_name.iteritems():
            if cn > claim_n:
                claims_for_name[cid] = cn-1

        self.db_claim_order.delete(claim_name)
        self.db_claim_order.put(claim_name, pickle.dumps(claims_for_name))

        undo_info = self.import_signed_claim_abandon(claim_id, undo_info)
        return undo_info


    def _get_signed_claim_undo_info(self, claim_type, undo_info, cert_id, prev_cert_id=None):
        """ add to undo_info signed claim related undo information """

        if claim_type == 'claim':
            claims = self.get_claims_signed_by(cert_id)
            undo_info['cert_to_claims'] = (cert_id,claims)
        elif claim_type == 'update':
            if prev_cert_id != cert_id:
                prev_claims = self.get_claims_signed_by(prev_cert_id)
                claims = self.get_claims_signed_by(cert_id)
                undo_info['prev_cert_to_claims'] = (prev_cert_id,prev_claims)
                undo_info['cert_to_claims'] = (cert_id,claims)
                undo_info['claim_to_cert'] = prev_cert_id

        elif claim_type == 'abandon':
            claims = self.get_claims_signed_by(cert_id)
            undo_info['cert_to_claims'] = (cert_id,claims)
            undo_info['claim_to_cert'] = cert_id
        else:
            raise Exception("unhandled type:{}".format(claim_type))

        return undo_info

    def import_signed_claim(self, claim, claim_id, undo_info):
        """ handle the import of claims/updates signed """
        try:
            decoded_claim = smart_decode(claim.value)
            parsed_uri = parse_lbry_uri(claim.name)
        except DecodeError:
            logger.warn("decode error for lbry://{}#{}".format(claim.name, claim_id))
            return undo_info
        except URIParseError:
            logger.warn("uri parse error for lbry://{}#{}".format(claim.name, claim_id))
            return undo_info
        if not decoded_claim.has_signature:
            return undo_info

        cert_id = decoded_claim.certificate_id
        prev_cert_id = None
        claim_type = 'claim'
        if type(claim) == deserialize.ClaimUpdate:
            prev_cert_id  = self.db_claim_to_cert(claim_id)
            claim_type = 'update'
        undo_info = self._get_signed_claim_undo_info(claim_type, undo_info, cert_id, prev_cert_id)

        if claim_type == 'update':
            if prev_cert_id != cert_id:
                prev_claims = self.get_claims_signed_by(prev_cert_id)
                prev_claims.remove(claim_id)
                self.write_claims_signed_by(prev_cert_id, prev_claims)

                claims = self.get_claims_signed_by(cert_id)
                claims.append(claim_id)
                self.write_claims_signed_by(cert_id,claims)

                self.db_claim_to_cert.put(clam_id, cert_id)
        elif claim_type == 'claim':
            self.db_claim_to_cert.put(claim_id, cert_id)
            claims = self.get_claims_signed_by(cert_id)
            claims.append(claim_id)
            self.write_claims_signed_by(cert_id, claims)
        else:
            raise Exception('unhandled type:{}'.format(claim_type))

        return undo_info

    def import_signed_claim_abandon(self, claim_id, undo_info):
        """ handle abandons of claims signed  """
        cert_id = self.db_claim_to_cert.get(claim_id)
        if cert_id is not None:
            undo_info = self._get_signed_claim_undo_info('abandon', undo_info, cert_id)
            claims = self.get_claims_signed_by(cert_id)
            claims.remove(claim_id)
            self.write_claims_signed_by(cert_id, claims)
            self.db_claim_to_cert.delete(claim_id)

        return undo_info
