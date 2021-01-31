# Lamport signature implementation

import secrets
from hashlib import sha256


class _KeyPair:

    """ _KeyPair is only intended to be used as an internal type """

    def __init__(self, zeropriv, onepriv, zeropub, onepub):
        self.zeropriv = zeropriv
        self.onepriv  = onepriv 
        self.zeropub  = zeropub 
        self.onepub   = onepub  

    @property
    def priv(self):
        return [self.zeropriv, self.onepriv]

    @property
    def pub(self):
        return [self.zeropub, self.onepub]


def generate_keys(filename='keys.txt'):
    """ 
    Generates and returns a public and private key pair

    """
    zeropriv = [secrets.token_hex(32) for i in range(256)]                      
    onepriv  = [secrets.token_hex(32) for i in range(256)]
    zeropub  = [sha256(block.encode()).hexdigest() for block in zeropriv]
    onepub   = [sha256(block.encode()).hexdigest() for block in onepriv]

    return _KeyPair(zeropriv, onepriv, zeropub, onepub)


def  sign_message(priv, msg):
    """
    signs a message using the given decoded private key

    accepts: msg: string

    returns signature: [256] 
    """

    bin_msg = message_to_hashed_binary(msg) 
    signed_message = []
    for i, bit in enumerate(bin_msg):
        block = priv[bit][i]
        signed_message.append(block)
         
    return signed_message


def verify_signature(msg, sig, pubkey):
    bin_msg = message_to_hashed_binary(msg)

    for i, block in enumerate(sig):
        hashed_block = sha256(block.encode()).hexdigest()
        if hashed_block != pubkey[bin_msg[i]][i]:
            return False

    return True
    


""""""""""""""""""""""""""
"""  Utility functions """
""""""""""""""""""""""""""

def export_key(key, filename):
    with open(filename, 'w') as f:
        f.writelines(key[0])
        f.writelines(key[1])


def export_key_pair(keypair, pub_file='pub.key', priv_file='priv.key'):
    export_key(keypair.pub, pub_file)
    export_key(keypair.priv, priv_file)


def parse_key(filename):
    key = [[],[]]
    start = 0
    end = 64  

    with open(filename, 'r') as f:
        key_str = f.read()

    if len(key_str) != 2 * 64 * 256: # 2 rows, 265 blocks, 64 char long blocks. 
        raise Exception('Invalid private key length')
    
    for i in range(128):
        key[0].append(key_str[start:end])
        start = end
        end += 64
        
    for i in range(128):
        key[1].append(key_str[start:end])
        start = end
        end += 64

    return key


def parse_key_pair(pub_file, priv_file):
    priv = parseKey(priv_file)
    pub = parseKey(pub_file)

    return  _KeyPair(priv[0], priv[1], pub[0], pub[1])


def hex_to_bin_list(hex_string):
    results = []
    b = bytes.fromhex(hex_string)
    for byte in b:
        i = 128
        while(i > 0):
            if byte & i != 0:
                results.append(1)
            else:
                results.append(0)
            i = int(i/2)
    return results


def message_to_hashed_binary(msg):
    hashed_msg = sha256(msg.encode()).hexdigest()
    return hex_to_bin_list(hashed_msg)



""""""""""""""""""""""""""
"""  CLI functionality """
""""""""""""""""""""""""""

if __name__ == "__main__":

    


    keypair = generate_keys()
    priv = keypair.priv


    print(priv)

    signature = sign

    #keypair = generate_keys()
    #keypair2 = generate_keys()

    #message = 'JP'

    #sig = sign_message(priv=keypair2['priv'], msg=message)

    #print(verify_signature(msg='JP', sig=sig, pubkey=keypair2['pub']))
