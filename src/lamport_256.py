# Lamport signature implementation

import secrets
from hashlib import sha256


def generate_keys(filename='keys.txt'):
    """ 
    Generates and returns a public and private key pair

    """

    zeropriv = [secrets.token_hex(32) for i in range(256)]
    onepriv  = [secrets.token_hex(32) for i in range(256)]
    zeropub  = [sha256(block.encode()).hexdigest() for block in zeropriv]
    onepub   = [sha256(block.encode()).hexdigest() for block in onepriv]

    return { 'priv': [zeropriv, onepriv], 'pub': [zeropub, onepub] }



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

def exportPub(pubkey, filename='pub.key'):
    with open(filename, 'w') as f:
        f.writelines(pubkey[0])
        f.writelines(pubkey[1])


def exportPriv(privkey, filename='priv.key'):
    with open(filename, 'w') as f:
        f.writelines(privkey[0])
        f.writelines(privkey[1])

def parseKey(filename):
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
    keypair2 = generate_keys()

    message = 'JP'

    sig = sign_message(priv=keypair2['priv'], msg=message)

    print(verify_signature(msg='JP', sig=sig, pubkey=keypair2['pub']))
