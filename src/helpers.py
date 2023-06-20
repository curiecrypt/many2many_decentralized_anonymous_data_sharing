#**
# * A Many-to-Many Decentralized Anonymous Data Sharing Scheme
# *
# * Copyright (c) 2023 curiecrypt
# **

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Hash import TupleHash128
from Crypto.Util.Padding import pad, unpad
from sage.misc.prandom import randrange
from Crypto.Random import get_random_bytes

import classes as dsc

iv = get_random_bytes(16)

# -------------------------------------------------- #
# ---------------- Helper Functions ---------------- #
# -------------------------------------------------- #
def generate_key(pp):
    sk = randrange(pp.n) #Random number
    PK = sk * pp.genEC
    return [sk, PK]

def register(pp, signers, parties, signerID):
    sk, PK = generate_key(pp)
    signer = dsc.signer(sk, PK, signerID) 
    signers.append(signer)
    public_signer = dsc.participant(signer.PK, signerID)
    parties.append(public_signer)

def encrpt(K, M):
    cipher = AES.new(K, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(M, AES.block_size))
    return ct_bytes

def decrpt(K, E):
    cipher = AES.new(K, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(E), AES.block_size)
    return plaintext

def create_L(parties, T):
    L = (SHA256.new(str(T).encode())).hexdigest()
    for party in parties:
        L += (SHA256.new(str(party).encode())).hexdigest()
    return L

def derive_aes_key(text, max_bytes):
    hd = TupleHash128.new(digest_bytes = max_bytes)
    hd.update(text.encode('utf8'))
    key = hd.hexdigest()
    return key.encode('utf8')

def collect_ring_members(parties, signer, ring_size):
    s_index = 0
    
    ## Fixed ring ##
    sID = signer.signerID 
    ringID = int(sID / ring_size)
    start = ringID * ring_size
    ring = []
    for i in range(start, start + ring_size):
        ring += [parties[i]]

    ring.sort(reverse=False, key=sort_key) 
    cnt = 0
    for member in ring:
        if member.signerID == signer.signerID:
            s_index = cnt
        cnt+=1
    return [ring, s_index] 

def get_hash_on_curve(pp, hash_input):
    hash = SHA256.new(str(hash_input[0]).encode())                                              
    for i in range(len(hash_input)-1):
        hash.update(str(hash_input[i+1]).encode())                                                    
    h = (int(hash.hexdigest(), 16)) % pp.n                              
    H = h * pp.genEC                                                      
    return H

def get_hash_on_Zn(n, hash_input):
    hash = SHA256.new(str(hash_input[0]).encode())                                            
    for i in range(len(hash_input)-1):
        hash.update(str(hash_input[i+1]).encode())                                                 
    h = (int(hash.hexdigest(), 16)) % n
    return h

def sort_key(party):
    return party.signerID

def print_sig_file(signerID, sig_file):
    print("* Signature generated for signer: ", signerID)
    print("* Signature file ID: ", sig_file.fID)
    members = "* Ring members: "
    for i in range(len(sig_file.ring)):
        members = members + str(sig_file.ring[i].signerID) + " "
    print(members)

def get_related_sigs(sig_files, sig_file):
    related_sigs = []
    for sf in sig_files:
        if sf.L == sig_file.L:
            related_sigs += [sf]
    return related_sigs
    
def get_sig_file(sig_file_list, fID):
    for sf in sig_file_list:
        if sf.fID == fID:
            return sf
    return -1
