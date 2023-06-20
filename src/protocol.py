#**
# * A Many-to-Many Decentralized Anonymous Data Sharing Scheme
# *
# * Copyright (c) 2023 curiecrypt
# **

import random
from random import randbytes
import time
from Crypto.Hash import SHA256
import functionality as dsf
import helpers as dsh
import classes as dsc

def generate_sig_file(signer, parties, tag_list, pp, ring_size):
    
    T = tag_list[random.randint(0, 3)] # Random tag
    fID = int(time.time_ns()/1000)
    M = randbytes(256)
    ring, ind = dsh.collect_ring_members(parties, signer, ring_size) # Set a random ring including signer, get the index of the signer in the ring
    K, C = dsf.encapsulate(pp, ring) # Encapsulation      
    E = dsh.encrpt(K, M) # E = Enc(K; M)
    
    L = dsh.create_L(ring, T) # L = (tag || ring)

    sigma = dsf.generate_signature(pp, ring, E, L, signer, ind) # sigma = A1, c_list, z_list

    sig_file = dsc.signature_file(fID, C, E, L, sigma, ring, signer.signerID) # sig_file = [fID, C, E, L, {sigma = A1, c_list, z_list}, ring_members]
    return sig_file


def check_sig_file(sig_file_list, transaction_list, sig_file, pp):
    if len(sig_file_list) == 1:     # If there is no previous signature, no traceability check
        transaction_list.append(dsc.transaction(sig_file.fID, 0))
    else:       # Check traceability for the new signature
        related_sigs = dsh.get_related_sigs(sig_file_list, sig_file)
        for j in range(len(related_sigs) - 1):
            comp_sig = related_sigs[j]
            T_out = dsf.check_traceability(sig_file, comp_sig, pp)
            if T_out == 1:
                # print("* Traceability check: Linked!")
                break
            elif T_out == -1: 
                # print("* Traceability check: ", sig_file.signerID)
                break
            else:
                if j == len(related_sigs) - 2:
                    transaction_list.append(dsc.transaction(sig_file.fID, T_out))       # if independent, add file to transaction list


def generate_block(block_chain, transaction_list):
    block_id = len(block_chain)
    prev_hash = (SHA256.new(str(block_chain[block_id - 1]).encode())).hexdigest()
    current_hash = (SHA256.new(str(transaction_list).encode())).hexdigest()
    timestamp = int(time.time_ns()/1000)
    block = dsc.block(block_id, transaction_list, prev_hash, current_hash, timestamp)
    return block
