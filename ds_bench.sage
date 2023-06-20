#**
# * A Many-to-Many Decentralized Anonymous Data Sharing Scheme
# *
# * Copyright (c) 2023 curiecrypt
# **

from Crypto.Hash import SHA256
import calendar
import time
import sys
sys.path.append("src")
import functionality as dsf
import helpers as dsh
import classes as dsc
import protocol as dsp
import random



### Parameters for SECP curve ### 
p = 2^256 - 2^32 - 977 
FF = GF(p)
EC = EllipticCurve([FF(0),FF(0),FF(0),FF(0),FF(7)])
genEC = EC.gens()[0]
n = genEC.order()
pp = dsc.public_param(genEC, FF, EC, n)


### Protocol parameters ### 
nr_signers = 256
ring_size = Integer(sys.argv[1])
signers = []
parties = []
sig_file_list = []
transaction_list = []
T_list = [bytes("DS_TAG_1", 'utf-8'), bytes("DS_TAG_2", 'utf-8'), bytes("DS_TAG_3", 'utf-8'), bytes("DS_TAG_4", 'utf-8')] 


########## Start Blockchain ####################################################################
print("*********** START BLOCKCHAIN *************")
gen = "datasharing"
gen_hash = (SHA256.new(gen.encode())).hexdigest()
current_GMT = time.gmtime()
timestamp = calendar.timegm(current_GMT)
genesis = dsc.block(0, [], gen_hash, gen_hash, timestamp)       # Generate the genesis block
block_chain = [genesis]     # Add the genesis block to chain
print("* Genesis block generated.")
print("******************************************\n")
################################################################################################


########## Register signers ####################################################################
print("************* Registration ***************")
for i in range(nr_signers):
    dsh.register(pp, signers, parties, i)       # Register random signers
print("* " + str(nr_signers) + " signers are registered.")
print("******************************************\n")
################################################################################################

f = open("results/benches_single/run_protocol" + str(ring_size) + ".txt", "a")
########## Protocol ############################################################################
print("************** Protocol ******************")
for i in range(nr_signers):
    t = cputime(subprocesses=True)
    ##### SIGNER #####
    signer = signers[i]
    sig_file = dsp.generate_sig_file(signer, parties, T_list, pp, ring_size) # Generate a signature and its corresponding file   
    sig_file_list.append(sig_file)      # Send signature file to server
    ####################
    
    ###### SERVER ######
    dsp.check_sig_file(sig_file_list, transaction_list, sig_file, pp)
    ####################

    ####### CHAIN #######
    if len(transaction_list) == 5:
        block = dsp.generate_block(block_chain, transaction_list)       # Generate a new block
        block_chain.append(block)       # Append new block to chain
        transaction_list = []       # Empty the transaction list
    #####################    
    f.write(str(cputime(subprocesses=True) - t) + "\n")

print("* " + str(len(sig_file_list)) + " signatures are generated.")   
print("******************************************\n")
f.close()


################################################################################################


f = open("results/benches/verify" + str(ring_size) + ".txt", "a")
ver_cnt = 0
print("************* VERIFICATION ***************")
for i in range(nr_signers):
    t = cputime(subprocesses=True)
    signer = signers[i]
    ring, ind = dsh.collect_ring_members(parties, signer, ring_size) # Set a random ring including signer, get the index of the signer in the ring
    T = T_list[random.randint(0, 3)] # Random tag
    L = dsh.create_L(ring, T) # L = (tag || ring)

    related_sig_files = []
    for block in block_chain:
        for transaction in block.transaction_list:
            sig_file = dsh.get_sig_file(sig_file_list, transaction.fID)
            if sig_file.L == L and sig_file.signerID != signer.signerID:
                related_sig_files += [sig_file]

    if (len(related_sig_files)) > 0:
        sig_file = related_sig_files[random.randint(0, len(related_sig_files)-1)]
        ver = dsf.verify_signature(sig_file, pp, parties[sig_file.signerID].PK)
        if ver == 1:
            K = dsf.decapsulate(sig_file.C, signer.sk, ind, pp)
            M = dsh.decrpt(K, sig_file.E)
            ver_cnt += 1
    f.write(str(cputime(subprocesses=True) - t) + "\n")

print("* " + str(ver_cnt) + " signatures are validated.")   
print("\n******************************************\n")
f.close()
