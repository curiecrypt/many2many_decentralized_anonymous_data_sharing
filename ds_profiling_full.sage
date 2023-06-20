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
import cProfile, pstats, io
from pstats import SortKey


pr = cProfile.Profile()

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
gen = "datasharing"
gen_hash = (SHA256.new(gen.encode())).hexdigest()
current_GMT = time.gmtime()
timestamp = calendar.timegm(current_GMT)
genesis = dsc.block(0, [], gen_hash, gen_hash, timestamp)       # Generate the genesis block
block_chain = [genesis]     # Add the genesis block to chain
################################################################################################


########## Register signers ####################################################################
for i in range(nr_signers):
    dsh.register(pp, signers, parties, i)       # Register random signers
################################################################################################

## Run protocol to collect signature files ##
for i in range(nr_signers):
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



################################################################################################
########## Start collecting stats ##############################################################
################################################################################################

#------------------- Geneerate signature -------------------#
f = open("results/stats_full/signing" + str(ring_size) + ".txt", "w")
signer = signers[random.randint(0, nr_signers - 1)]

##----- STATS ----##
pr.enable()
sig_file = dsp.generate_sig_file(signer, parties, T_list, pp, ring_size) # Generate a signature and its corresponding file   
sig_file_list.append(sig_file)      # Send signature file to server
dsp.check_sig_file(sig_file_list, transaction_list, sig_file, pp)
if len(transaction_list) == 5:
    block = dsp.generate_block(block_chain, transaction_list)       # Generate a new block
    block_chain.append(block)       # Append new block to chain
    transaction_list = []       # Empty the transaction list
pr.disable()
##---------------##

s = io.StringIO()
sortby = SortKey.CUMULATIVE
ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
ps.print_stats()
f.write(s.getvalue())
f.close()
#---------------------------------------------------------#



#--------------------- Verify signature --------------------#
f = open("results/stats_full/verification" + str(ring_size) + ".txt", "w")
signer = signers[random.randint(0, nr_signers - 1)]

##----- STATS ----##
pr.enable()
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
    sig_file = related_sig_files[0]
    ver = dsf.verify_signature(sig_file, pp, parties[sig_file.signerID].PK)
    if ver == 1:
        K = dsf.decapsulate(sig_file.C, signer.sk, ind, pp)
        M = dsh.decrpt(K, sig_file.E)
pr.disable()
##---------------##

s = io.StringIO()
sortby = SortKey.CUMULATIVE
ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
ps.print_stats()
f.write(s.getvalue())
f.close()
#-----------------------------------------------------------#

################################################################################################

