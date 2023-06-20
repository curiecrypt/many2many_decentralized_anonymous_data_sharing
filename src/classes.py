#**
# * A Many-to-Many Decentralized Anonymous Data Sharing Scheme
# *
# * Copyright (c) 2023 curiecrypt
# **

import time

# Public parameters: Finite field, Elliptic curve, generator of the curve
class public_param:
    def __init__(self, genEC, FF, EC, n):
        self.genEC = genEC
        self.FF = FF
        self.EC = EC
        self.n = n

# Signer: Secret key, public key, signerID
class signer:
    def __init__(self, sk, PK, signerID):
        self.sk = sk
        self.PK = PK
        self.signerID = signerID

# Public signer: Public key, signerID
class participant:
    def __init__(self, PK, signerID):
        self.PK = PK
        self.signerID = signerID

# Signature: Referring \sigma on paper.   
class signature:
    def __init__(self, A1, c_list, z_list):
        self.A1 = A1
        self.c_list = c_list
        self.z_list = z_list

# Signature sile: File ID, C, E, L, \sigma, the ring related to the signature
class signature_file:
    def __init__(self, fID, C, E, L, sig, ring, signerID):
        self.fID = fID
        self.C = C
        self.E = E
        self.L = L
        self.signature = sig
        self.ring = ring
        self.signerID = signerID

# Transaction: Transaction ID, signature file, result of traceability check
class transaction:
    def __init__(self, fID, T_out):
        self.tID = int(time.time_ns()/1000)
        self.fID = fID
        self.T_out = T_out

# Block: Block ID, transactions of the block, previous hash, block hash, timestamp
class block: 
    def __init__(self, blockID, transaction_list, prev_hash, block_hash, time):
        self.blockID = blockID
        self.prev_hash = prev_hash
        self.block_hash = block_hash 
        self.time = time
        self.transaction_list = transaction_list
