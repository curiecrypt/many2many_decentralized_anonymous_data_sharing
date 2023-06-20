#**
# * A Many-to-Many Decentralized Anonymous Data Sharing Scheme
# *
# * Copyright (c) 2023 curiecrypt
# **

import helpers as dsh
import classes as dsc
from sage.misc.prandom import randrange


# -------------------------------------------------- #
# --------------- Protocol Functions --------------- #
# -------------------------------------------------- #
def encapsulate(pp, parties):
    
    K = pp.EC.random_element()              # Random point on elliptic curve --//   k <- G                                                 
    r = dsh.get_hash_on_Zn(pp.n, [K])       # SHA256 of `K`, result is on `mod order(genEC)` --//   r = H(k)            
    C0 = r * pp.genEC                       # `C0 = r * genEC` --// c0 = g^r                                 
    C_list = [C0]                           # Add `C0` to `C_list`    

    for P in parties:
        C = K + r * P.PK                    # Ci = K + r * PKi --//   c_i = k * pk_i ^ r                                           
        C_list += [C]                       # Add `Ci` to `C_list` 
    
    AESK = dsh.derive_aes_key(str(K), 16)   # Derive AES key depending on point `K` --//    K <- KDF(k)                                        
    
    return [AESK, C_list]

def generate_signature(pp, ring, E, L, signer, signer_index):

    ind = signer_index + 1                      # Index starts from `0`. Increase all indices by `1` to get the inverse of `0`.
    inv = pow(ind, pp.n - 2, pp.n)              # Modular inverse of the index

    H = dsh.get_hash_on_curve(pp, [L])          # SHA256 of `L` outputs the corresponding point on curve --//    h = H(L)
    SIGMA = signer.sk * H                       # `SIGMA = sk_signer * H` --//    sigma_i = h ^ sk_i
    A0 = dsh.get_hash_on_curve(pp, [L, E])      # SHA256 of `L, E` outputs the corresponding point on curve --//    A0 = H(L, E)
    A1 = inv * (SIGMA - A0)                     # `A1 = inv * (SIGMA - A0)` --//    A1 = (sigma_i / A0) ^ (1 / i)

    SIGMA_list = []
    for j in range(len(ring)):
        if j != signer_index:                                                    
            S = A0 + (j + 1) * A1               # `S = A0 + (j + 1) * A1` --//    sigma_j = A0 * A1 ^ j
            SIGMA_list += [S]    
        else:
            SIGMA_list += [SIGMA]

    w = randrange(pp.n)                         # Random scalar in mod Order(genEC) --//    w_i = <- Z_q 
    A_signer = w * pp.genEC                     # --// a_i = g ^ w_i
    B_signer = w * H                            # --// b_i = h ^ w_i

    z_list = []
    c_list = []
    A_list = []
    B_list = []
    for j in range(len(ring)):
        if j != signer_index:   
            z = randrange(pp.n)                 # Random scalar in mod Order(genEC) --//    z_j = <- Z_q
            c = randrange(pp.n)                 # Random scalar in mod Order(genEC) --//    c_j = <- Z_q
            A = z * pp.genEC + c * signer.PK    # --// a_j = g ^ z_j * pk_i ^ c_j
            B = z * H + c * SIGMA_list[j]       # --// b_j = h ^ z_j * sigma_j ^ c_j                
            z_list += [z] 
            c_list += [c] 
            A_list += [A]
            B_list += [B]
        else:
            A_list += [A_signer]                                                        
            B_list += [B_signer]                     
            z_list += [0]                                                              
            c_list += [0]        

    hash_input = [L, A0, A1]
    hash_input += A_list
    hash_input += B_list
    c = dsh.get_hash_on_Zn(pp.n, hash_input)    # SHA256 of (L, A_list, B_list) --//   c = H''(L, A0, A1, AN, BN)
    # --------------------------------- #

    c_sum = 0
    for cj in c_list:
       c_sum = (c_sum + cj) % pp.n
    
    c_signer = (c - c_sum) % pp.n
    z_signer = (w - c_signer * signer.sk) % pp.n

    z_list[signer_index] = z_signer                                                            
    c_list[signer_index] = c_signer     

    signature = dsc.signature(A1, c_list, z_list)  
                          
    return signature

def verify_signature(sf, pp, PK):
  
    ######## check g,A1 \in G, ci,zi \in Zq, pki \in G ########
    if not pp.genEC in pp.EC or not sf.signature.A1 in pp.EC:
        return -1 

    for i in range(len(sf.ring)):
        if not sf.signature.z_list[i] in pp.FF or not sf.signature.c_list[i] in pp.FF or not sf.ring[i].PK in pp.EC:
            return -2
    # ------------------------------------------------------- #

    H = dsh.get_hash_on_curve(pp, [sf.L])           # SHA256 of `L` outputs the corresponding point on curve --//    h = H(L)
    A0 = dsh.get_hash_on_curve(pp, [sf.L, sf.E])    # SHA256 of `L, E` outputs the corresponding point on curve --//    A0 = H(L, E)
    A1 = sf.signature.A1
                                
    A_list = []
    B_list = []
    for j in range(len(sf.ring)):
        SIGMA = A0 + (j + 1) * A1                   # `S = A0 + (j + 1) * A1` --//    sigma_j = A0 * A1 ^ j
        z = sf.signature.z_list[j]
        c = sf.signature.c_list[j]
        A = z * pp.genEC + c * PK                   # --// a_j = g ^ z_j * pk_i ^ c_j 
        B = z * H + c * SIGMA                       # --// b_j = h ^ z_j * sigma_j ^ c_j
        A_list += [A]      
        B_list += [B]  

    hash_input = [sf.L, A0, A1]
    hash_input += A_list
    hash_input += B_list
    c = dsh.get_hash_on_Zn(pp.n, hash_input)        # SHA256 of (L, A_list, B_list) --//   c = H''(L, A0, A1, AN, BN)

    c_sum = 0
    for cj in sf.signature.c_list:
        c_sum = (c_sum + cj) % pp.n

    if c == c_sum:  
        return 1
    else:
        return 0

def check_traceability(sf_1, sf_2, pp):
    
    sigma_list_1 = []
    sigma_list_2 = []
    for i in range(len(sf_1.ring)):
        A0 = dsh.get_hash_on_curve(pp, [sf_1.L, sf_1.E])                                                       
        sigma_list_1 += [A0 + (i + 1) * sf_1.signature.A1]                                

        A0 = dsh.get_hash_on_curve(pp, [sf_2.L, sf_2.E])                                                     
        sigma_list_2 += [A0 + (i + 1) * sf_2.signature.A1]                             

    T_list = []
    for i in range(len(sigma_list_1)):
        if sigma_list_1[i] in sigma_list_2:
            T_list += [sf_1.ring[i]]

    if len(T_list) == len(sf_1.ring):
        return 1 # "linked"

    if  len(T_list) == 1 and T_list[0].signerID == sf_1.signerID:
        return -1  # signer's pk 

    return 0 # "independent"    

def decapsulate(C, sk, ind, pp):
    
    K = C[ind + 1] - sk * C[0]
    r = dsh.get_hash_on_Zn(pp.n, [K])           
    if C[0] != r * pp.genEC:
        return 0
    
    AESK = dsh.derive_aes_key(str(K), 16)           
                                 
    return AESK
# -------------------------------------------------- #
