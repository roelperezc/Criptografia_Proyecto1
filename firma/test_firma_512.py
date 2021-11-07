# -*- coding: utf-8 -*-
"""
Created on Sat Oct 30 13:22:41 2021

"""

import matplotlib.pyplot as plt
import time
import re
from time import process_time_ns
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

test_gen = open("186-4ecdsatestvectors/SigGen.txt","r")

    #Generación de llaves privadas 
pk_rsa = rsa.generate_private_key(public_exponent=65537,key_size=1024)
pk_ecdsa_521 = ec.generate_private_key(ec.SECP521R1())
pk_ecdsa_571 = ec.generate_private_key(ec.SECT571K1())
    
    #Generación de llaves públicas
pbk_rsa = pk_rsa.public_key()
pbk_ecdsa_521 = pk_ecdsa_521.public_key()
pbk_ecdsa_571 = pk_ecdsa_571.public_key()
    
publicKeys = [pbk_rsa,pbk_ecdsa_521,pbk_ecdsa_571]

rsa_256s,ecdsa521_256s,ecdsa571_256s = [],[],[]
rsa_256v,ecdsa_521_256v,ecdsa_571k_256v = [],[],[]
    
rsa_512s,ecdsa521_512s,ecdsa571_512s = [],[],[]
rsa_512v,ecdsa_521_512v,ecdsa_571k_512v = [],[],[]

def signature(pk_rsa,pk_ecdsa_521,pk_ecdsa_571,line_bytes):
    
    global rsa_256s,ecdsa521_256s,ecdsa571_256s
    global rsa_512s,ecdsa521_512s,ecdsa571_512s
    
    signatures = []
    
    ti = time.time()
    rsa_sig = pk_rsa.sign(line_bytes,padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    tf = time.time()
    rsa_256s.append(tf - ti)
    
    ti = time.time()
    ecdsa_521_sig = pk_ecdsa_521.sign(line_bytes,ec.ECDSA(hashes.SHA256()))
    tf = time.time()
    ecdsa521_256s.append(tf - ti)
    
    ti = time.time()
    ecdsa_571_sig = pk_ecdsa_571.sign(line_bytes,ec.ECDSA(hashes.SHA256()))
    tf = time.time()
    ecdsa571_256s.append(tf - ti)
    
    ti = time.time()
    rsa_sig_512 = pk_rsa.sign(line_bytes,padding.PSS(mgf=padding.MGF1(hashes.SHA512_256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    tf = time.time()
    rsa_512s.append(tf - ti)
    
    ti = time.time()
    ecdsa_521_sig_512 = pk_ecdsa_521.sign(line_bytes,ec.ECDSA(hashes.SHA512_256()))
    tf = time.time()
    ecdsa521_512s.append(tf - ti)
    
    ti = time.time()
    ecdsa_571_sig_512 = pk_ecdsa_571.sign(line_bytes,ec.ECDSA(hashes.SHA512_256()))
    tf = time.time()
    ecdsa571_512s.append(tf - ti)
    
    #Firma RSA
    signatures.append([rsa_sig,rsa_sig_512])

    #Firma ECDSA521
    signatures.append([ecdsa_521_sig,ecdsa_521_sig_512])
    
    #Firma ECDSA571
    signatures.append([ecdsa_571_sig,ecdsa_571_sig_512])
    
    return signatures
    
def verification(signatures,publicKeys,line_bytes):
    
    global rsa_256v,ecdsa_521_256v,ecdsa_571k_256v
    global rsa_512v,ecdsa_521_512v,ecdsa_571k_512v
    
#    sha_256, sha_512 = []
    
    #RSA
    #publicKeys[0] = pbk_rsa ----------------- signatures[0][0] = rsa_sig
    ti = time.time()
    publicKeys[0].verify(signatures[0][0],line_bytes,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    tf = time.time()
    rsa_256v.append(tf - ti)
    
    #publicKeys[0] = pbk_rsa ----------------- signatures[0][1] = rsa_sig_512
    ti = time.time()
    publicKeys[0].verify(signatures[0][1],line_bytes,padding.PSS(mgf=padding.MGF1(hashes.SHA512_256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    tf = time.time()
    rsa_512v.append(tf - ti)
    
    #ECDSA 521
    #publicKeys[1] = pbk_ecdsa_521 ----------------- signatures[1][0] = ecdsa_521_sig
    ti = time.time()
    publicKeys[1].verify(signatures[1][0], line_bytes, ec.ECDSA(hashes.SHA256()))
    tf = time.time()
    ecdsa_521_256v.append(tf - ti)
    
    #publicKeys[1] = pbk_ecdsa_521 ----------------- signatures[1][1] = ecdsa_521_sig_512
    ti = time.time()
    publicKeys[1].verify(signatures[1][1], line_bytes, ec.ECDSA(hashes.SHA512_256()))
    tf = time.time()
    ecdsa_521_512v.append(tf - ti)
        
    #ECDSA 571
    #publicKeys[2] = pbk_ecdsa_571 ----------------- signatures[0][0] = ecdsa_571_sig
    ti = time.time()
    publicKeys[2].verify(signatures[2][0], line_bytes, ec.ECDSA(hashes.SHA256()))
    tf = time.time()
    ecdsa_571k_256v.append(tf - ti)
    
    #publicKeys[2] = pbk_ecdsa_571 ----------------- signatures[0][1] = ecdsa_571_sig_512
    ti = time.time()
    publicKeys[2].verify(signatures[2][1], line_bytes, ec.ECDSA(hashes.SHA512_256()))
    tf = time.time()
    ecdsa_571k_512v.append(tf - ti)
        
    return


def test(line_bytes):
    
    global rsa_256s,ecdsa521_256s,ecdsa571_256s
    global rsa_512s,ecdsa521_512s,ecdsa571_512s
    global rsa_256v,ecdsa_521_256v,ecdsa_571k_256v
    global rsa_512v,ecdsa_521_512v,ecdsa_571k_512v
    
    rsa_256s,ecdsa521_256s,ecdsa571_256s = [],[],[]
    rsa_256v,ecdsa_521_256v,ecdsa_571k_256v = [],[],[]
        
    rsa_512s,ecdsa521_512s,ecdsa571_512s = [],[],[]
    rsa_512v,ecdsa_521_512v,ecdsa_571k_512v = [],[],[]

    sha_256s, sha_512s,sha_256v, sha_512v = [],[],[],[]
    
    for line in line_bytes:

        #Firma de mensaje
        signatures=signature(pk_rsa,pk_ecdsa_521,pk_ecdsa_571,line)
    
        #Verificación de firma
        verification(signatures,publicKeys,line)
    
    sha_256s.append([rsa_256s,ecdsa521_256s,ecdsa571_256s])
    sha_512s.append([rsa_512s,ecdsa521_512s,ecdsa571_512s])
    sha_256v.append([rsa_256v,ecdsa_521_256v,ecdsa_571k_256v])
    sha_512v.append([rsa_512v,ecdsa_521_512v,ecdsa_571k_512v])
    
    return sha_256s,sha_256v,sha_512s,sha_512v

def comparacion(array, compare):
    for i in range(len(array)):
        for j in range(len(array[0])):
            if compare[i][j] < array[i][j]:
                array[i][j] = compare[i][j]
    return array
    
def main():
    
    gen_time = time.time()
    num = []
    line_bytes = []
    
    for line in test_gen:
        if re.match("^Msg",line):
            
            line = line.replace("Msg = ","")
            line = line.replace("\n","")
            
            line_bytes.append(line.encode())
            

    s256,v256,s512,v512 = test(line_bytes)
    for i in range(9):
        s256_1,v256_1,s512_1,v512_1 = test(line_bytes)
        s256 = comparacion(s256, s256_1)
        v256 = comparacion(v256, v256_1)
        s512 = comparacion(s512, s512_1)
        v512 = comparacion(v512, v512_1)
    
    for x in range(len(s256[0][1])):
        num.append(x)
        
    #Gráfica de firma
    fig = plt.figure(figsize=(100,75))
    fig.add_subplot(941)
    plt.plot(num,s256[0][0],'-b',label='RSA PSS')
    plt.plot(num,s256[0][1],'-g',label='ECDSA 521')
    plt.plot(num,s256[0][2],'-r',label='ECDSA 571K')
    plt.xlabel('Mensjaes')
    plt.ylabel('Tiempo')
    plt.legend(loc='best')
    plt.title('Firma RSA vs ECDSA 521 vs ECDSA 571 con SHA256')
    plt.show()
    
    #Gráfica de verificación de firma
    fig = plt.figure(figsize=(100,75))
    fig.add_subplot(941)
    plt.plot(num,v256[0][0],'-b',label='RSA PSS')
    plt.plot(num,v256[0][1],'-g',label='ECDSA 521')
    plt.plot(num,v256[0][2],'-r',label='ECDSA 571K')  
    plt.xlabel('Messages')
    plt.ylabel('Time')
    plt.legend(loc='best')
    plt.title('Verificación de firma RSA vs ECDSA 521 vs ECDSA 571 con SHA256')
    plt.show()
    
    #Gráfica de firma
    fig = plt.figure(figsize=(100,75))
    fig.add_subplot(941)
    plt.plot(num,s512[0][0],'-b',label='RSA PSS')
    plt.plot(num,s512[0][1],'-g',label='ECDSA 521')
    plt.plot(num,s512[0][2],'-r',label='ECDSA 571K')
    plt.xlabel('Mensjaes')
    plt.ylabel('Tiempo')
    plt.legend(loc='best')
    plt.title('Firma RSA vs ECDSA 521 vs ECDSA 571 con SHA512')
    plt.show()
    
    #Gráfica de verificación de firma
    fig = plt.figure(figsize=(100,75))
    fig.add_subplot(941)
    plt.plot(num,v512[0][0],'-b',label='RSA PSS')
    plt.plot(num,v512[0][1],'-g',label='ECDSA 521')
    plt.plot(num,v512[0][2],'-r',label='ECDSA 571K')  
    plt.xlabel('Messages')
    plt.ylabel('Time')
    plt.legend(loc='best')
    plt.title('Verificación de firma RSA vs ECDSA 521 vs ECDSA 571 con SHA512')
    plt.show()
    
    print("Tiempo total de ejecucion: ", time.time() - gen_time)
    return 0

main()
