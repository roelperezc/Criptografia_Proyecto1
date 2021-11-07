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

def signature(pk_rsa,pk_ecdsa_521,pk_ecdsa_571,line_bytes):
    
    signatures = []    
    
    ti = time.time()
    rsa_sig = pk_rsa.sign(line_bytes,padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    tf = time.time()
    rsa_pss = tf - ti
    
    ti = time.time()
    ecdsa_521_sig = pk_ecdsa_521.sign(line_bytes,ec.ECDSA(hashes.SHA256()))
    tf = time.time()
    ecdsa_521 = tf - ti
    
    ti = time.time()
    ecdsa_571_sig = pk_ecdsa_571.sign(line_bytes,ec.ECDSA(hashes.SHA256()))
    tf = time.time()
    ecdsa_571k = tf - ti
    
    #Firma RSA
    signatures.append(rsa_sig)

    #Firma ECDSA521
    signatures.append(ecdsa_521_sig)
    
    #Firma ECDSA571
    signatures.append(ecdsa_571_sig)
    
    return rsa_pss,ecdsa_521,ecdsa_571k, signatures
    
def verification(signatures,publicKeys,line_bytes):
    
    #RSA
    #publicKeys[0] = pbk_rsa ----------------- signatures[0] = rsa_sig
    ti = time.time()
    publicKeys[0].verify(signatures[0],line_bytes,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    tf = time.time()
    rsa_ver = tf - ti
    
    #ECDSA 521
    #publicKeys[1] = pbk_ecdsa_521 ----------------- signatures[1] = ecdsa_521_sig
    ti = time.time()
    publicKeys[1].verify(signatures[1], line_bytes, ec.ECDSA(hashes.SHA256()))
    tf = time.time()
    ecdsa_521_ver = tf - ti
    
    #ECDSA 571
    #publicKeys[2] = pbk_ecdsa_571 ----------------- signatures[0] = ecdsa_571_sig
    ti = time.time()
    publicKeys[2].verify(signatures[2], line_bytes, ec.ECDSA(hashes.SHA256()))
    tf = time.time()
    ecdsa_571_ver = tf - ti
    
    return rsa_ver, ecdsa_521_ver, ecdsa_571_ver

def test(line_bytes):
    

    rsa_temp = []
    ecdsa521_temp = []
    ecdsa571_temp = []
    
    rsa_pss_ver = []
    ecdsa_571k_ver = []
    ecdsa_521_ver = []
    
    for line in line_bytes:

            #Firma de mensaje
        rsa_t,ec521,ec571,signatures=signature(pk_rsa,pk_ecdsa_521,pk_ecdsa_571,line)
        rsa_temp.append(rsa_t)
        ecdsa521_temp.append(ec521)
        ecdsa571_temp.append(ec571)
    
                #Verificación de firma
        rsa_ver,ec521_ver,ec571_ver=verification(signatures,publicKeys,line)
        rsa_pss_ver.append(rsa_ver)
        ecdsa_521_ver.append(ec521_ver)
        ecdsa_571k_ver.append(ec571_ver)
            

    return [rsa_temp,ecdsa521_temp,ecdsa571_temp],[rsa_pss_ver,ecdsa_521_ver,ecdsa_571k_ver]

def comparacion(array, compare):
    for i in range(len(array)):
        for j in range(len(array[0])):
            if compare[i][j] < array[i][j]:
                array[i][j] = compare[i][j]
    return array
    
def main():
    num = []
    line_bytes = []
    
    for line in test_gen:
        if re.match("^Msg",line):
            
            line = line.replace("Msg = ","")
            line = line.replace("\n","")
            
            line_bytes.append(line.encode())
            

    sign_times,ver_times = test(line_bytes)
    
    for i in range(9):
        sig_aux,ver_aux = test(line_bytes)
        sign_times = comparacion(sign_times, sig_aux)
        ver_times = comparacion(ver_times,ver_aux)

    for x in range(len(sign_times[0])):
        num.append(x)
        
    #Gráfica de firma
    fig = plt.figure()
    fig.add_subplot(941)
    plt.plot(num,sign_times[0],'-b',label='RSA PSS')
    plt.plot(num,sign_times[1],'-g',label='ECDSA 521')
    plt.plot(num,sign_times[2],'-r',label='ECDSA 571K')
    plt.xlabel('Mensjaes')
    plt.ylabel('Tiempo')
    plt.legend(loc='best')
    plt.title('Firma RSA vs ECDSA 521 vs ECDSA 571')
    plt.show()
    
    #Gráfica de verificación de firma
    fig = plt.figure()
    fig.add_subplot(941)
    plt.plot(num,ver_times[0],'-b',label='RSA PSS')
    plt.plot(num,ver_times[1],'-g',label='ECDSA 521')
    plt.plot(num,ver_times[2],'-r',label='ECDSA 571K')  
    plt.xlabel('Messages')
    plt.ylabel('Time')
    plt.legend(loc='best')
    plt.title('Verificación de firma RSA vs ECDSA 521 vs ECDSA 571')
    plt.show()

    return 0

main()
