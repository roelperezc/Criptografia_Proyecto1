#Bibliotecas para los algoritmos
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import os
import time
import timeit
import matplotlib.pyplot as plt

# Devuelve el tiempo mínimo de ejecución para cada algoritmo por cada tamaño de vector de prueba
def test(v, n, r):
    # Minimo de cada algoritmo para cada vector de prueba
    min_chacha20_enc = [9999999999]*v
    min_chacha20_dec = [9999999999]*v
    min_ecb_enc  = [9999999999]*v
    min_ecb_dec  = [9999999999]*v
    min_cbc_enc  = [9999999999]*v
    min_cbc_dec  = [9999999999]*v
    min_oaep_enc = [9999999999]*v
    min_oaep_dec = [9999999999]*v
    
    #-> Entradas
    
    #Llaves para RSA-OAEP (tamaño 1024, hash SHA-256)
    if r == 1:
        private_key = rsa.generate_private_key(public_exponent=65537,key_size=1024)
        public_key = private_key.public_key()
    #Llave para Chacha20 y AES (tamaño 256 bits = 32 bytes)
    key = os.urandom(32)
    #Nonce para Chacha20 (tamaño 128 bits = 16 bytes)
    nonce = os.urandom(16)
    #Vector de inicialización para AES (tamaño 128 bits = 16 bytes)
    iv = os.urandom(16)
    
    #-> Funciones para utilizar los algoritmos
    
    #Chacha20
    chacha20 = algorithms.ChaCha20(key, nonce)
    cipher_chacha20 = Cipher(chacha20, mode=None)
    #AES-ECB/AES-CBC
    cipher_aes_ecb = Cipher(algorithms.AES(key), modes.ECB())
    cipher_aes_cbc = Cipher(algorithms.AES(key), modes.CBC(iv))
    
    # tamaño de vectores de prueba
    for i in range(v):
        #print("Para "+str(i))
        #Vector de tamaño fijo
        message = os.urandom(62)
        
        # número de pruebas por cada tamaño de vector 
        for j in range(n):
            
            #Padding para AES
            padder = pad.PKCS7(128).padder() #bloques de 128 bits
            padded_data = padder.update(message)
            padded_data += padder.finalize()
            
            #Cifrado Chacha20 (key, nonce)
            ti = timeit.default_timer() # inicio
            encryptor = cipher_chacha20.encryptor()
            ct = encryptor.update(message)
            tf = timeit.default_timer()  # fin
            elapsed_time = tf - ti # tiempo de ejecucion)
            min_chacha20_enc[i] = min(min_chacha20_enc[i], elapsed_time) #Min por cada tamaño de vector
            
            #Decifrado Chacha20 (message)
            ti = timeit.default_timer() # inicio
            decryptor = cipher_chacha20.decryptor()
            pt = decryptor.update(ct)
            tf = timeit.default_timer()  # fin
            elapsed_time = tf - ti # tiempo de ejecucion)
            min_chacha20_dec[i] = min(min_chacha20_dec[i], elapsed_time) #Min por cada tamaño de vector
            
            #Cifrado AES-ECB
            ti = timeit.default_timer() # inicio
            encryptor = cipher_aes_ecb.encryptor()
            ct = encryptor.update(padded_data)
            tf = timeit.default_timer()  # fin
            elapsed_time = tf - ti # tiempo de ejecucion)
            min_ecb_enc[i] = min(min_ecb_enc[i], elapsed_time) #Min por cada tamaño de vector

            #Decifrado AES-ECB
            ti = timeit.default_timer() # inicio
            decryptor = cipher_aes_ecb.decryptor()
            pt = decryptor.update(ct)
            tf = timeit.default_timer()  # fin
            elapsed_time = tf - ti # tiempo de ejecucion)
            min_ecb_dec[i] = min(min_ecb_dec[i], elapsed_time) #Min por cada tamaño de vector
            
            #Cifrado AES-CBC
            ti = timeit.default_timer() # inicio
            encryptor = cipher_aes_cbc.encryptor()
            ct = encryptor.update(padded_data)
            tf = timeit.default_timer()  # fin
            elapsed_time = tf - ti # tiempo de ejecucion)
            min_cbc_enc[i] = min(min_cbc_enc[i], elapsed_time) #Min por cada tamaño de vector

            #Decifrado AES-CBC
            ti = timeit.default_timer() # inicio
            decryptor = cipher_aes_cbc.decryptor()
            pt = decryptor.update(ct)
            tf = timeit.default_timer()  # fin
            elapsed_time = tf - ti # tiempo de ejecucion)
            min_cbc_dec[i] = min(min_cbc_dec[i], elapsed_time) #Min por cada tamaño de vector
            
            if r == 1 :
                #Cifrado RSA-OAEP (mensaje)
                ti = timeit.default_timer() # inicio
                ct = public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                tf = timeit.default_timer()  # fin
                elapsed_time = tf - ti # tiempo de ejecucion)
                min_oaep_enc[i] = min(min_oaep_enc[i], elapsed_time) #Min por cada tamaño de vector
            
                #Decifrado RSA-OAEP (ciphertext)
                ti = timeit.default_timer() # inicio
                pt = private_key.decrypt(ct, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                tf = timeit.default_timer()  # fin
                elapsed_time = tf - ti # tiempo de ejecucion)
                min_oaep_dec[i] = min(min_oaep_dec[i], elapsed_time) #Min por cada tamaño de vector
            
    return [min_chacha20_enc,min_chacha20_dec,min_ecb_enc,min_ecb_dec,min_cbc_enc,min_cbc_dec,min_oaep_enc,min_oaep_dec]

#Devuelve el valor minimo entre dos valores
def min(x,y):
    if x < y:
        return x
    else:
        return y

#Núm máx de tamaño de vector 62 bytes
resultados = test(62,300,1)
#Núm máx de tamaño de vector 600 bytes
resultados2 = test(600,300,0)

n = []
for x in range(62):
    n.append(x)

n2 = []
for x in range(600):
    n2.append(x)
    
#Gráfica de cifrado
plt.plot(n, resultados[0], 'r-', label='Chacha20')
plt.plot(n, resultados[2], 'g-', label='AES-ECB')
plt.plot(n, resultados[4], 'b-', label='AES-CBC')
plt.plot(n, resultados[6], 'y-', label='RSA-OAEP')
plt.xlabel('Vectores de prueba')
plt.ylabel('Mínimo de tiempo de ejecución')
plt.legend(loc='upper left')
plt.suptitle('Cifrado Chacha20 vs AES-ECB vs AES-CBC vs RSA-OAEP')
plt.title('Tamaño de vectores de prueba 62 bytes')
plt.show()

#Gráfica de cifrado
plt.plot(n2, resultados2[0], 'r-', label='Chacha20')
plt.plot(n2, resultados2[2], 'g-', label='AES-ECB')
plt.plot(n2, resultados2[4], 'b-', label='AES-CBC')
plt.xlabel('Vectores de prueba')
plt.ylabel('Mínimo de tiempo de ejecución')
plt.legend(loc='upper left')
plt.suptitle('Cifrado Chacha20 vs AES-ECB vs AES-CBC')
plt.title('Tamaño de vectores de prueba 600 bytes')
plt.show()
    
#Gráfica de decifrado
plt.plot(n, resultados[1], 'r-', label='Chacha20')
plt.plot(n, resultados[3], 'g-', label='AES-ECB')
plt.plot(n, resultados[5], 'b-', label='AES-CBC')
plt.plot(n, resultados[7], 'y-', label='RSA-OAEP')
plt.xlabel('Vectores de prueba')
plt.ylabel('Mínimo de tiempo de ejecución')
plt.legend(loc='upper left')
plt.suptitle('Decifrado Chacha20 vs AES-ECB vs AES-CBC vs RSA-OAEP')
plt.title('Tamaño de vectores de prueba 62 bytes')
plt.show()

#Gráfica de decifrado
plt.plot(n2, resultados2[1], 'r-', label='Chacha20')
plt.plot(n2, resultados2[3], 'g-', label='AES-ECB')
plt.plot(n2, resultados2[5], 'b-', label='AES-CBC')
plt.xlabel('Vectores de prueba')
plt.ylabel('Mínimo de tiempo de ejecución')
plt.legend(loc='upper left')
plt.suptitle('Decifrado Chacha20 vs AES-ECB vs AES-CBC')
plt.title('Tamaño de vectores de prueba 600 bytes')
plt.show()