import hashlib
import re
from time import process_time_ns
import matplotlib.pyplot as plt


def prueba():

    test_v_file = open("sha-3bytetestvectors/SHA3_512LongMsg.rsp","r")

    t_sha384 = []
    t_sha512 = []
    t_sha3_384 = []
    t_sha3_512 = []
    
    for line in test_v_file:

        if re.match("^Msg",line):
            line = line.replace("Msg = ","")
            line = line.replace("\n","")

            line_bytes = line.encode()

            m = hashlib.sha384()
            m.update(line_bytes)
            ti = process_time_ns() # inicio
            m.digest()
            tf = process_time_ns() # fin
            elapsed_time = tf - ti
            t_sha384.append(elapsed_time)

            m = hashlib.sha512()
            m.update(line_bytes)
            ti = process_time_ns() # inicio 
            m.digest()
            tf = process_time_ns()  # fin
            elapsed_time = tf - ti
            t_sha512.append(elapsed_time)

            m = hashlib.sha3_384()
            m.update(line_bytes)
            ti = process_time_ns() # inicio
            m.digest()
            tf = process_time_ns() # fin
            elapsed_time = tf - ti
            t_sha3_384.append(elapsed_time)

            m = hashlib.sha3_512()
            m.update(line_bytes)
            ti = process_time_ns() # inicio 
            m.digest()
            tf = process_time_ns() # fin
            elapsed_time = tf - ti
            t_sha3_512.append(elapsed_time)
    
    return [t_sha384,t_sha512,t_sha3_384,t_sha3_512]

def test_average(n):
    resultado = prueba()
    for i in range(n-1):
        resultado_temp = prueba()
        for j in range(len(resultado[0])):
            resultado[0][j] = resultado[0][j] + resultado_temp[0][j]
            resultado[1][j] = resultado[1][j] + resultado_temp[1][j]
            resultado[2][j] = resultado[2][j] + resultado_temp[2][j]
            resultado[3][j] = resultado[3][j] + resultado_temp[3][j]
    for i in range(len(resultado[0])):
        resultado[0][i] = resultado[0][i] / n
        resultado[1][i] = resultado[1][i] / n
        resultado[2][i] = resultado[2][i] / n
        resultado[3][i] = resultado[3][i] / n
    
    return resultado

pruebas_promedio = test_average(100)

n = [i for i in range(100)]

plt.plot(n, pruebas_promedio[0], 'r-', label='SHA-384')
plt.plot(n, pruebas_promedio[1], 'b-', label='SHA-512')
plt.plot(n, pruebas_promedio[2], 'g-', label='SHA3-384')
plt.plot(n, pruebas_promedio[3], 'y-', label='SHA3-512')

plt.legend(loc='upper left')
plt.xlabel('Vectores de prueba')
plt.ylabel('Tiempo de ejecuciòn (nanosegundos)')

plt.show()