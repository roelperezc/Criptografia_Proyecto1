import hashlib as hashes
import re
import timeit
from time import process_time_ns
import matplotlib.pyplot as plt

# Devuelve el tiempo mínimo de ejecución para cada algoritmo por cada vector de prueba
def test(files, n):

    # Lista de vectores de prueba obtenida de archivos
    vectors = test_vectors(files)

    # Minimo de cada algoritmo para cada vector de prueba
    min_sha384 = [99999]*len(vectors)
    min_sha512 = [99999]*len(vectors)
    min_sha3_384 = [99999]*len(vectors)
    min_sha3_512 = [99999]*len(vectors)

    # n pruebas
    for i in range(n):

        # por cada vector de prueba 
        for j in range(len(vectors)):

            # SHA2-384
            m = hashes.sha384()
            m.update(vectors[j]) # Vector j
            ti = timeit.default_timer()#ti = process_time_ns() # inicio
            m.digest()
            tf = timeit.default_timer()#tf = process_time_ns() # fin
            elapsed_time = tf - ti # tiempo de ejecucion
            min_sha384[j] = min(min_sha384[j],elapsed_time)
            
            # SHA2-512
            m = hashes.sha512()
            m.update(vectors[j]) # Vector j
            ti = timeit.default_timer()#ti = process_time_ns() # inicio 
            m.digest()
            tf = timeit.default_timer()#tf = process_time_ns()  # fin
            elapsed_time = tf - ti # tiempo de ejecucion)
            min_sha512[j] = min(min_sha512[j],elapsed_time)
            
            # SHA3-384
            m = hashes.sha3_384()
            m.update(vectors[j]) # Vector j
            ti = timeit.default_timer()#ti = process_time_ns() # inicio
            m.digest()
            tf = timeit.default_timer()#tf = process_time_ns() # fin
            elapsed_time = tf - ti # tiempo de ejecucion
            min_sha3_384[j] = min(min_sha3_384[j],elapsed_time)
            
            # SHA3-512
            m = hashes.sha3_512()
            m.update(vectors[j]) # Vector j
            ti = timeit.default_timer()#ti = process_time_ns() # inicio 
            m.digest()
            tf = timeit.default_timer()#tf = process_time_ns() # fin
            elapsed_time = tf - ti # tiempo de ejecucion
            min_sha3_512[j] = min(min_sha3_512[j],elapsed_time)

    return [min_sha384,min_sha512,min_sha3_384,min_sha3_512]


# Devuelve los vectores de prueba de los archivos 
def test_vectors(files):

    vectors = []

    for file in files: 
        test_vector_file = open(file,"r")
        
        # Por cada linea de archivo de vector de prueba
        for line in test_vector_file:

            # Si la linea contiene un vector de prueba
            if re.match("^Msg",line):
                #Separa y codifica el vector de prueba
                line = line.replace("Msg = ","")
                line = line.replace("\n","")
                line_bytes = line.encode()
                vectors.append(line_bytes)

    return vectors

# Devuelve el valor minimo entre dos valores
def min(x,y):
    if x < y:
        return x
    else:
        return y



pruebas = ["shabytetestvectors/SHA384LongMsg.rsp",
           "shabytetestvectors/SHA512LongMsg.rsp",
           "sha-3bytetestvectors/SHA3_384LongMsg.rsp",
           "sha-3bytetestvectors/SHA3_512LongMsg.rsp"]

resultados = test(pruebas,100)

n = [i for i in range(len(resultados[0]))]

plt.plot(n, resultados[0], 'r-', label='SHA-384')
plt.plot(n, resultados[1], 'b-', label='SHA-512')
plt.plot(n, resultados[2], 'g-', label='SHA3-384')
plt.plot(n, resultados[3], 'y-', label='SHA3-512')

plt.legend(loc='upper left')
plt.xlabel('Vectores de prueba')
plt.ylabel('Minimo de tiempo de ejecuciòn (segundos)')
plt.title('Tiempo de ejecución de vectores de prueba')
plt.show()
