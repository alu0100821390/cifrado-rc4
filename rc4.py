##############################################################################
## Universidad de La Laguna						    ##
## Escuela Superior de Ingeniería y Tecnología	 			    ##
## Grado en Ingeniería Informática				 	    ##
## Seguridad en Sistemas Informáticos			 		    ##
## Fecha: 07/03/2017							    ##
## Autor: Kevin Estévez Expósito (alu0100821390) 			    ##
## 									    ##
## Práctica 3: Cifrado RC4						    ##
## Descripción: Cifrado y descifrado de mensajes mediante el cifrado RC4.   ##
##									    ##
## Ejecución: py rc4.py "'texto_original'" "'semilla_de_clave'"		    ##
## Ejemplo de ejecución: py rc4.py "1, 34" "2, 5" 			    ##
##############################################################################


import sys
from operator import xor

texto_original = sys.argv[1].replace(' ', '').split(",")	# Se guarda el texto original pasado por parámetros en forma de lista #
semilla_original = sys.argv[2].replace(' ', '').split(",")	# Se guarda la semilla de clave pasada por parámetros en forma de lista #

M = []
for i in texto_original:	# Se guarda el texto original como lista de enteros
	M.append(int(i))

semilla = []
for i in semilla_original:	# Se guarda la semilla original como lista de enteros
	semilla.append(int(i))


##### INICIALIZACIÓN (KSA) #####

print ()
print ("INICIALIZACIÓN")
print ()

S = list(range(0, 256))	# Se crea el vector de estado en forma de lista

K = []
for i in range(len(S)):	# Se amplía la clave hasta una longitud de 256
	K.append(semilla[i%len(semilla)])

print ("S =", S)
print ()
print ("K =", K)
print ()

f = 0
for i in range(len(S)):
	print ("S[" + str(i) + "]=" + str(S[i]) + ", K[" + str(i) + "]=" + str(K[i]) + " produce ", end="")

	f = (f + S[i] + K[i]) % len(S)
	S[i], S[f] = S[f], S[i]	# Inercambia S[i] y S[f]
	
	print ("f=" + str(f) + ", S[" + str(i) + "]=" + str(S[i]) + ", S[" + str(f) + "]=" + str(S[f]))

print ()
print ("S =", S)
print ()


##### GENERACIÓN DE SECUENCIA CIFRANTE Y TEXTO CIFRADO (PRGA) #####

print()
print ("GENERACIÓN DE SECUENCIA CIFRANTE Y TEXTO CIFRADO")
print ()

secuencia_cifrante = []
C = []

i = 0
f = 0
for j in range (len(M)):	# Genera cada byte de secuencia
	i = (i+1)%len(S)
	f = (f+S[i])%len(S)
	S[i], S[f] = S[f], S[i]	# Intercambia S[i] y S[f]
	t = (S[i]+S[f])%len(S)
	secuencia_cifrante.append(S[t])	# Se guarda la secuencia cifrante generada
	C.append(xor(M[j], S[t]))	# Se cifra el texto con una XOR

	print ("Byte " + str(j+1) + " de secuencia cifrante: Salida: S[" + str(t) + "] = " + str(S[t]) + ":\t" + bin(S[t])[2:].zfill(8))
	print ("Byte " + str(j+1) + " de texto original: Entrada: M[" + str(j+1) + "] = " + str(M[j]) + ":\t\t" + bin(M[j])[2:].zfill(8))
	print ("Byte " + str(j+1) + " de texto cifrado: Salida: C[" + str(j+1) + "] = " + str(C[j]) + ":\t\t" + bin(C[j])[2:].zfill(8))
	print ()

print ()
print ("Secuencia cifrante:", secuencia_cifrante)
print ("Texto cifrado:", C)
print ()


##### DESCIFRADO #####

print ()
print ("Descifrando...")

descifrado_lista = []

for i in range (len(C)):	# Se descifra el texto cifrado con una XOR y la secuencia cifrante
	descifrado_lista.append(xor(secuencia_cifrante[i], C[i]))

descifrado = ''
for i in range (len(descifrado_lista)-1):
	descifrado += str(descifrado_lista[i])
	descifrado += ', '
descifrado += str(descifrado_lista[len(descifrado_lista)-1])

print ()
print ("Texto original descifrado:", descifrado)


sys.exit(0)
