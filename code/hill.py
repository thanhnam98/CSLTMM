import numpy as np
from z3 import *
import math
from sympy import Matrix

cipher_table	= [b'LM',b'TX',b'EW',b'AX',b'AP',b'YV',b'QS',b'AG',b'MH',b'RI',b'MS',b'PJ',b'SN',b'NX',b'NO',b'DX',b'AD',b'CV',b'QC',b'WY',b'CJ',b'FT',b'QE',b'GQ',b'PZ',b'IS',b'UA',b'LZ',b'NC',b'UI',b'CT',b'YE',b'FV']
bigrams_table = [b"TH",b"HE",b"IN",b"ER",b"AN",b"RE",b"ES",b"ON",b"ST",b"NT",b"EN",b"AT",b"ED",b"ND",b"TO",b"OR",b"EA",b"TI",b"AR",b"TE",b"NG",b"AL",b"IT",b"AS",b"IS",b"HA",b"ET",b"SE",b"OU",b"OF",b'AL',b'AS',b'LE']

print(cipher_table)
print(bigrams_table)

def getPlaintext(K):
	cipher          = b'LMQETXYEAGTXCTUIEWNCTXLZEWUAISPZYVAPEWLMGQWYAXFTCJMSQCADAGTXLMDXNXSNPJQSYVAPRIQSMHNOCVAXFV'
	plaintext 		  = b''
	i = 0
	while(i < len(cipher)):
		partial_ciphertext = cipher[i:i+2]
		C = np.array(list(partial_ciphertext)).reshape(2,1).T - ord('A')
		P = np.dot(C,K) % 26

		plaintext = plaintext + chr(P[0][0] + ord('A')).encode('utf-8')
		plaintext = plaintext + chr(P[0][1] + ord('A')).encode('utf-8')

		# print(plaintext)
		i += 2

	print('Plaintext: ' + plaintext.decode('utf-8'))

def gcd(a,b): 
    if(b==0): 
        return a 
    else: 
        return gcd(b,a%b)

def getInverseKeyMatrix(key):
	inverseKeyMatrix = Matrix(key).inv_mod(26)
	np.inverseKeyMatrix = np.array(inverseKeyMatrix)
	return np.inverseKeyMatrix

def calculator(known_plaintext, partial_ciphertext):
    s = Solver()
    x, y, z, t = Ints('x y z t')
    P = np.array(list(known_plaintext[:2])).reshape(2,1).T - ord('A')
    C = np.array(list(partial_ciphertext[:2])).reshape(2,1).T - ord('A')
    a  = str(P[0][0])
    b  = str(P[0][1])
    m1 = str(C[0][0])
    m2 = str(C[0][1])
    s.add((a*x + b*y) % 26 == m1)
    s.add((a*z + b*t) % 26 == m2)
    P = np.array(list(known_plaintext[2:])).reshape(2,1).T - ord('A')
    C  = np.array(list(partial_ciphertext[2:])).reshape(2,1).T - ord('A')
    a  = str(P[0][0])
    b  = str(P[0][1])
    m1 = str(C[0][0])
    m2 = str(C[0][1])
    s.add((a*x + b*y) % 26 == m1)
    s.add((a*z + b*t) % 26 == m2)

    if s.check() == sat:
        ret = s.model()
        return ret[x].as_long(), ret[y].as_long(), ret[z].as_long(), ret[t].as_long()
    else:
        return 'none', 'none', 'none', 'none'  


def  main():
    for pos in range(0,len(bigrams_table)):
        for i in range(0, len(cipher_table)):
            for o in range(0, len(cipher_table)):
                if i == o: continue
                for j in range(0, len(bigrams_table)):
                    if bigrams_table[j] == bigrams_table[pos]:
                        continue
                    known_plaintext 	  = bigrams_table[pos] + bigrams_table[j]
                    partial_ciphertext 	= cipher_table[i] + cipher_table[o]
              
                    x, y, z, t = calculator(known_plaintext, partial_ciphertext)
          
                    if(x != 'none'):
                        key_string = ''
                        key_string += chr((x % 26) + ord('A'))
                        key_string += chr((y % 26) + ord('A'))
                        key_string += chr((z % 26) + ord('A'))
                        key_string += chr((t % 26) + ord('A'))
                        key_string = key_string.encode('utf-8')
                        K = np.array(list(key_string)).reshape(2,2).T - ord('A')

                        det_key = K[0][0]*K[1][1] - K[0][1]*K[1][0]
                        if det_key != 0 and gcd(det_key, 26) == 1:
                            print('[*]Well magic! Found key:' + key_string.decode('utf-8'))
                            K = getInverseKeyMatrix(K)
                            getPlaintext(K)

if __name__ == '__main__':
    main()