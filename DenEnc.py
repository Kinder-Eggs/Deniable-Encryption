from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import random

HEADER_PREFIX = '\x96\x93\xf3\xcf'  # Header for the messages (changes in size must be modified on line 57 and onwards)
EXP_CNT = 10 * 1000  # Expansion count value, make it higher so it takes more time (brute force security measure)
MSG_LEN = 2*16  # Message length will be equivalente to this value - size of the header (must be a multiple of 16)

code = raw_input("Digite d para decriptar ou e para encriptar: ")
if(code == 'e'):
	message = raw_input("Insire a primeira mensagem para ser encriptada: ")
	password = raw_input("Insira a primeira chave: ")
	message2 = raw_input("Insire a segunda mensagem para ser encriptada: ")
	password2 = raw_input("Insira a segunda chave: ")

	message = HEADER_PREFIX + message
	message2 = HEADER_PREFIX + message2


	while (len(message)%MSG_LEN != 0):  # Complete messages with blanks until it has the desired size
		message += " "

	while (len(message2)%MSG_LEN != 0):
		message2 += " "

	kandm = {password: message, password2: message2}

	for key, msg in kandm.iteritems():  # Create each key hash and encrypt the equivalent message with it

		cipher = AES.new(PBKDF2(key, '-'*256, 32, EXP_CNT, prf=lambda p,s: HMAC.new(p,s,SHA256).digest()))  # Password-Based Key Derivation Function 2

		kandm[key] = cipher.encrypt(msg)

	# Concatenate the encrypted messages creating an unreadable string
	messages = kandm.values()
	
	ciphertext = reduce(lambda x, y: x + y, messages)

	print(ciphertext)

	with open("output.txt", 'w') as f:
		f.write(ciphertext)  # Save the string on a .txt file

if(code == 'd'):
	password = raw_input("Insira a chave: ")

	cipher = AES.new(PBKDF2(password, '-'*256, 32, EXP_CNT, prf=lambda p,s: HMAC.new(p,s,SHA256).digest()))  # Password-Based Key Derivation Function 2

	with open("output.txt", 'r') as f:
		message = f.read()  # Read the archive where the encrypted string is saved

	msg = cipher.decrypt(message)

	plaintext = ''
	for i in range(len(msg)):
		if (msg[i] == HEADER_PREFIX[0]):
			if (msg[i+1] == HEADER_PREFIX[1]):
				if (msg[i+2] == HEADER_PREFIX[2]):
					if (msg[i+3] == HEADER_PREFIX[3]):
						for j in range(MSG_LEN - 4):
							plaintext += msg[i+4+j]
						break


	print(plaintext)


