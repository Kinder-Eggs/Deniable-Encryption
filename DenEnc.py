from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import random

HEADER_PREFIX = '\x96\x93\xf3\xcf'  # prefixo das mensagens, pode ser alterado
EXP_CNT = 10 * 1001  # Expansion count para o hash, maior = mais lento
MSG_LEN = 2*16  # Tamanho da mensagem, deve ser multiplo de 16 (a mensagem pode ter ate este valor -4)

code = raw_input("Digite d para decriptar ou e para encriptar: ")
if(code == 'e'):
	message = raw_input("Insire a primeira mensagem para ser encriptada: ")
	password = raw_input("Insira a primeira chave: ")
	message2 = raw_input("Insire a segunda mensagem para ser encriptada: ")
	password2 = raw_input("Insira a segunda chave: ")

	message = HEADER_PREFIX + message  # Adiciona o prefixo
	message2 = HEADER_PREFIX + message2


	while (len(message)%MSG_LEN != 0):  # Completa mensagems com espacos ate MSG_LEN
		message += " "

	while (len(message2)%MSG_LEN != 0):
		message2 += " "

	kandm = {password: message, password2: message2}  # Gera um dict com a chave e a mensagem

	for key, msg in kandm.iteritems():  # Cria o hash de cada chave e encripta cada mensagem com ela

		cipher = AES.new(PBKDF2(key, '-'*256, 32, EXP_CNT, prf=lambda p,s: HMAC.new(p,s,SHA256).digest()))  # Password-Based Key Derivation Function 2

		kandm[key] = cipher.encrypt(msg)

	# Transforma o dict em uma unica string completamente ilegivel
	messages = kandm.values()
	
	ciphertext = reduce(lambda x, y: x + y, messages)

	print(ciphertext)

	with open("output.txt", 'w') as f:
		f.write(ciphertext)  # coloca a mensagem cifrada em um arquivo

if(code == 'd'):
	password = raw_input("Insira a chave: ")

	cipher = AES.new(PBKDF2(password, '-'*256, 32, EXP_CNT, prf=lambda p,s: HMAC.new(p,s,SHA256).digest()))  # Password-Based Key Derivation Function 2

	with open("output.txt", 'r') as f:
		message = f.read()

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


