from random import randint

ALPHABET = ' 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'

def OTP_encrypt(plain_text, key):

	cipher_text = ''
	for index, char in enumerate(plain_text):
		key_index = index
		char_index = ALPHABET.find(char)
		cipher_text += ALPHABET[(char_index+key_index)%len(ALPHABET)]
		
	return cipher_text	

def OTP_decrypt(cipher_text, key):

	plain_text = ''
	
	for index, char in enumerate(cipher_text):
		key_index = index
		char_index = ALPHABET.find(char)
		plain_text += ALPHABET[(char_index-key_index)%len(ALPHABET)]	
		
	return plain_text	

def OTP_random_sequence(plain_text):
	random_sequence = []
	for rand in range(len(plain_text)):
		random_sequence.append(randint(0,len(ALPHABET)))
		
	return random_sequence
	
if __name__ == "__main__":
	
	plain_text = "Shannon defined the quantity of information produced by a source for example the quantity in a message by a formula similar to the equation that defines thermodynamic entropy in physics. In its most basic terms Shannons informational entropy is the number of binary digits required to encode a message. Today that sounds like a simple even obvious way to define how much information is in a message. In 1948, at the very dawn of the information age, this digitizing of information of any sort was a revolutionary step. His paper may have been the first to use the word bit, short for binary digit. As well as defining information, Shannon analyzed the ability to send information through a communications channel. He found that a channel had a certain maximum transmission rate that could not be exceeded. Today we call that the bandwidth of the channel. Shannon demonstrated mathematically that even in a noisy channel with a low bandwidth, essentially perfect, error-free communication could be achieved by keeping the transmission rate within the channel's bandwidth and by using error-correcting schemes: the transmission of additional bits that would enable the data to be extracted from the noise-ridden signal. Today everything from modems to music CDs rely on error-correction to function. A major accomplishment of quantum-information scientists has been the development of techniques to correct errors introduced in quantum information and to determine just how much can be done with a noisy quantum communications channel or with entangled quantum bits (qubits) whose entanglement has been partially degraded by noise."
	key = OTP_random_sequence(plain_text)
	cipher_text = OTP_encrypt(plain_text, key)
	print("Encrypted message: \n%s" % cipher_text)
	decrypted_text = OTP_decrypt(cipher_text, key)
	print("Decrypted message: \n%s" % decrypted_text)


