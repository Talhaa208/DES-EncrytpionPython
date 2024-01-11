from tkinter import *
from tkinter import ttk
from otp import *
from des import des,base64


ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
root = Tk()
root.resizable(0,0)

root.title("Encryiption/Decryption App")
Ciphered = ""
decipher = ""
Algorithm = IntVar()


# Encryption Frame
encryptedframe = ttk.LabelFrame(root, text="Encryption Cell", padding=(10, 10))
encryptedframe.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

title_frame = ttk.Label(encryptedframe, text="Type the message to Encrypt")
title_frame.grid(row=0, column=0, pady=(0, 10), sticky="w")

messagebox = Text(encryptedframe, width=45, height=10)
messagebox.grid(row=1, column=0, pady=(0, 10))

encryptedkey_frame = ttk.LabelFrame(encryptedframe, width=400, height=10)
encryptedkey_frame.grid(row=2, column=0, pady=(0, 10), sticky="w")

label = ttk.Label(encryptedkey_frame, text="Enter The Encryption Key", foreground="blue")
label.grid(row=0, column=0)

Encryptedkey = ttk.Entry(encryptedkey_frame, width=32)
Encryptedkey.grid(row=0, column=1, padx=20)

Encrypt_text = ttk.LabelFrame(encryptedframe, width=35, height=10)
Encrypt_text.grid(row=3, column=0, pady=(0, 10))

Ciphered_text = Text(Encrypt_text, width=40, height=10)
Ciphered_text.pack()


# Decryption Frame
decryptedframe = ttk.LabelFrame(root, text="Decryption Cell", padding=(10, 10))
decryptedframe.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

label = ttk.Label(decryptedframe, text="Type the message to Decrypt")
label.grid(row=0, column=0, pady=(0, 10), sticky="w")

message_to_decrypt = Text(decryptedframe, width=45, height=10)
message_to_decrypt.grid(row=1, column=0, pady=(0, 10))

decryptedkey_frame = ttk.LabelFrame(decryptedframe, width=400, height=10)
decryptedkey_frame.grid(row=2, column=0, pady=(0, 10), sticky="w")

label = ttk.Label(decryptedkey_frame, text="Enter The Decryption Key", foreground="blue")
label.grid(row=0, column=0)

Decryptedkey = ttk.Entry(decryptedkey_frame, width=32)
Decryptedkey.grid(row=0, column=1, padx=20)

Decrypt_text = ttk.LabelFrame(decryptedframe, width=35, height=10)
Decrypt_text.grid(row=3, column=0, pady=(0, 10))

Deciphered_message = Text(Decrypt_text, width=40, height=10)
Deciphered_message.pack()



# Algorithm Frame
algorithm_frame = ttk.LabelFrame(root, text="Choose Algorithm", padding=(10, 10))
algorithm_frame.grid(row=1, column=0, columnspan=2, pady=10, sticky="nsew")

label = ttk.Label(algorithm_frame, text="Choose Algorithm")
label.grid(row=0, column=0)

ttk.Radiobutton(algorithm_frame, text="OTP", variable=Algorithm, value=0).grid(row=1, column=0)
ttk.Radiobutton(algorithm_frame, text="DES", variable=Algorithm, value=1).grid(row=1, column=1)


def copy():
        pass



def encrypt():


    plain_text = messagebox.get(1.0,END)
    plain_text = plain_text.strip()
    key = Encryptedkey.get()
    Ciphered_text.config(state=NORMAL)
    message_to_decrypt.config(state=NORMAL)
    Ciphered_text.delete(1.0, 'end-1c')
    ciphered = ''

    if Algorithm.get() == 0:
        Ciphered_text.delete(1.0, END)
        ciphered = OTP_encrypt(plain_text,key)
    elif Algorithm.get() == 1:
        data = bytes(plain_text,"utf-8")
        CBC = 0
        try:
            k = des(key, CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=2)
            ciphered =base64.b64encode(k.encrypt(data))
        except Exception as e:
            Ciphered_text.insert(END,e)
            pass

    Ciphered_text.insert(INSERT, ciphered)

def decrypt():
        plain_text = ''
        ciphered = message_to_decrypt.get(1.0, 'end-1c')
        ciphered = ciphered.strip()
        key = Encryptedkey.get()
        Deciphered_message.delete(1.0, 'end-1c')
        if Algorithm.get() == 0:

            plain_text = OTP_decrypt(ciphered,key)
        elif Algorithm.get() == 1:
            try:
                data =base64.b64decode(ciphered)
                CBC = 0
                k = des(key, CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=2)
                plain_text = k.decrypt(data)
            except Exception as e:
                Deciphered_message.insert(END,e)
                pass
        elif Algorithm.get() == 2:
                try:
                    data =base64.b64decode(ciphered)
                    key = bytes(key, 'utf-8')
                    iv = b'\xbe\xa9Q\x18\x9a}\xcf\xd0tH\xc7+~\xe1\xc5\xac'
                   # plain_text = aes.AES(key).decrypt_ctr(data, iv)
                except Exception as e:
                    Deciphered_message.insert(END,e)
                pass

        Deciphered_message.insert(INSERT,plain_text)

encryption_button = Button(encryptedkey_frame, text="Encrypt", command=encrypt, bg='Red', fg='white')
encryption_button.grid(row=2, column=1, padx=0, pady=20, ipadx=10, ipady=5)

decrypt_btn = Button(decryptedkey_frame, text="Decrypt", command=decrypt, bg='Green', fg='white')
decrypt_btn.grid(row=2, column=1, padx=0, pady=20, ipadx=10, ipady=5)


root.mainloop()
