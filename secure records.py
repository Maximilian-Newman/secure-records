import hashlib
import random
import os
from datetime import datetime

ENCRYPTION_DEPTH = 200
ROT_SIZE = 100
SEPARATION = b"\n\x01\x02.drec file separator\x02\x01\n"
ENTRY_SEP = b"\n\x01\x02.drec new entry\x02\x01\n"
MID_ENTRY_SEP = b"\n\x01\x02.drec entry body\x02\x01\n"
openFile = []
openName = ""
openKey = ""







# Prime number generation code:

# Pre generated primes
first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67,
                     71, 73, 79, 83, 89, 97, 101, 103,
                     107, 109, 113, 127, 131, 137, 139,
                     149, 151, 157, 163, 167, 173, 179,
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]
 
 
def nBitRandom(n):
    return random.randrange(2**(n-1)+1, 2**n - 1)
 
 
def getLowLevelPrime(n):
    '''Generate a prime candidate divisible 
    by first primes'''
    while True:
        # Obtain a random number
        pc = nBitRandom(n)
 
        # Test divisibility by pre-generated
        # primes
        for divisor in first_primes_list:
            if pc % divisor == 0 and divisor**2 <= pc:
                break
        else:
            return pc
 
 
def isMillerRabinPassed(mrc):
    '''Run 20 iterations of Rabin Miller Primality test'''
    maxDivisionsByTwo = 0
    ec = mrc-1
    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1
    assert(2**maxDivisionsByTwo * ec == mrc-1)
 
    def trialComposite(round_tester):
        if pow(round_tester, ec, mrc) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2**i * ec, mrc) == mrc-1:
                return False
        return True
 
    # Set number of trials here
    numberOfRabinTrials = 20
    for i in range(numberOfRabinTrials):
        round_tester = random.randrange(2, mrc)
        if trialComposite(round_tester):
            return False
    return True
 
 
def random_prime(n):
    while True:
        prime_candidate = getLowLevelPrime(n)
        if not isMillerRabinPassed(prime_candidate):
            continue
        else:
            return prime_candidate








# Digital Signature  code:

def hashFunc(message):
    return hashlib.sha256(message.encode()).hexdigest()

def coprime(a, b):
    while b != 0:
        a, b = b, a % b
    return a
    
    
def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

#Euclid's extended algorithm for finding the multiplicative inverse of two numbers    
def modinv(a, m):
	g, x, y = extended_gcd(a, m)
	if g != 1:
		raise Exception('Modular inverse does not exist')
	return x % m    




def RSA_generate_keypair(p, q):

    n = p * q

    #Phi is the totient of n
    phi = (p-1) * (q-1)

    #Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    #Use Euclid's Algorithm to verify that e and phi(n) are comprime
    
    g = coprime(e, phi)
  
    while g != 1:
        e = random.randrange(1, phi)
        g = coprime(e, phi)

    #Use Extended Euclid's Algorithm to generate the private key
    d = modinv(e, phi)

    #Return public and private keypair
    #Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))


def RSA_encrypt(privatek, plaintext):
    #Unpack the key into it's components
    key, n = privatek

    #Convert each letter in the plaintext to numbers based on the character using a^b mod m
            
    #numberRepr = [ord(char) for char in plaintext]\
    numberRepr = int.from_bytes(plaintext.encode(), "big")
    cipher = pow(numberRepr,key,n)
    
    #Return the array of bytes
    return cipher


def RSA_decrypt(publick, ciphertext):
    #Unpack the key into its components
    key, n = publick
       
    #Generate the plaintext based on the ciphertext and key using a^b mod m
    numberRepr = pow(ciphertext, key, n)
    plain = int.to_bytes(numberRepr, 64, "big")
    
    #Return the array of bytes as a string
    return plain.decode()

def generate_signature(message, privateKey):
    hashed = hashFunc(message)
    return format(RSA_encrypt(privateKey, hashed), "X")

def verify_signature(signature, publicKey, message):
    signature = int(signature, 16)
    receivedHashed = RSA_decrypt(publicKey, signature)
    ourHashed = hashFunc(message)
    if receivedHashed == ourHashed:
        return True
    return False
    
   
    

publicKey = [0, 0]
privateKey = [0, 0]
try:
    file = open("secure records RSA key.txt", "r")
    keys = file.read().split("\n")
    privateKey = (int(keys[1]), int(keys[3]))
    publicKey = (int(keys[2]), int(keys[3]))
    file.close()
except:
    if input("You do not have any key for digital signing. Do you want to generate a new one? (enter 'Y' for yes) ") == "Y":
        print("Generating keys, please wait...")
        p = random_prime(2048)
        q = random_prime(2048)
        publicKey, privateKey = RSA_generate_keypair(p, q)
        file = open("secure records RSA key.txt", "w")
        file.write("This file contains you RSA private key. NEVER share it with anyone, others could use it to forge your digital signature.\n")
        file.write(str(privateKey[0]) + "\n" + str(publicKey[0]) + "\n" + str(privateKey[1]))
        file.close()
        print("Done")












print("Testing your RSA keys")
signature = generate_signature("test", privateKey)
if verify_signature(signature, publicKey, "test"):
    print("Success")
else:
    print("Failed")
    print("Your private and public keys do not match. You will not be able to digitally sign your new entries")













def encrypt_byte(byte, key): #encrypt a single byte
    byte += key
    while byte > 255:
        byte = byte - 256
    while byte < 0:
        byte += 256
    return byte

def decrypt_byte(byte, key):
    byte -= key     # shift left instead of right
    while byte > 255:
        byte = byte - 256
    while byte < 0:
        byte += 256
    return byte

def encrypt_bytes(bytes_list, keyString):
    num = int(hashlib.sha256(keyString.encode()).hexdigest(), 16)
    key1 = []
    key2 = []
    key3 = []
    for i in range(0, ENCRYPTION_DEPTH):
        key1.append(num % (i+5))
        key2.append(num % (2*i+4))
        key3.append(num % (3*i+1))
        
    output = []
    for byte in bytes_list:
        for i in range(ENCRYPTION_DEPTH-2, -1, -1):
            key1[i] += key1[i+1]
            key2[i] += key2[i+1]
            key3[i] += key3[i+1]
            key1[i] = key1[i] % ROT_SIZE
            key2[i] = key2[i] % ROT_SIZE
            key3[i] = key3[i] % ROT_SIZE
        
        byte = encrypt_byte(byte, key1[0] * key2[0] + key3[0])
        output.append(byte)
    return bytes(output)




def decrypt_bytes(bytes_list, keyString):
    num = int(hashlib.sha256(keyString.encode()).hexdigest(), 16)
    key1 = []
    key2 = []
    key3 = []
    for i in range(0, ENCRYPTION_DEPTH):
        key1.append(num % (i+5))
        key2.append(num % (2*i+4))
        key3.append(num % (3*i+1))
        
    output = []
    for byte in bytes_list:
        for i in range(ENCRYPTION_DEPTH-2, -1, -1):
            key1[i] += key1[i+1]
            key2[i] += key2[i+1]
            key3[i] += key3[i+1]
            key1[i] = key1[i] % ROT_SIZE
            key2[i] = key2[i] % ROT_SIZE
            key3[i] = key3[i] % ROT_SIZE
        
        byte = decrypt_byte(byte, key1[0] * key2[0] + key3[0])
        output.append(byte)
    return bytes(output)



def verification_string(password):
    return hashlib.sha256((password + "qwerty").encode()).hexdigest()

def open_file(name, password):
    global openName
    global openFile
    global openKey
    
    try:
        file = open(name, "rb")
    except:
        print("ERROR: file not found")
        return

    data = decrypt_bytes(file.read(), password)
    file.close()

    if SEPARATION in data:
        data = data.split(SEPARATION)
        if data[0] == verification_string(password).encode():
            if b"\n" in data[1]:
                data[1] = data[1].split(b"\n")
            else:
                data[1] = [data[1]]
            
            if ENTRY_SEP in data[2]:
                data[2] = data[2].split(ENTRY_SEP)
            else:
                data[2] = [data[2]]

            if data[2] == [b""]:
                data[2] = []
            if data[1] == [b""]:
                data[1] = []
            
            for i in range(0, len(data[2])):
                data[2][i] = data[2][i].split(MID_ENTRY_SEP)
                            
            openName = name
            openFile = data
            openKey = password
            print("File successfully opened")
            return

    print("ERROR: Incorrect password")


def save_file(name, password, data):
    verification = verification_string(password)
    fileContent = verification.encode() + SEPARATION
    
    for title in data[1]:
        fileContent += title + b"\n"
    if data[1] != []:
        fileContent = fileContent[:-1]
    
    fileContent += SEPARATION
    for entry in data[2]:
        fileContent += entry[0] + MID_ENTRY_SEP + entry[1] + MID_ENTRY_SEP + entry[2] + ENTRY_SEP
    if len(data[2]) > 0:
        fileContent = fileContent[:-len(ENTRY_SEP)]
    
    file = open(name, "wb")
    file.write(encrypt_bytes(fileContent, password))
    file.close()
    
    print()
    print("File written successfully.")
    print()


def create_new_file():
    print("\n\n\n\n\nCreating new file\n\n")
    name = input("Enter a name for the new file: ") + ".drec"
    print()

    try:
        open(name, "r")
        print("This file name is already used. Try using a different one.")
        print()
        return
    except:
        pass
    
    password = input("Create a password. It will be required to access the file: ")
    for i in range(50):
        print()

    save_file(name, password, ["", [], []])
    open_file(name, password)


while True:
    if openName == "":
        print()
        print()
        print("1. Create new file")
        print("2. Open existing file")
        option = input("Enter your choice: ")
        if "1" in option:
            create_new_file()
        elif "2" in option:
            name = input("Enter file name: ")
            password = input("Enter password: ")
            
            for i in range(50):
                print()
            print("Decrypting your file...")
            print("This may take a while")
            print()
            open_file(name, password)
            print()
            print()
            print()

    else:
        print("Open File: " + openName)
        print()
        print("1. View table of contents")
        print("2. Read an entry")
        print("3. Add new entry")
        print("4. Dump full file")
        print("5. Export LaTeX")
        print("6. Delete an entry")
        print("7. Rename an entry")
        print("8. Close file")
        option = input("Enter your choice: ")
        print()
        print()
        if "1" in option:
            print("Table of Contents:")
            print()
            for title in openFile[1]:
                print(title.decode())
        elif "2" in option:
            name = input("Enter the name of the entry you want to access: ")
            for entry in openFile[2]:
                if entry[0].decode().upper() == name.upper():
                    print()
                    print()
                    print()
                    print("Entry: " + entry[0].decode())
                    print()
                    print(entry[1].decode())
                    print()
                    print("End of entry")
                    if verify_signature(entry[2].decode(), publicKey, entry[1].decode()):
                        print("Digital Signature Verified")
                    else:
                        print("Digital Signature Not Verified")
                    
        elif "3" in option:
            name = ""
            while name == "" or name in openFile[1]:
                name = input("Enter a name for your entry: ")
            print()
            print("Enter text here. When you are done, press enter 3 times.")
            print()
            entry = ""
            while not entry.endswith("\n\n\n"):
                entry += input() + "\n"
            entry = entry[:-3]
            print("Here is what you wrote:")
            print()
            print(entry)
            print()
            print()
            print()
            if input("Are you sure you want to keep this? (Enter 'Y' for yes): ") == "Y":
                signature = "Not Signed"
                if privateKey[0] != 0:
                    signature = generate_signature(entry, privateKey).encode()
                openFile[1].append(name.encode())
                openFile[2].append([name.encode(), entry.encode(), signature])
                save_file(openName, openKey, openFile)
                print("Entry Saved")
            else:
                print("Operation Cancelled")

        elif "4" in option:
            output = ""
            for entry in openFile[2]:
                output += "\n\n\n\n\n" + entry[0].decode() + "\n\n"
                if "[R]" in entry[0].decode():
                    output += "This entry has been redacted from the published version of this document. Please see the original .drec file if you want to read it.\n\n"
                    for char in entry[1].decode():
                        if char in "\n\t,;.!?'-@()[] ":
                            output += char
                        else:
                            output += "X"
                else:
                    output += entry[1].decode()
                output += "\n\n\nDigital Signature:\n" + entry[2].decode()
            print(output)

        elif "5" in option:
            try:
                os.mkdir(os.path.dirname(__file__) + "/LaTeX output")
            except: pass
            file = open("LaTeX output/" + openName + ".tex", "wb")
            file.write(b"""\documentclass[10pt, a5paper]{report}
\usepackage{setspace}
\usepackage[bottom=1.5cm, right=2.5cm, left=2.5cm, top=1.5cm]{geometry}
\usepackage{afterpage}
\\title{Title}
\\author{Author}
\\date{""")
            file.write(datetime.now().strftime("%B %d, %Y").encode())
            file.write(b"""}
\\begin{document}
\\afterpage{\\null\\thispagestyle{empty}\\newpage}
\\maketitle





\\newpage
\\section*{Technical Notes}
This document was automatically created by MaxCloud Secure Records.

Digital signatures were generated by RSA encrypting the SHA-256 hash of the message body.
The RSA public key that can be used for verification is written below in hexadecimal form.
When possible, you should confirm that the key is accurate by comparing it with another source.

e =

\\begin{tiny}
\\texttt{\\setstretch{1.0}""")
            for i in range(0, len(format(publicKey[0], "X")), 2):
                    file.write(format(publicKey[0], "X").encode()[i:i+2] + b" ")
            file.write(b"""}\\par
\\end{tiny}

n =

\\begin{tiny}
\\texttt{\\setstretch{1.0}""")
            for i in range(0, len(format(publicKey[1], "X")), 2):
                    file.write(format(publicKey[1], "X").encode()[i:i+2] + b" ")
            
            file.write(b"""}\\par
\\end{tiny}

A simple way of verifying signatures is by using the original .drec file if you have access to it.
If you are verifying from this document, note that LaTeX encoding and hidden characters may result in false negatives.

Some entries may have been redacted in this copy.
Redacted entries are marked by an [R], and can only be viewed in the original .drec file.
Their punctuation and digital signatures match the original content for verification purposes.

\\newpage
\\tableofcontents
""")
            for entry in openFile[2]:
                file.write(b"\n\\newpage\n\\section{" + entry[0] + b"}\n")
                if "[R]" in entry[0].decode():
                    file.write(b"\\begin{quote}\n\\textit{\\textbf{Note:} This entry has been redacted from the published version of this document. Please see the original .drec file if you want to read it.}\n\\end{quote}\n")
                    for char in entry[1].decode():
                        if char in "\n\t,;.!?'-@()[] ":
                            if char == "\n":
                                file.write(b"\\\\")
                            file.write(char.encode())
                        else:
                            file.write(b"x")
                
                else:
                    for char in entry[1].decode():
                        if char == "\n":
                            file.write(b"\\\\")
                        if char in "%\\^":
                            file.write(b"\\")
                        if char == b"\\":
                            file.write("\textbackslash")
                        else:
                            file.write(char.encode())
                    
                file.write(b"\n\\vspace*{\\fill}\n\\subsubsection*{Signature:}\n\\begin{tiny}\n\\texttt{\\setstretch{1.0}")
                for i in range(0, len(entry[2]), 2):
                    file.write(entry[2][i:i+2] + b" ")
                file.write(b"}\\par\n\\end{tiny}\n\n")
            
            file.write(b"\n\\end{document}")
            file.close()

        elif "6" in option:
            name = input("Enter the name of the entry you want to remove: ").encode()
            if name in openFile[1]:
                openFile[1].remove(name)
            for entry in openFile[2]:
                if entry[0] == name:
                    openFile[2].remove(entry)
                    print("Entry found.")
                    print("It will be properly removed when you close the file or when you add a new entry.")

        elif "7" in option:
            oldName = input("Enter the current name of the entry you want to rename: ").encode()
            newName = input("Enter the new name: ").encode()
            for i in range(0, len(openFile[1])):
                if openFile[1][i] == oldName:
                    openFile[1][i] = newName
                    print("Index modified")
                    break
            
            for i in range(0, len(openFile[2])):
                if openFile[2][i][0] == oldName:
                    openFile[2][i][0] = newName
                    print("Entry modified")
                    print("Changes will be applied when you close the file or when you add a new entry.")


        
        elif "8" in option:
            print()
            print("Saving changes, please wait")
            save_file(openName, openKey, openFile)
            openFile = []
            openName = ""
            openKey = ""
            for i in range(50):
                print()
            print("File Closed")
            
        print()
        print()
        print()

    
