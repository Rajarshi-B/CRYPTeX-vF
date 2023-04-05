import tkinter as tk
import tkinter.messagebox as messagebox
import hashlib
from tkinter import filedialog, Toplevel
import string
import secrets
from base64 import b85encode, b85decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

INFO = '''
# In short the cipher works in the following steps
# 1) First user-provided Key is taken and using PBKDF2 sha3_512 a key is derived lets call this 'hKey'                    
# 2) The hKey is taken and is XORed with the Plain-Text, till its entire length lets call this enc_text_1 or PlainXORhKey 
# 3) Standard AES-256 encryption is performed with a PBKDF2(sha512/256, key) on enc_text_1, => enc_text_2 or AES(enc...)  
# 4) Then enc_text_2 is encoded in base85 format so that almost all characters excluding 'space' is present=>b85(en...)   
# 5) The Random 'Parameters' (AES_IV, (1)hkey and AES_Key) are concatenated with b85(enc_text_2) => b85(enc_text_2)P      
# 6) b(enc_text_2)P is left shifted by n_shift, n_shift is determined by frequency of 'Small letters' in it. => ENC_OUT   
# Summary n_shift(b85(AES256_SHA2_512/256(Plain-XOR-hKey_sha3_512))+Parameters) = ENC_OUT -> Option-1 (Radio Button)      

# IF option 2 Vigenere Wrapper is chosen           
# 7) The ENC_OUT is taken and is Encrypted using a Shift cipher characters being ASCII-33->126 => VigenWrap(ENC_OUT)      
# 8) The purpose of VigenWrap is to obfuscate the AES encrypted output along with parameters.                                        
# 9) Point (8) is useful because Shift Cipher is breakable only when underlying text is 'not'random i.e dictionary words    
# 10) Adding to point (9), if Key for the shift cipher is long enough(~= len(ENC_OUT)) and random => One-Time-Pad ∞       
# 11) Summary VigenWrap(n_shift(b85(AES256_SHA2_512/256(Plain-XOR-hKey_sha3_512))+Parameters)) = OUT_                     
# 12) Binary File mode takes the bytes from a binary/compiled file and performs operations till step(11).                 

# All steps are symmetric and reversible.
# No need to worry as every advancement is over intact-AES-256+PBKDF2-SHA512/256 but STRONG/LONG/Random PASSCODE is a MUST.
# Text boxes get automatically truncated when the text in the input box contains num(chars) >= 30000 to prevent crashing.
# First choose among the radio buttons then proceed.
# Use default file extensions whenever possible .xenc and .bxenc to open encrypted files.
# Opening .bxenc files with some other extensions will result in errors while decrypting.

Signature: 5C9E1F5AFB0DCE4249A349E7D37101F9445617FF25B90AF1627B3EE29C38D8D1 | RajarshiB
'''


### General Vigenere Cipher for ASCII 33-126 to be used over AES to Mask the AES output ###

vigen_start = ord('!')
vigen_end = ord('~')
def encrypt_vigenere(text):
    key = Num_Vigen_box.get("1.0", tk.END).strip()
    cip = []
    start = vigen_start
    end = vigen_end
    length = end - start + 1
    key = str(key) * (int(len(text) / len(key)) + 1)
    key = key[0:len(text)]

    for l, k in zip(text, key):
        key_base = (ord(k) - start) % (end + 1)
        text_base = (ord(l) - start) % (end + 1)
        pos = start + (text_base + key_base) % length
        cip.append(chr(pos))
    return ''.join([l for l in cip])


def decrypt_vigenere(text):
    key = Num_Vigen_box.get("1.0", tk.END).strip()
    cip = []
    start = vigen_start
    end = vigen_end
    length = end - start + 1
    key = str(key) * (int(len(text) / len(key)) + 1)
    key = key[0:len(text)]

    for l, k in zip(text, key):
        key_base = (ord(k)  - start)% (end + 1)
        text_base = (ord(l)  - start)% (end + 1)
        if ((text_base - key_base) >= 0):
            pos = start + (text_base - key_base)
        else:
            pos = end - ((key_base - text_base)%length) + 1
        cip.append(chr(pos))
    return ''.join([l for l in cip])


Num_key_default = '_1415926535897932384626433832795028841971693993751058' \
                  '20974944592307816406286208998628034825342117067982148086' \
                  '51328230664709384460955058223172535940812848111745028410270193' \
                  '852110555964462294895493038196442881097566593344612847564823378678' \
                  '316527120190914564856692346034861045432664821339360726024914127372458' \
                  '70066063155881748815209209628292540917153643678925903600113305305488204665' \
                  '2138414695194151160943305727036575959195309218611738193261179310511854807446237' \
                  '9962749567351885752724891227938183011949129833673362440656643086021394946395224737190' \
                  '7021798609437027705392171762931767523846748184676694051320005681271452635608277857713' \
                  '427577896091736371787214684409012249534301465495853710507922796892589235420199561121290' \
                  '21960864034418159813629774771309960518707211349999998'
# 768 is the length (decimals of pi)

Vigen_key_default = "_V!G3N3Re_DEFAULT_KEY"

AES_Vigen_Box_Msg = "[NOT NEEDED FOR AES]"

Default_Passcode = "[INSERT PASSCODE HERE]"

Input_Content = ''
Output_Content = ''

character_limit = 30000


### Plain text is taken and is XORed with the hash(key) then the resulting text is encrypted using AES256.
### Then the encrypted text is rotated by the number of characters(a-z)
### Code is badly written and unoptimised.


def set_Input_Content(Text):
    global Input_Content
    Input_Content = Text


def set_Output_Content(Text):
    global Output_Content
    Output_Content = Text


# XOR operation with the hashed key
def encrypt1(b_hashed_key, plain_text):
    n = int(var.get())
    l_key = len(b_hashed_key)
    if(n == 4):
        b_plain_text = bytearray(b85decode(plain_text.encode('utf8')))
    else:
        b_plain_text = bytearray(plain_text.encode('utf8'))
    l_plain_text = len(b_plain_text)
    b_xor_text = bytearray(b'')
    for i in range(l_plain_text):
        b_xor_text.append(b_plain_text[i] ^ b_hashed_key[i % l_key])
    return [b_xor_text, b85encode(b_xor_text).decode('utf8')]

# Basic AES CBC encryption with key expansion
def encrypt2standard(plain_key, bytes_from_encrypt1):
    key_ex = keyexpand(plain_key)
    key = key_ex[0]
    key_salt = key_ex[1]
    alphabet = (string.printable)[0:94]
    iv = ''.join(secrets.choice(alphabet) for i in range(16))
    iv = iv.encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(bytes_from_encrypt1, AES.block_size))
    iv = (cipher.iv).decode('utf-8')
    ct = b85encode(ct_bytes).decode('utf-8')
    return [ct, iv, key_salt]


# Performs the decrypt operation by taking in the key and expanding it
def decrypt1standard(enc_text, AES_IV, key_salt, plainkey):
    key_ex = keyexpand(plainkey, key_salt)
    key = key_ex[0]

    cipher = AES.new(key, AES.MODE_CBC, AES_IV.encode('utf-8'))
    cipher_text = b85decode(enc_text)

    dct_bytes = unpad(cipher.decrypt(cipher_text), AES.block_size)

    return dct_bytes


# Reverse of encrypt1
def decrypt2(b_hashed_key, b_xor_text):
    n = int(var.get())
    l_key = len(b_hashed_key)
    l_xor_text = len(b_xor_text)
    b_plain_text = bytearray(b'')
    for i in range(l_xor_text):
        b_plain_text.append(b_xor_text[i] ^ b_hashed_key[i % l_key])
    if(n==4):
        return [b_plain_text, (b85encode(b_plain_text).decode('utf8'))]
    else:
        return [b_plain_text, b_plain_text.decode('utf8')]


# Returns hash(key) with random salt
def hashkey(plain_key, salt=None):
    plain_key_copy = plain_key
    alphabet = (string.printable)[0:94]
    if (salt == None):
        salt = ''.join(secrets.choice(alphabet) for i in range(4))
    else:
        salt = salt

    bytes_hashed_key = hashlib.pbkdf2_hmac('sha3_512', plain_key_copy.encode('utf8'), salt.encode('utf8'),
                                           int(iter_box.get("1.0", tk.END).strip()), 64)
    bytes_hashed_key = bytearray(bytes_hashed_key)
    hashed_key = b85encode(bytes_hashed_key).decode('utf8')


    return [bytes_hashed_key, salt, hashed_key]


# To get the proper key size(256 bits/ 32 bytes) for AES
def keyexpand(plain_key, salt=None):
    plain_key_copy = plain_key
    alphabet = (string.printable)[0:94]
    if (salt == None):
        salt = ''.join(secrets.choice(alphabet) for i in range(4))
    else:
        salt = salt
    hashed_key = hashlib.pbkdf2_hmac('sha512', plain_key_copy.encode('utf8'), salt.encode('utf8'),
                                     int(iter_box.get("1.0", tk.END).strip()), 32)

    return [hashed_key, salt]


def my_range(start, end, step):
    while start <= end:
        yield start
        start += step


def shift_left(enc_text, n):
    enc_text = enc_text[n:] + enc_text[0:n]
    return enc_text


def shift_right(enc_text, n):
    enc_text = enc_text[-n:] + enc_text[0:-n]
    return enc_text


def count_smalls(enc_text):
    count_ = 0
    for i in list(enc_text):
        if ((ord(i) >= 97) & (ord(i) <= 122)):
            count_ = count_ + 1
    return count_


def encrypt_AES_merge_shift(plain_text, key):
    text = plain_text
    hkey = hashkey(key)
    t = encrypt1(hkey[0], text)
    encp = encrypt2standard(key, t[0])  # ct + iv(16) + keysalt(4)
    out_ = encp[0] + encp[1] + encp[2] + hkey[1]
    out_ = shift_left(out_, count_smalls(out_))
    return out_


def decrypt_shift_seperate_AES(enc_text):
    text = enc_text
    text = shift_right(text, count_smalls(text))
    len_text = len(text)
    hsalt = text[len_text - 4:]
    hkey = hashkey(passcode_box.get("1.0", tk.END).strip(), hsalt)
    key_salt = text[(len_text - 8):(len_text - 4)]
    AES_iv = text[(len_text - 24):(len_text - 8)]
    ct = text[0:(len_text - 24)]

    out_ = decrypt1standard(ct, AES_iv, key_salt,
                            passcode_box.get("1.0", tk.END).strip())  # (enc_text,AES_IV ,key_salt , plainkey)
    out_ = decrypt2(hkey[0], out_)
    return out_[1]


def process_encrypt():
    input_box.config(state="normal")
    output_box.config(state="normal")
    n = int(var.get())
    if(n != 4):
        input_text = input_box.get("1.0", tk.END).strip()
        set_Input_Content(input_text)  # keep it global
    else:
        input_text = Input_Content
    passcode_text = passcode_box.get("1.0", tk.END).strip()
    output_box.delete("1.0", tk.END)
    out_ = encrypt_AES_merge_shift(input_text, passcode_text)
    if (n == 1):
        try:
            set_Output_Content(out_) #keep it global
            output_box.insert("1.0", out_)
            log_box.insert("1.0", "|Encrypted! Iter = " + str(int(iter_box.get("1.0", tk.END).strip())) + "|  ")
        except:
            messagebox.showerror("Error", "Error while encrypting!")
            log_box.insert("1.0", "|Error while encrypting|  ")

    elif (n == 3 or n == 4):
        try:
            vigen_out_ = encrypt_vigenere(out_)
            set_Output_Content(vigen_out_)  # keep it global
            if (len(vigen_out_) >= character_limit):
                output_box.insert("1.0", "Trimmed_Contents: " + vigen_out_[:character_limit])
            else:
                output_box.insert("1.0", vigen_out_)

            log_box.insert("1.0", "|Encrypted! Iter = " + str(int(iter_box.get("1.0", tk.END).strip())) + "|  ")
            if (n == 4):
                messagebox.showinfo("CRYPTeX", "Encrypted Binary Data!, SAVE-IT!")
        except:
            if (n == 4):
                messagebox.showerror("Error", "Error while Encrypting@BinaryData!")
                log_box.insert("1.0", "|Error while Encrypting@BinaryData|  ")
            else:
                messagebox.showerror("Error", "Error while Encrypting@VigenWrapper")
                log_box.insert("1.0", "|Error while Encrypting@VigenWrapper|  ")
    MODE_Config()


def process_decrypt():
    input_box.config(state="normal")
    output_box.config(state="normal")
    #input_text = input_box.get("1.0", tk.END).strip()
    input_text = Input_Content.strip()  # keep it global
    #print(input_text)
    output_box.delete("1.0", tk.END)
    n = int(var.get())

    if (n == 1):
        try:
            out_ = decrypt_shift_seperate_AES(input_text)
            set_Output_Content(out_) #keep it global
            #print(out_)
            output_box.insert("1.0", out_)
            log_box.insert("1.0", "|Decrypted!|  ")
        except:
            messagebox.showerror("Error", "Error while decrypting!")
            log_box.insert("1.0", "|Error while decrypting|  ")
    elif (n == 3 or n == 4):
        try:
            vigen_out_ = decrypt_shift_seperate_AES(decrypt_vigenere(input_text))
            set_Output_Content(vigen_out_) #keep it global

            if (len(vigen_out_) >= character_limit):
                output_box.insert("1.0", "Trimmed_Contents: " + vigen_out_[:character_limit])
            else:
                output_box.insert("1.0", vigen_out_)

            log_box.insert("1.0", "|Decrypted! Iter = " + str(int(iter_box.get("1.0", tk.END).strip())) + "|  ")
            if(n==4):
                messagebox.showinfo("CRYPTeX", "Decrypted Binary Data!, SAVE-IT!")
        except:
            if(n==4):
                messagebox.showerror("Error", "Error while decrypting@BinaryData!")
                log_box.insert("1.0", "|Error while decrypting@BinaryData|  ")
            else:
                messagebox.showerror("Error", "Error while decrypting@VigenWrapper")
                log_box.insert("1.0", "|Error while decrypting@VigenWrapper|  ")
    MODE_Config()


def ReverseCODES():
    key = passcode_box.get("1.0", tk.END).strip()
    vigen_key = Num_Vigen_box.get("1.0", tk.END).strip()
    key = key[::-1]
    vigen_key = vigen_key[::-1]
    passcode_box.delete("1.0", tk.END)
    Num_Vigen_box.delete("1.0", tk.END)
    passcode_box.insert("1.0", key)
    Num_Vigen_box.insert("1.0",vigen_key)

def ReverseInput():
    input = input_box.get("1.0", tk.END).strip()
    input = input[::-1]
    set_Input_Content(input)
    input_box.delete("1.0", tk.END)
    input_box.insert("1.0", input)

def ReverseOutput():
    output = output_box.get("1.0", tk.END).strip()
    output = output[::-1]
    set_Output_Content(output)
    output_box.delete("1.0", tk.END)
    output_box.insert("1.0", output)



def copy_output():
    input_box.config(state="normal")
    output_box.config(state="normal")
    #output_text = output_box.get("1.0", tk.END).strip()
    output_text = Output_Content.strip() #keep it global
    if output_text:
        root.clipboard_clear()
        if (len(output_text) >= character_limit):
            messagebox.showerror("CRYPTeX", "Output too large to copy!")
        else:
            root.clipboard_append(output_text)
            messagebox.showinfo("CRYPTeX", "Output copied to clipboard!")
            log_box.insert("1.0", "|Output Copied to Clipboard|  ")

    else:
        messagebox.showwarning("CRYPTeX", "Output box is empty!")
    MODE_Config()


def send_to_input():
    input_box.config(state="normal")
    output_box.config(state="normal")
    #output_text = output_box.get("1.0", tk.END).strip()
    output_text = Output_Content.strip()  # keep it global
    if output_text:
        set_Input_Content(output_text) #keep it global
        input_box.delete("1.0", tk.END)
        if (len(output_text) >= character_limit):
            input_box.insert("1.0", "Trimmed_Contents: " + output_text[:character_limit])
        else:
            input_box.insert("1.0", output_text)
        # messagebox.showinfo("CRYPTeX", "Sent to input!")
        log_box.insert("1.0", "|Output Copied to Input Box|  ")
    else:
        messagebox.showwarning("CRYPTeX", "Output box is empty!")
    MODE_Config()


def Open_File():
    input_box.config(state="normal")
    output_box.config(state="normal")
    n = int(var.get())
    try:
        if(n==4):
            input_file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*"), ("CRYPTeX Files", "*.bxenc")])

            if input_file_path:
                extension = input_file_path.split('.')[-1]
                if (extension == 'bxenc'):
                    f = open(input_file_path, "rt")
                    contents = f.read()


                else:
                    f = open(input_file_path, "rb")
                    contents = f.read()
                    contents = b85encode(contents).decode("utf8")





                #print(type(contents))
                open_label.config(text=input_file_path)
                #print(open_label)
                input_box.delete("1.0", tk.END)
                set_Input_Content(contents) # Keep it global
                if (len(contents) >= character_limit):
                    #messagebox.showinfo("CRYPTeX", "Hide(TextBoxes) to save Bandwidth")
                    #hide_widget()
                    input_box.insert("1.0", "Trimmed_Contents: "+contents[:character_limit])
                else:
                    input_box.insert("1.0", contents)
                messagebox.showinfo("CRYPTeX", "Binary Data Loaded Successfully!")
                log_box.insert("1.0", "|Binary Data Loaded Successfully!|  ")
                log_box.insert("1.0", "|Binary File Opened from " + input_file_path + "|  ")
            f.close()
        else:
            input_file_path = filedialog.askopenfilename(filetypes=[("All Text Data", ["*.xenc","*.txt"]),
                                                                    ("All Files", "*.*"),
                                                                    ("CRYPTeX Files", "*.xenc"),
                                                                    ("Text Files", "*.txt")])
            f = open(input_file_path, "rt")
            contents = f.read()

            if input_file_path:
                open_label.config(text=input_file_path)
                input_box.delete("1.0", tk.END)
                set_Input_Content(contents)  # Keep it global
                if (len(contents) >= character_limit):
                    messagebox.showerror("CRYPTeX", "Use File Encrypt to open Binary Files./"
                                                    "Hide(TextBoxes) to save Bandwidth.")
                    #hide_widget()
                    input_box.insert("1.0", "Trimmed_Contents: "+contents[:character_limit])
                else:
                    input_box.insert("1.0", contents)
                messagebox.showinfo("CRYPTeX", "Data Loaded Successfully!")
                log_box.insert("1.0", "|Data Loaded Successfully!|  ")
                log_box.insert("1.0", "|File Opened from " + input_file_path + "|  ")
            f.close()
    except:
        log_box.insert("1.0", "|No File Chosen| / |Error Opening File|  ")
    MODE_Config()



def save_output():
    try:
        n = int(var.get())
        if(n == 4):
            file_ext = (open_label.cget("text")).split('.')
            filename = (file_ext[0].split('/'))[-1]
            extension = file_ext[-1]
            #print(file_ext)
            #print(extension)
            #print(extension == 'bxenc')
            if(extension == 'bxenc'):
                output_file_path = filedialog.asksaveasfilename(initialfile=filename+'.[Actual-Extension]',
                                                                defaultextension="*.*",
                                                                filetypes=[("All Files", "*.*"),
                                                                           ("Executables", "*.exe"),
                                                                           ("PNG Image", "*.png"),
                                                                           ("JPEG Image", "*.jpg"),
                                                                            ("Mp4 File", "*.mp4"),
                                                                           ("Binary File", "*.bin")])
                f = open(output_file_path, 'wb')

                #output_text = output_box.get("1.0", tk.END).strip()
                output_text = Output_Content.strip() #keep it global
                if output_text:
                    b_output_text = b85decode(output_text.encode('utf8'))
                    #print(type(b_output_text))
                    f.write(b_output_text)
                    messagebox.showinfo("CRYPTeX", "Decrypted Binary File Saved")
                    log_box.insert("1.0", "|Decrypted Binary File Saved to " + output_file_path + "|  ")
                else:
                    messagebox.showwarning("CRYPTeX", "Output box is empty!")
                    log_box.insert("1.0", "|Empty Box Warning!|  ")
                f.close()
            else:
                output_file_path = filedialog.asksaveasfilename(initialfile=filename+'.'+extension+'.bxenc',
                                                                defaultextension="*.bxenc",
                                                                filetypes=[('CRYPTeX Binary Files', '*.bxenc')])
                f = open(output_file_path, 'wt')

                #output_text = output_box.get("1.0", tk.END).strip()
                output_text = Output_Content.strip() #keep it global
                if output_text:
                    print(output_text, file=f)
                    messagebox.showinfo("CRYPTeX", "Encrypted Binary File Saved")
                    log_box.insert("1.0", "|Binary File Saved to " + output_file_path + "|  ")
                else:
                    messagebox.showwarning("CRYPTeX", "Output box is empty!")
                    log_box.insert("1.0", "|Empty Box Warning!|  ")
                f.close()

        else:
            output_file_path = filedialog.asksaveasfilename(initialfile='[filename].xenc',
                                                            defaultextension=".xenc",
                                                            filetypes=[("All Files", "*.*"), ("CRYPTeX Files", "*.xenc"),
                                                                       ("Text Files", "*.txt")])
            f = open(output_file_path, 'wt')

            #output_text = output_box.get("1.0", tk.END).strip()
            output_text = Output_Content.strip()  # keep it global
            if output_text:
                print(output_text, file=f)
                messagebox.showinfo("CRYPTeX", "File Saved")
                log_box.insert("1.0", "|File Saved to " + output_file_path + "|  ")
            else:
                messagebox.showwarning("CRYPTeX", "Output box is empty!")
                log_box.insert("1.0", "|Empty Box Warning!|  ")
            f.close()
    except:
        log_box.insert("1.0", "|Error Saving File|  ")

#5C9E1F5AFB0DCE4249A349E7D37101F9445617FF25B90AF1627B3EE29C38D8D1
root = tk.Tk()
root.title("CRYPTeX 🥷 [5C9E1F5AFB0DCE4249A349E7D37101F9445617FF25B90AF1627B3EE29C38D8D1]")
root.iconbitmap("OWL.ico")
root.configure(background='#565a73') 
root.attributes('-alpha', 1)
root.resizable(width=False, height=False)

def info_window():
    new = Toplevel(root)
    new.geometry("1100x500")
    new.resizable(width=False, height=False)
    new.title("CRYPTeX INFO")
    info_label = tk.Label(new, text=INFO, font=('Helvetica 12 bold'), background='#fac0d5')
    info_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

def steps_window():
    def Generate_chars():
        choose_from = characs.get("1.0",tk.END).strip()
        Random_chars = ''.join(secrets.choice(choose_from) for i in range(int(num_chars.get("1.0",tk.END))))
        rand_text.delete("1.0", tk.END)
        rand_text.insert("1.0", Random_chars)
    def Copy_Rand():
        root.clipboard_clear()
        root.clipboard_append(rand_text.get("1.0", tk.END))
        messagebox.showinfo("CRYPTeX", "Generated Numbers Copied")

    new = Toplevel(root)
    new.geometry("350x200")
    new.resizable(width=False, height=False)
    new.title("Random Key Generator")
    new.iconbitmap("OWL.ico")
    rand_text = tk.Text(new, height=5, width=40, background='#fac0d5')
    rand_text.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
    num_chars = tk.Text(new, font=('Helvetica 12 bold'),height=1, width=10, background='#fac0d5')
    num_chars.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

    num_chars_l = tk.Label(new, text="Num(chars)", background='#fac0d5')
    num_chars_l.grid(row=1, column=0, padx=5, pady=5)

    characs = tk.Text(new, height=4, width=30, background='#fac0d5')
    characs.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
    gen_button = tk.Button(new, text="Generate", command=Generate_chars, width=10, background='#03fcc2')
    gen_button.grid(row=2, column=0, padx=10, pady=5, sticky=tk.E)

    cpy_button = tk.Button(new, text="Copy", command=Copy_Rand, width=5, background='#03fcc2')
    cpy_button.grid(row=1, column=0, padx=10, pady=5, sticky=tk.E)

    alphabets = (string.printable)[0:94]
    characs.insert("1.0",alphabets)
    num_chars.insert("1.0", 32)
    rand_text.insert("1.0", "[WILL BE GENERATED HERE]")


def show_widget():
    # output_box.grid(row=2, column=1, rowspan=3, padx=10, pady=5)
    # input_box.grid(row=3, column=0, padx=10, pady=5)
    sh.configure(text="Hide", command=hide_widget)
    root.attributes('-alpha', 1)
    log_box.insert("1.0", "|Show Button| ")


def hide_widget():
    # output_box.grid_forget()
    # input_box.grid_forget()
    sh.configure(text="Show", command=show_widget)
    root.attributes('-alpha', 0.1)
    log_box.insert("1.0", "|Hide Button| ")


def MODE_Config():
    n = int(var.get())
    Num_Vigen_key = Num_Vigen_box.get("1.0", tk.END).strip()

    if (n == 1):
        input_box.config(state="normal")
        output_box.config(state="normal")
        Num_Vigen_box.config(state="normal")

        if (input_box.get("1.0", tk.END).strip() == "[OPEN FILE]"):
            input_box.delete("1.0", tk.END)
            input_box.insert("1.0", Input_Content)

        if ((Num_Vigen_key == '') or  (Num_Vigen_key == Vigen_key_default+Num_key_default)):
            Num_Vigen_box.delete("1.0", tk.END)
            Num_Vigen_box.insert("1.0", AES_Vigen_Box_Msg)
        log_box.insert("1.0", "|Mode = AES-256|PBKDF2(SHA-512)++|  ")

        Num_Vigen_box.config(state="disabled")


    elif (n == 3):
        input_box.config(state="normal")
        output_box.config(state="normal")
        Num_Vigen_box.config(state="normal")
        if(input_box.get("1.0", tk.END).strip()=="[OPEN FILE]"):
            input_box.delete("1.0", tk.END)
            input_box.insert("1.0", Input_Content)

        if ((Num_Vigen_key == '') or (Num_Vigen_key == Num_key_default) or (Num_Vigen_key == AES_Vigen_Box_Msg)):
            Num_Vigen_box.delete("1.0", tk.END)
            Num_Vigen_box.insert("1.0", Vigen_key_default+Num_key_default)
        log_box.insert("1.0", "|Mode = VigenWrap(AES-256|PBKDF2(SHA-512)++)|  ")


    elif (n == 4):
        input_box.config(state="normal")
        output_box.config(state="normal")
        Num_Vigen_box.config(state="normal")
        set_Input_Content(input_box.get("1.0", tk.END).strip())
        input_box.delete("1.0",tk.END)
        input_box.insert("1.0", "[OPEN FILE]")
        if ((Num_Vigen_key == '') or (Num_Vigen_key == Num_key_default) or (Num_Vigen_key == AES_Vigen_Box_Msg)):
            Num_Vigen_box.delete("1.0", tk.END)
            Num_Vigen_box.insert("1.0", Vigen_key_default+Num_key_default)
        log_box.insert("1.0", "|Mode = Binary_File_VigenWrap(AES-256|PBKDF2(SHA-512)++)|  ")
        input_box.config(state="disabled")
        output_box.config(state="disabled")
        Num_Vigen_box.config(state="normal")


open_button = tk.Button(root, text="OpenFile📂", command=Open_File, width=10, background='#03fcc2')
open_button.grid(row=0, column=0, padx=10, pady=5)

info_button = tk.Button(root, text="INFO",font=("Arial", 6, "bold"), command=info_window, width=4, background='#b52828')
info_button.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

open_label = tk.Label(root, text="[Input Path]", font=("Arial", 8, "italic"))
open_label.grid(row=1, column=0, padx=10, pady=5)

input_label = tk.Label(root, text="Input", font=("Arial", 12, "bold"))
input_label.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
input_label.bind("<Button-1>", lambda e:ReverseInput())

input_box = tk.Text(root, height=10, width=40)
input_box.grid(row=3, column=0, padx=10, pady=5)

passcode_label = tk.Label(root, text="Passcode🗝", font=("Arial", 12, "bold"))
passcode_label.grid(row=4, column=0, padx=10, pady=5, sticky=tk.W)
passcode_label.bind("<Button-1>", lambda e:ReverseCODES())

passcode_box = tk.Text(root, height=3, width=40, background='#fac0d5')
passcode_box.grid(row=5, column=0, padx=10, pady=5)
passcode_box.insert("1.0", Default_Passcode)

Num_Vigen_box = tk.Text(root, height=2, width=25, background='#fcba03')
Num_Vigen_box.grid(row=4, column=0, padx=10, pady=5, sticky=tk.E)
Num_Vigen_box.insert("1.0", AES_Vigen_Box_Msg)

encrypt_button = tk.Button(root, text="Encrypt🔒", command=process_encrypt, width=10, background='#e8937d')
encrypt_button.grid(row=6, column=0, padx=10, pady=5, sticky=tk.E)

decrypt_button = tk.Button(root, text="Decrypt🔓", command=process_decrypt, width=10, background='#03fcc2')
decrypt_button.grid(row=6, column=0, padx=10, pady=5, sticky=tk.W)

output_label = tk.Label(root, text="Output", font=("Arial", 12, "bold"))
output_label.grid(row=2, column=1, padx=10, pady=5, sticky=tk.E)
output_label.bind("<Button-1>", lambda e:ReverseOutput())

output_box = tk.Text(root, height=10, width=40)
output_box.grid(row=2, column=1, rowspan=3, padx=10, pady=5)

copy_button = tk.Button(root, text="Copy->Clipboard", command=copy_output, width=15, background='#03fcc2')
copy_button.grid(row=4, column=1, padx=10, pady=5, sticky=tk.E)

send_output_input = tk.Button(root, text="Send Output->Input", command=send_to_input, width=15, background='#03fcc2')
send_output_input.grid(row=4, column=1, padx=10, pady=5, sticky=tk.W)

save_button = tk.Button(root, text="Save Output", command=save_output, width=10, background='#476cc4')
save_button.grid(row=6, column=1, padx=10, pady=5, sticky=tk.E)

gen_button = tk.Button(root, text="GEN_RANDOM",font=("Arial", 8, "bold"), command=steps_window, width=10, background='#fac0d5')
gen_button.grid(row=0, column=1, padx=10, pady=5, sticky=tk.E)

var = tk.IntVar()

R1 = tk.Radiobutton(root, text="AES-256|PBKDF2(SHA-512)++", variable=var, value=1,
                    command=MODE_Config)
R1.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)


R3 = tk.Radiobutton(root, text="VigenWrap(AES-256|PBKDF2(SHA-512)++)", variable=var, value=3,
                    command=MODE_Config)
R3.grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)

R4 = tk.Radiobutton(root, text="EnDyc(Binary File)-Vigen(AES-256)", variable=var, value=4,
                    command=MODE_Config)
R4.grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)




log_box = tk.Text(root, height=3, width=40, background='#e1e7f0')
log_box.grid(row=5, column=1, padx=10, pady=5)

iter_box = tk.Text(root, height=1, width=10)
iter_box.grid(row=6, column=1, padx=10, pady=5, sticky=tk.W)
iter_box.insert("1.0", "1000000")


iter_label = tk.Label(root, text="<= Iterations(PBKDF2)", font=("Arial", 8, "bold"))
iter_label.grid(row=6, column=1, padx=10, pady=5)

var.set(3)
MODE_Config()
root.mainloop()

