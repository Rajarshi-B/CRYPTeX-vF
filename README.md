# CRYPTeX-vF
A Cryptography GUI App made as a pet project (for fun) using Python standard libraries. To be used to encrypt text and small binary files. Uses standard AES-256-PBKDF2_SHA2 with random salts and iv. On top of which a Shift Cipher is used to completely obfuscate the AES-Output and can even be converted to a One-Time-Pad if the shift cipher's key is random and length is sufficiently long. Shift Cipher wrapper is used on top because the output of AES is pseudorandom and unpredictable for random salts and iv, frequency analysis using language structure will fail.
>Question: Why use a cipher on top of AES-256? If slowing down brute force is the aim then why not encrypt the same data multiple times?

>Answer: That can be done, but the memory requirements will increase Len(AES + IV1 + Salt2) > Len(AES(AES + IV1 + Salt) + IV2 + Salt2). Slowing down can also be done if each character of the pseudorandom output is shifted, the length remains exactly the same in that case. It also keeps the door open for arbitrarily long passwords and One-Time-Pads with random keys(obviously safely protected) which if implemented correctly will make it impossible to decrypt. (Caution: Nothing is truly random and nothing can be perfectly guarded as humans are flawed.)

![alt text](https://github.com/Rajarshi-B/CRYPTeX-vF/blob/fe3a4dd81e30e9f924b4d87b013a6dfbe7e4fa8b/CRYPTeX-vF.png)

>Code is badly written :P

>I am not an expert in cryptography, nor a professional programmer, use at your own risk, if you are going to use it at all :P

>Contributions to the code are always welcome!


 In short, the cipher works in the following steps
    
    1) First user-provided Key is taken and using PBKDF2 sha3_512 a key is derived let's call this 'hKey'.
    
    2) The hKey is taken and is XORed with the Plain-Text, till its entire length let's call this enc_text_1 or PlainXORhKey.
    
    3) Standard AES-256 encryption is performed with a PBKDF2(sha512/256, key) on enc_text_1, => enc_text_2 or AES(enc...)
    
    4) Then enc_text_2 is encoded in base85 format so that almost all characters excluding 'space' is present=>b85(en...).
    
    5) The Random 'Parameters' (AES_IV, (1)hkey and AES_Key) are concatenated with b85(enc_text_2) => b85(enc_text_2)P.
    
    6) b85(enc_text_2)P is left shifted by n_shift, n_shift is determined by the frequency of 'Small letters' in it. => ENC_OUT.
 
    Summary:n_shift(b85(AES256_SHA2_512/256(Plain-XOR-hKey_sha3_512))+Parameters) = ENC_OUT -> Option-1 (Radio Button)

 IF option 2 Vigenere Wrapper is chosen  
 
    7) The ENC_OUT is taken and is Encrypted using a Shift cipher characters being ASCII-33->126 => VigenWrap(ENC_OUT)  
    
    8) The purpose of VigenWrap is to obfuscate the AES encrypted output along with parameters.               
    
    9) Point (8) is useful because Shift Cipher is breakable only when underlying text is 'not random i.e dictionary words.
    
    10) Adding to point (9), if the Key for the shift cipher is long enough(~= len(ENC_OUT)) and random => One-Time-Pad ∞      
 
    Summary:VigenWrap(n_shift(b85(AES256_SHA2_512/256(Plain-XOR-hKey_sha3_512))+Parameters)) = Vigen_ENC_OUT_ -> Option-2(Radio Button)
 
 Binary File mode takes the bytes from a binary file, encodes the bytes in base85 and performs operations till (10).

>All steps are symmetric and reversible.

>No need to worry as every advancement is over intact-AES-256+PBKDF2-SHA512/256 but STRONG/LONG/Random PASSCODE is a MUST.

>Text boxes get automatically truncated when the text in the input box contains num(chars) >= 30000 to prevent crashing.

>Use default file extensions whenever possible .xenc and .bxenc to open encrypted files.

>Opening .bxenc files with some other extensions will result in errors while decrypting.

Nuitka standalone executable has been created. Check "CRYPTeX-vF.exe".

nuitka --standalone --onefile --mingw64  --disable-console --enable-plugin=tk-inter --windows-icon-from-ico="OWL.ico" --include-data-files="OWL.ico"="OWL.ico" "CRYPTeX-vF.py"

>Windows Defender usually flags pyinstaller/nuitka/py2exe onefile archives as a virus.
