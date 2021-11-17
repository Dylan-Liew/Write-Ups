import math

'''
def encrypt(plaintext='',key=''):
    plaintext_ascii = [ ord(i) for i in plaintext ]
    key_ascii = [ ord(i) for i in key ]

    key_counter = 0
    plaintext_counter = 0
    ciphertext = ''
    off_list = ''
    while len(plaintext) > plaintext_counter:
        if key_counter == 5:
            key_counter = 0
        if (plaintext_ascii[plaintext_counter] + key_ascii[key_counter]) % 2 == 1:
            off_list += str(plaintext_counter)
        new_ascii = math.ceil((plaintext_ascii[plaintext_counter] + key_ascii[key_counter])/2)
        
        ciphertext += chr(new_ascii)
        
        key_counter += 1
        plaintext_counter += 1

    ciphertext += "offset" + off_list
    return ciphertext
'''

#Fix the lines with the # in them

def decrypt(ciphertext='',key=''):
    #Extract the ciphertext
    off = ciphertext[ciphertext.index("")+6:]#
    ciphertext = ciphertext[0:ciphertext.index("")]#
    ciphertext_ascii = [ ord(i) for i in ciphertext ]
    key_ascii = [ ord(i) for i in key ]

    key_counter = #
    ciphertext_counter = 0
    plaintext = ''
    while len(ciphertext) < ciphertext_counter:#
        if key_counter == 5:
            key_counter = 0
        new_ascii = ciphertext_ascii[ciphertext_counter] * 4 - key_ascii[key_counter]#
        plaintext += chr(new_ascii)
        
        key_counter += 1
        ciphertext_counter += 1


    #Make list of offset indexes
    skip = False
    off_list = []
    prev_num = 0
    for i in range(len(off)):
        if skip == False:
            if int(off[i]) > prev_num:
                off_list.append(int(off[i]))
                prev_num = int(off[i])
            else:
                off_list.append(int(off[i:i+1]))#
                prev_num = int(off[i:i+2])
                skip = True
        else:
            skip = #

    #Create new plaintext after setting offset characters back
    newplaintext = ''
    for i in range(len(plaintext)):
        if i in off_list:
            newchar = chr(ord(plaintext[i])-1)
        else:
            newchar = plaintext[i]

        newplaintext += newchar
    return newplaintext

#Maybe reading the encryption code can help
