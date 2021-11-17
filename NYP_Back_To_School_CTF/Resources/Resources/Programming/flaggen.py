import random
import string
chars = ['b','G','r','Y','{','3','d','?','g','}','N','3','!','U','P']
test = True
flag = ['_','_','_','_','_','_','_','_','_','_','_','_','_','_','_']
combinedflag = ''
letters = string.ascii_letters + string.digits

#Edit the script to find the flag
while True:
    if test == False:
        pw = ''.join(random.choice(letters) for i in range(10))  #password generator
        print(pw)
        pwcheck = input("Enter password: ")
        if pwcheck == pw and len(pwcheck) == 20 and pwcheck[0:3] == "NYP":  #requirements
            for i in range(len(chars)):
                flag[keys[i]] = chars[i] #char-key assignment
            for i in flag:
                combinedflag = i
            print(combinedflag)
            break
        else:
            print("Look down")
    else:        
        #:( no flag







































































































    #NYP{y0u_g0t_m3!}




















































































































































        keys = [3, 11, 5, 6, 2, 8, 12, 14, 13, 7, 1, 0, 4, 10, 9]
        k3ys = [6,9,11,1,3,10,4,12,8,14,0,5,13,7,2]
        test = False





