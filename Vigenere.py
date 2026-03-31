alphabet = "abcdefghijklmnopqrstuvwxyz "

letter_to_index = dict(zip(alphabet,range(len(alphabet))))
index_to_letter = dict(zip(range(len(alphabet)),alphabet))

def encryption( message , key) :
    encrypted = ""
    # 1st we split the message to the length of the key
    split_message = [message[i:i +len(key)] for i in range(0,len(message),len(key))]

    #2nd we convert the message to index and add the key mod 26
    for each_split in split_message:
        i= 0
        for letter in each_split:
            number= (letter_to_index[letter] + letter_to_index[key[i]])% len(alphabet)
            encrypted += index_to_letter[number]
            i+=1
    return encrypted

def decryption( cipher , key) :
    decrypted = ""
    # 1st we split the message to the length of the key
    split_cipher = [cipher[i:i +len(key)] for i in range(0,len(cipher),len(key))]

    #2nd we convert the message to index and subtract the key mod 26
    for each_split in split_cipher:
        i= 0
        for letter in each_split:
            number= (letter_to_index[letter] - letter_to_index[key[i]])% len(alphabet)
            decrypted += index_to_letter[number]
            i+=1
    return decrypted

def main() :
    message = input("Enter the message : ").lower()
    key = input("Enter the key : ").lower()
    cipher = encryption(message, key)
    decrypted = decryption(cipher, key)
    print("The original message is :" + message)
    print("The cipher message is :" + cipher)
    print("The decrypted message is :" + decrypted)

if __name__ == "__main__" :
    main()