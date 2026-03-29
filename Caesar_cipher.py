def encryption(message, key, decrypt):
    if decrypt:
        key = -key
    result = ""
    for letter in message.lower():
        if letter.isalpha():
            ascii_value = ord(letter)
            shifted_value = (ascii_value - ord('a') + key) % 26
            result += chr(shifted_value + ord('a'))
        else:
            result += letter
    return result

def get_key():
    while True:
        try:
            key = int(input("Choose a key (between 0 and 26): "))
            if 0 <= key <= 26:
                return key
            print("Invalid! Key must be between 0 and 26.")
        except ValueError:
            print("Invalid! Please enter a number.")

def main():
    print("========= CAESAR CIPHER MENU =========")
    user_choice = input("Do you want to Encrypt a message or Decrypt? (E/D)").upper()
    if user_choice != "E" and user_choice != "D":
     while user_choice != "E" and user_choice != "D":
        user_choice = input("Please choose either E or D only :").upper()

    if user_choice == "E":
        message = input("What is your message ?").lower()
        key = get_key()
        print("Result:", encryption(message, key, False))
    elif user_choice == "D":
        message = input("What is your message ?").lower()
        key = get_key()
        print("Result:", encryption(message, key, True))

if __name__ == "__main__":
    main()