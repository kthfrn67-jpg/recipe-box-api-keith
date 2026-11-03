from security import hash_password, verify_password

def main():
    password = "soup-lover-123"

    stored_hash = hash_password(password)
    print("Stored hash:", stored_hash)

    print("Correct password check:",
          verify_password(stored_hash, "soup-lover-123"))

    print("Wrong password check:",
          verify_password(stored_hash, "soup-hater-999"))

if __name__ == "__main__":
    main()