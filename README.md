# C++ Password Manager

A simple, command-line password manager written in C++.  
**Note:** This project is for educational and personal use only.  
It demonstrates basic password storage and encryption concepts, but is **not suitable for production or sensitive data.**

## Features

- Add, retrieve, and list password entries
- Passwords are encrypted using a combination of Vigenère and substitution ciphers derived from a master key
- Encrypted passwords are stored in Base64 format in a local file
- Supports full printable ASCII passwords and usernames
- Portable (no hard-coded file paths)

## Usage

### Compile

```sh
g++ -std=c++11 -o password-manager main.cpp
```

### Run

```sh
./password-manager
```

### Menu Options

1. **Add entry** – Add a new username/password, encrypted with your master key
2. **Get password** – Retrieve a password by username (requires the master key)
3. **List entries** – List all saved usernames
4. **Exit** – Quit the program

## File Storage

Passwords are stored in a file called `vault.dat` in the project directory, in the format:

```
username|encrypted_password_base64
```

## Security Warning

- **Do not use for real or sensitive passwords!**
- Uses custom cryptography (Vigenère + substitution cipher) which is not considered secure
- If you lose your master key, your passwords cannot be recovered
- No protection against file tampering or brute-force attacks
- For real-world password management, use established password managers and cryptographic libraries

## License

[MIT License](LICENSE)

## Contributing

Pull requests and suggestions are welcome!  
Open an issue to discuss improvements or ask questions.

## Author

FatihMUTLU1
