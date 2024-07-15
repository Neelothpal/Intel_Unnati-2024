
# HASH GUARD 🔐

## Cryptography Operations using mbedtls

This C program demonstrates cryptographic operations using the `mbedtls` library, including SHA-256 hashing, RSA encryption/decryption, 3DES encryption/decryption, and AES encryption/decryption. 

## Features

1. **SHA-256 Hashing**:
   - Computes the SHA-256 hash of a user-provided 32-byte message.

2. **RSA Operations**:
   - Encrypts and decrypts messages using RSA.
   - Generates RSA key pairs (public and private keys).
   - Creates and verifies digital signatures.

3. **3DES Encryption/Decryption**:
   - Encrypts and decrypts messages using 3DES (Triple DES).

4. **AES Encryption/Decryption**:
   - Encrypts and decrypts messages using AES (Advanced Encryption Standard).

## Prerequisites

- **Docker**: Ensure that you have docker installed on your system and is running while creating and running the docker image.

## Compilation

To compile the code and create a docker image use the following command:

```docker
docker build -t crypto_app_image .
```

## Usage

Run the compiled program and follow the prompts to select the desired cryptographic operation:

```docker
docker run -it crypto_app_image
```

### 1. SHA-256 Hashing

- **Operation**: Hashes a 32-byte message using SHA-256.
- **Input**: Enter a message (max 32 bytes).
- **Output**: SHA-256 hash of the message.

### 2. RSA Encryption/Decryption

- **Operation**: Perform RSA encryption, decryption, key pair generation, and digital signature operations.
- **Options**:
  - **Encrypt**: Encrypt a message using RSA.
  - **Decrypt**: Decrypt a message using a specified RSA private key.
  - **Generate RSA Key Pair**: Generate a new RSA public/private key pair and save to PEM files.
  - **Digital Signature**: Sign a message using RSA and a specified private key.
  - **Verify Digital Signature**: Verify a signature against a message using a specified public key.

### 3. 3DES Encryption/Decryption

- **Operation**: Encrypts or decrypts a 32-byte message using 3DES.
- **Options**:
  - **Encrypt**: Encrypt a message and display the 3DES key.
  - **Decrypt**: Decrypt a message using a provided 3DES key.

### 4. AES Encryption/Decryption

- **Operation**: Encrypts or decrypts a 32-byte message using AES-256.
- **Options**:
  - **Encrypt**: Encrypt a message and display the AES key.
  - **Decrypt**: Decrypt a message using a provided AES key.

## Example

### SHA-256 Hashing

```
Enter a message to hash (max 32 bytes): Hello World
SHA-256 hash:
A591A6D40BF420404A011733C8A5AC54F7FBDC6A7F20D8D8A850A3A5B1C3A3C2
```

### RSA Encryption

```
Choose an operation:
1. Encrypt
2. Decrypt
3. Generate RSA Key Pair
4. Digital Signature
5. Verify Digital Signature
Enter your choice: 1
Enter a message to encrypt (max 245 bytes): Hello RSA
Encrypted data (hex): [Encrypted data in hex]
RSA Private Key saved to private_key.pem
RSA Public Key saved to public_key.pem
```

### 3DES Encryption

```
Choose operation:
1. Encrypt
2. Decrypt
Enter your choice: 1
Enter a 32-byte message to encrypt: Hello 3DES
Encrypted data (in hex): [Encrypted data in hex]
```

### AES Encryption

```
Choose operation:
1. Encrypt
2. Decrypt
Enter your choice: 1
Enter a 32-byte message to encrypt: Hello AES
Encrypted data (in hex): [Encrypted data in hex]
```

## Files

- `private_key.pem`: Contains the RSA private key.
- `public_key.pem`: Contains the RSA public key.
- `hash_value.bin`: Contains the hash value of a message for digital signature.
- `crypto_operations`: The compiled binary executable.
- `dockerfile`: The docker file that is used to create the docker image.

## Team - BYTEFORGE
 - S.Neelothpal Team Lead
 - D.Sathvika Team member  
 - M.Sri Priya Bhargavi Team member  
 - MD.Abdul Azeez  Team member
 - M.Anudeep	 Team member    

## Acknowledgements

- `mbedtls` library for cryptographic functions.
- [mbedTLS Documentation](https://mbed.org/projects/mbed-os-lib-mbedtls/) for reference.

## References

- [SHA-256 Algorithm](https://en.wikipedia.org/wiki/SHA-2)
- [RSA Algorithm](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Triple DES (3DES)](https://en.wikipedia.org/wiki/Triple_DES)
- [AES (Advanced Encryption Standard)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
```

Feel free to modify the example commands, file names, and paths as per your specific requirements or environment. 😊