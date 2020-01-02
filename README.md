# GS15Project
GS15 IT project - Cryptography - Engineering school: Troyes University of Technology - 2019.  
As part of our cryptography course, we want to create a secure communication tool. We will implement cryptographic tools: certificates for authentication, signature (hashage) and symmetric encryption. We will create a menu in order to test individually the implemented algorithms. 

We will encode several cryptology-related functions such as :
- The Camellia Symmetric Encryption Function
- CBC, PCBC and ECB encryption modes
- The sha-3 hash function with the implementation of a sponge function 
- A private key sharing function with Diffie Hellman method
- An electronic signature function


## The Camellia Encryption
We have developed the three requested encryption modes: ECB, CBC, PCBC while trying to make them reusable for the rest of the project. 
For the moment, we have implemented, without testing, these functions by imagining to allow the user to switch from one mode to another, to choose the input or output file names, the block size, the key ...

The Camellia encryption has not presented us with any particular problem. We had a rather clear explanation with the "Description of the Camellia Encryption Algorithm" at RFC 3713 of the IETF: https://tools.ietf.org/html/rfc3713. 
Nevertheless, we spent several days to understand how to implement our algorithm correctly, we still haven't managed to finish it. Moreover, we had difficulties to handle conversions between variable types: int, string, bytes.  
In addition, we spent some time to make sure we understood how SBOXs work.

## Three encryption modes

Not too much to worry about. We had the course materials to help and guide us. The only thing that's a bit long is to always keep in mind the fact that you can reuse the function in the rest of the project. 

## SHA-3 
In Development. 

## The Diffie Hellman protocol
The principle of Shnorr groups allows to generate prime numbers. According to the statement of our project, the prime number p (and then q in the rest of the project) is determined. The number p is an integer of minimum 512 bits (64 bytes). We thus fixed it at 128 bytes to allow to have a number as random as possible wherever we want to generate this number. 
The writing of Alice and Bob's keys is done in two separate files. For ease of use, the private and public keys of each are in the same file. This is, of course, not recommended for real use. 
In the case of our exercise, we imagine taking the role of Alice. She generates Diffie Hellman's parameters, generates her personal parameters (a private random number, her public key that she will share with Bob) and will ask Bob to share her communication key with her. 
Afterwards, we will encrypt the files with this key.

## The electronic signature
We decided to implement DSA (*Digital Signature Algorithm*) for electronic signature. The algorithm is open source and can be easily found on the internet. We took inspiration from these different codes to make our own. At the moment it's in development. 

# Overall problem during the project
The main concern encountered during this project and the cruel lack of tools to manipulate byte sequences under Python. A lot of functions are non-existent or very badly optimized! 

# How To

The structure of the project:

- root: The folder where the menu file is located that calls the menu options
- lib: The folder where all functions are stored.
- tests: The folder where all text files are saved. It contains keys, signatures or certificates.

## The lib files 
At the moment there are 5 files created. Each file can be called to test the functions associated with the file, except the crypto_utils.py file:

- ***crypto_utils***: this is THE file containing supporting functions such as block cipher methods or miller-rabin test.
- ***diffie_hellman***: a file defining functions associated with the diffie hellman protocol. By running the functions in sequence, we simulate a communication between Alice and Bob using a diffie hellman protocol.
- ***Signature***: a file defining the functions associated with the DSA signature method. By calling it, it simulates the request to sign a message with Alice's key, and the verification of it. Under development, not yet push on the Master branch. 
- Camellia***: a file defining the functions associated with the Camellia encryption method. By calling it, we test the encryption and decryption of a block of data. It is not yet fully operational. 
- ***Read***: a file testing the block encryption and decryption methods on a file
- ***hash***: Should allow hashing using a sponge function. 
We often had to transform entire blocks of bits to apply them to binary functions. 
In our crypto_utils file, we have been busy developing several tools to handle these things. Little by little, we finally found functions under python that allow to handle integers more simply. 
