# KryptoPP
CryptoPP wrapper and header-only library.


# AES IMPORTANT NOTES
This implementation of AES uses CryptoPP CBC (Cipher Block Chaining), which covers most usage cases.
The encryption key length can be enforced by using the template argument when declaring CryptoPP::AES::KEY.
The encryption method provided by this library does not require an IV (it is an optional argument). If no IV is provided, it will be randomly generated.

Please note that this library always prepended the IV (unencrypted) to the binary data, as it is usually not necessary to keep it secret.
We recommend, while using the overload specifying an IV, not to use the same IV more than once, as it compromises the security of symmetric encryption.
Thanks to this library, it is possible to completely ignore the IV by not passing it — the library will generate it randomly each time, which is the correct way to use CBC encryption.

In a future update, a "Checked" version of each Encrypt/Decrypt function will be implemented. This version will prepend a salt before encrypting the binary data and verify that the salt is still present when decrypting.
This is useful to ensure that the data has not been modified or corrupted.


# AES used to encrypt Binary data
```c++
#include <kryptopp/kryptopp.h>

try
{
	// declaring some binary input
	KryptoPP::BINARY binary = {CryptoPP::byte(0xFF), CryptoPP::byte(0xFA), CryptoPP::byte(0xAC),
							   CryptoPP::byte(0x12), CryptoPP::byte(0xFA), CryptoPP::byte(0xAC)};

	// note: i m using a 32 bytes string (excluding the zero delimiter) which is the default key size
	//       but it is possible to specify a different key length passing agument template e.g. :
	//       KryptoPP::AES::GetKeyFromString<16>("................")
	const auto aeskey = KryptoPP::AES::GetKeyFromString("STRING IS EXACTLY 32 BYTES LONG!");
	const auto encrypted = KryptoPP::AES::Encrypt(binary, aeskey);

	// encrypted is now a BINARY containing the encrypted data
	// note: i m using BINARY as input of KryptoPP::AES::Encrypt but it is possible to use another
	//       overload that only require a more generic const void* and size_t

	// decrypting back data
	const auto plain = KryptoPP::AES::Decrypt(binary, aeskey);

	// plain is now containing back the plain binary which is equal to "binary" the initial input
}

catch (const std::exception& except)
{
	// note: i m catching std::exception but it is possible to catch CryptoPP::Exception instead
	// handling exception!
	//......
}
```



# AES usage to encrypt Strings
```c++
#include <kryptopp/kryptopp.h>

try
{
	// declaring some string input
	std::string input = "OUT MOST IMPORTANT SECRET!";

  // making key and encrypting string
	const auto aeskey = KryptoPP::AES::GetKeyFromString("STRING IS EXACTLY 32 BYTES LONG!");
	const auto encrypted = KryptoPP::AES::EncryptString(input, aeskey);

	// encrypted is now a std::string containing the encrypted text
  // .... use of the encrypted memory

	// decrypting back to plain string...
	const auto plain = KryptoPP::AES::DecryptString(binary, aeskey);
  // .... use of the plain text
}

catch (const std::exception& except)
{
	// note: i m catching std::exception but it is possible to catch CryptoPP::Exception instead
	// handling exception!
	//......
}
```
Other example can be found in test/kryptopp-test/kryptopp-test.cpp



# RSA IMPORTANT NOTES
RSA encryption is an asymmetric encryption method that, given a Public Key, allows for one-way encryption of data.
There is no way to decrypt the data using the public key alone.
To decrypt the data, you must provide the Private Key, which is paired with the public key used for encryption.

RSA encryption is much slower than AES or any other symmetric encryption method. For this reason, it is only recommended for encrypting small chunks of data.
The maximum length of data that can be encrypted with RSA is limited and depends on the length of the paired keys.
Note that key generation takes significantly longer for larger keys due to the complexity of the operation, which is 𝑂(𝑛³).
For this reason, generating a 2048-bit key pair is approximately 8 times faster than generating a 4096-bit key pair, and this makes not possible to generate keys that are large enough to encrypt MBs of data.

# RSA usage to encrypt binary
```c++
#include <kryptopp/kryptopp.h>

try
{
	// declaring some binary input
	KryptoPP::BINARY binary = {CryptoPP::byte(0xFF), CryptoPP::byte(0xFA), CryptoPP::byte(0xAC),
							   CryptoPP::byte(0x12), CryptoPP::byte(0xFA), CryptoPP::byte(0xAC)};

	// note: i m using a random generated key pair but this wrapper offers
	//       helper functions to convert them from binary and to binary
	const auto rsaPair = KryptoPP::RSA::GenerateRandomKeyPair();
	const auto encrypted = KryptoPP::RSA::Encrypt(binary.data(), binary.size(), rsaPair.publicKey);

	// encrypted is now a BINARY containing the encrypted data
	// .... use of encrypted data ....

	// decrypting back data
	const auto plain = KryptoPP::RSA::Decrypt(encrypted.data(), encrypted.size(), rsaPair.privateKey);

	// plain is now containing back the plain binary which is equal to "binary" the initial input
}

catch (const std::exception& except)
{
	// note: i m catching std::exception but it is possible to catch CryptoPP::Exception instead
	// handling exception!
	//......
}
```


# MIX IMPORTANT NOTES
MIX is a hybrid encryption method that leverages the advantages of AES and the security of RSA.
Hybrid encryption generates a random encryption key to encrypt data with AES, and this key is then encrypted using RSA. This way, only those who possess the RSA private key can decrypt the encryption key, which is then used to decrypt the original data with AES.

With this method, even large amounts of data can be encrypted, taking advantage of AES for data encryption—since it is very fast—while still maintaining the benefits of asymmetric encryption.

This approach, which utilizes AES in the best possible way (with a random key and a random IV), ensures a high level of robustness without causing efficiency loss or imposing limitations on the maximum data size, which would occur if only RSA were used.

# MIX usage to encrypt Binary

```c++
#include <kryptopp/kryptopp.h>

try
{
	// getting random key and input memory
	const auto rsaPair = KryptoPP::RSA::GenerateRandomKeyPair();
	const auto input = std::string("\"MIX - Hello World!\"");
	std::cout << "MIX encryption: input.size = " << input.size() << std::endl;

	// encrypting memory
	const auto encrypted = KryptoPP::MIX::Encrypt(input.data(), input.size(), rsaPair.publicKey);
	std::cout << "MIX encryption: encrypted.size = " << encrypted.encrypted.size() << std::endl;

	// decrypting memory
	const auto plain = KryptoPP::MIX::Decrypt(encrypted, rsaPair.privateKey);
	const auto plainString = std::string{reinterpret_cast<const char*>(plain.data()), plain.size()};
	std::cout << "MIX encryption: plain.size = " << plainString.size() << std::endl;
	std::cout << "MIX encryption: plain = " << plainString << "   expected = " << input << std::endl;

	if (input == plainString)
		std::cout << "MIX encryption: test passed!\n\n";
	else
		std::cout << "MIX encryption: test failed!\n\n";
}

catch (const std::exception& except)
{
	// note: i m catching std::exception but it is possible to catch CryptoPP::Exception instead
	// handling exception!
	//......
}
```



# Test steps (only Visual Studio is actually supported)
- Download the CryptoPP version you prefer from Official CryptoPP website (only higher than 8.0.0 are supported)
- Create a directory into kryptopp/test naming it cryptopp
- Extract the zip containing the CryptoPP source inside it
- Open cryptest.sln
- Right click on the solution and click on "Batch compilation"
- Select all the cryptlib configurations and compile all of them
- Close this solution and open kryptopp-test.sln
- Compile it and run it using "Play" button
