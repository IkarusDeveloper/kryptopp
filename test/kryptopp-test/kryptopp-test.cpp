#include <iostream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/default.h>
#include <cryptopp/hex.h>
#include <cryptopp/aes.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <kryptopp/kryptopp.h>

// file used to link cryptopp dynamically depending on the compilation flags
#include "cryptopp-link.h"

int main()
{
	// testing AES encryption
	{
		// getting random key and input memory
		const auto aesKey = KryptoPP::AES::GetRandomKEY();
		const auto input = std::string("\"AES - Hello World!\"");
		std::cout << "AES encryption: input.size = " << input.size() << std::endl;

		// encrypting memory
		const auto encrypted = KryptoPP::AES::EncryptString(input, aesKey);
		std::cout << "AES encryption: encrypted.size = " << encrypted.size() << std::endl;

		// decrypting memory
		const auto plain = KryptoPP::AES::DecryptString(encrypted, aesKey);
		std::cout << "AES encryption: plain.size = " << plain.size() << std::endl;
		std::cout << "AES encryption: plain = " << plain << "   expected = " << input << std::endl;

		if (input == plain)
			std::cout << "AES encryption: test passed!\n\n";
		else
			std::cout << "AES encryption: test failed!\n\n";
	}

	// testing RSA encryption
	{
		// getting random key and input memory
		const auto rsaPair = KryptoPP::RSA::GenerateRandomKeyPair();
		const auto input = std::string("\"RSA - Hello World!\"");
		std::cout << "RSA encryption: input.size = " << input.size() << std::endl;

		// encrypting memory
		const auto encrypted = KryptoPP::RSA::EncryptString(input, rsaPair.publicKey);
		std::cout << "RSA encryption: encrypted.size = " << encrypted.size() << std::endl;

		// decrypting memory
		const auto plain = KryptoPP::RSA::DecryptString(encrypted, rsaPair.privateKey);
		std::cout << "RSA encryption: plain.size = " << plain.size() << std::endl;
		std::cout << "RSA encryption: plain = " << plain << "   expected = " << input << std::endl;

		if (input == plain)
			std::cout << "RSA encryption: test passed!\n\n";
		else
			std::cout << "RSA encryption: test failed!\n\n";
	}

	// testing MIX encryption
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

	return 0;
}
