#ifndef INCLUDE_KRYPTOPP_KRYPTOPP_H
#define INCLUDE_KRYPTOPP_KRYPTOPP_H

#include <random>
#include <numeric>
#include <array>
#include <vector>

namespace KryptoPP
{
	using BINARY = std::vector<CryptoPP::byte>;

	namespace AES
	{
		// max supported key size is CryptoPP::AES::MAX_KEYLENGTH
		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH,
				  std::enable_if_t<KEY_SIZE <= CryptoPP::AES::MAX_KEYLENGTH, int> = 0>
		using KEY = std::array<CryptoPP::byte, KEY_SIZE>;

		using IV = std::array<CryptoPP::byte, CryptoPP::AES::BLOCKSIZE>;

		inline CryptoPP::byte GetRandomBYTE()
		{
			// initializing random engine generator and distribution
			thread_local std::default_random_engine eng(std::random_device{}());
			thread_local std::uniform_int_distribution<int> distribution(
				std::numeric_limits<CryptoPP::byte>::min(), std::numeric_limits<CryptoPP::byte>::max());
			return static_cast<CryptoPP::byte>(distribution(eng));
		}

		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH>
		inline KEY<KEY_SIZE> GetKeyFromString(const std::string& str)
		{
			if (str.size() < KEY_SIZE)
				throw CryptoPP::Exception(CryptoPP::Exception::ErrorType::INVALID_ARGUMENT,
										  "KryptoPP::AES::GetKeyFromString: String size < KEY_SIZE");

			KEY<KEY_SIZE> key{};
			std::transform(str.begin(), str.begin() + sizeof(key), key.begin(),
						   [](const char value) { return static_cast<CryptoPP::byte>(value); });
			return key;
		}

		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH>
		inline KEY<KEY_SIZE> GetKeyFromBinary(const BINARY& binary)
		{
			if (binary.size() < KEY_SIZE)
				throw CryptoPP::Exception(CryptoPP::Exception::ErrorType::INVALID_ARGUMENT,
					"KryptoPP::AES::GetKeyFromBinary: Binary size < KEY_SIZE");

			KEY<KEY_SIZE> key{};
			std::copy(binary.data(), binary.data() + key.size(), key.data());
			return key;
		}

		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH>
		inline KEY<KEY_SIZE> GetRandomKEY()
		{
			// filling key with random values
			KEY<KEY_SIZE> rkey{};
			std::transform(rkey.begin(), rkey.end(), rkey.begin(),
						   [](auto&& value) { return GetRandomBYTE(); });
			return rkey;
		}

		inline IV GetRandomIV()
		{
			// filling key with random values
			IV riv{};
			std::transform(riv.begin(), riv.end(), riv.begin(), [](auto&& value) { return GetRandomBYTE(); });
			return riv;
		}

		// helper function that automatically prepend IV to the binary data
		// and encrypt binaries using key
		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH>
		inline BINARY Encrypt(const void* memory, size_t size, const KEY<KEY_SIZE>& key, const IV& iv)
		{
			// casting input memory
			auto cmemory = reinterpret_cast<const CryptoPP::byte*>(memory);

			// detecting output max size
			const auto maxoutput = size + iv.size() + CryptoPP::AES::BLOCKSIZE;

			// allocating output encrypted binary
			BINARY encrypted(maxoutput);

			// pre-pending iv into binary
			std::copy(iv.data(), iv.data() + iv.size(), encrypted.data());

			// making encryption object
			CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e(key.data(), key.size(), iv.data());

			// preparing sink, stream and source
			CryptoPP::ArraySink sink(encrypted.data() + sizeof(iv), encrypted.size() - sizeof(iv));
			CryptoPP::ArraySource(
				cmemory, size, true,
				new CryptoPP::StreamTransformationFilter(e, new CryptoPP::Redirector(sink)));

			// truncating output at the real output length
			encrypted.resize(sink.TotalPutLength() + sizeof(iv));
			return encrypted;
		}

		// helper function that automatically generate random IV and prepend it to the binary data
		// and encrypt binaries using key
		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH>
		inline BINARY Encrypt(const void* memory, size_t size, const KEY<KEY_SIZE>& key)
		{
			// making a random iv
			const auto iv = GetRandomIV();

			// applying it to the overload getting an input IV
			return Encrypt(memory, size, key, iv);
		}

		// wrapper getting a BINARY as input argument getting an IV via argument
		// helper function that automatically prepend IV to the binary data
		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH>
		inline BINARY Encrypt(const BINARY& memory, const KEY<KEY_SIZE>& key, const IV& iv)
		{
			return ::KryptoPP::AES::Encrypt(memory.data(), memory.size(), key, iv);
		}

		// wrapper getting a BINARY as input argument
		// helper function that automatically generate random IV and prepend it to the binary data
		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH>
		inline BINARY Encrypt(const BINARY& memory, const KEY<KEY_SIZE>& key)
		{
			return ::KryptoPP::AES::Encrypt(memory.data(), memory.size(), key);
		}

		// wrapper getting a std::string as input argument getting an IV via argument
		// helper function that automatically prepend IV to the binary data
		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH>
		inline std::string EncryptString(const std::string& str, const KEY<KEY_SIZE>& key, const IV& iv)
		{
			const auto binary = ::KryptoPP::AES::Encrypt(str.data(), str.size(), key, iv);
			return std::string(reinterpret_cast<const char*>(binary.data()), binary.size());
		}

		// wrapper getting a std::string as input argument generating a random iv
		// helper function that automatically prepend IV to the binary data
		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH>
		inline std::string EncryptString(const std::string& str, const KEY<KEY_SIZE>& key)
		{
			const auto iv = KryptoPP::AES::GetRandomIV();
			return EncryptString(str, key, iv);
		}

		// helper function that automatically get the IV from the begin of the binaries and
		// use it to decrypt the binaries using the input key
		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH>
		inline BINARY Decrypt(const void* memory, size_t size, const KEY<KEY_SIZE>& key)
		{
			// checking that memory size fit at least the iv length
			if (size < sizeof(IV))
				throw CryptoPP::Exception(CryptoPP::Exception::ErrorType::INVALID_ARGUMENT,
										  "KryptoPP::AES::Decrypt: InvalidMemorySize");

			// decoding IV
			const auto& iv = *reinterpret_cast<const IV*>(memory);

			// casting input memory
			auto cmemory = reinterpret_cast<const CryptoPP::byte*>(memory) + sizeof(IV);

			// allocating plain memory output binary
			BINARY plain(size - sizeof(IV));

			// creating decryption object
			CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d(key.data(), key.size(), iv.data());

			// making sink, source and stream
			CryptoPP::ArraySink sink(plain.data(), plain.size());
			CryptoPP::ArraySource(
				cmemory, size - sizeof(iv), true,
				new CryptoPP::StreamTransformationFilter(d, new CryptoPP::Redirector(sink)));

			// truncating output getting sink put length
			plain.resize(sink.TotalPutLength());
			return plain;
		}

		// wrapper that only require a BINARY as input argument
		// helper function that automatically get the IV from the begin of the binaries and
		// use it to decrypt the binaries using the input key
		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH>
		inline BINARY Decrypt(const BINARY& memory, const KEY<KEY_SIZE>& key)
		{
			return Decrypt(memory.data(), memory.size(), key);
		}

		// overload that return a std::string
		// its use is not recommended for excessively long strings because of the extra copy
		// helper function that automatically get the IV from the begin of the binaries and
		// use it to decrypt the binaries using the input key
		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH>
		inline std::string DecryptString(const std::string& str, const KEY<KEY_SIZE>& key)
		{
			const auto binary = Decrypt(str.data(), str.size(), key);
			return std::string(reinterpret_cast<const char*>(binary.data()), binary.size());
		}
	}  // namespace AES

	// NOTE: i decided to do not support BINARY overloads for RSA Encrypt/Decrypt to discourage use of RSA
	// for large memory chunks, RSA can only handle small chunks of memory (maximum size depends on key
	// length)
	namespace RSA
	{
		struct KeyPair
		{
			CryptoPP::RSA::PrivateKey privateKey;
			CryptoPP::RSA::PublicKey publicKey;
		};

		template <class T>
		concept RSAKeyConcept =
			std::is_same_v<T, CryptoPP::RSA::PrivateKey> || std::is_same_v<T, CryptoPP::RSA::PublicKey>;

		struct KeyPairBinary
		{
			BINARY privateKey;
			BINARY publicKey;
		};

		template <size_t KEY_SIZE = 2048>
		inline KeyPair GenerateRandomKeyPair()
		{
			// Generating random keys
			thread_local CryptoPP::AutoSeededRandomPool rng;
			CryptoPP::InvertibleRSAFunction keyFunc;
			keyFunc.GenerateRandomWithKeySize(rng, KEY_SIZE);
			return {.privateKey = keyFunc, .publicKey = keyFunc};
		}

		template <RSAKeyConcept KeyType>
		BINARY GetBinaryFromKey(const KeyType& Key)
		{
			// preparing queue
			CryptoPP::ByteQueue bytes;

			// encoding key
			if constexpr (std::is_same_v<KeyType, CryptoPP::RSA::PrivateKey>)
				Key.DEREncodePrivateKey(bytes);
			else if constexpr (std::is_same_v<KeyType, CryptoPP::RSA::PublicKey>)
				Key.DEREncodePublicKey(bytes);

			BINARY result{};
			CryptoPP::VectorSink sink(result);
			bytes.TransferAllTo(sink);
			return result;
		}

		template <RSAKeyConcept KeyType>
		KeyType GetKeyFromBinary(const BINARY& binary)
		{
			// decoding
			CryptoPP::ArraySource source(binary.data(), binary.size(), true);
			KeyType key;
			if constexpr (std::is_same_v<KeyType, CryptoPP::RSA::PrivateKey>)
				key.BERDecodePrivateKey(source, false, binary.size());
			else if constexpr (std::is_same_v<KeyType, CryptoPP::RSA::PublicKey>)
				key.BERDecodePublicKey(source, false, binary.size());
			return key;
		}

		inline KeyPairBinary GetBinaryFromKeyPair(const KeyPair& pair)
		{
			return {
				.privateKey = GetBinaryFromKey(pair.privateKey),
				.publicKey = GetBinaryFromKey(pair.publicKey),
			};
		}

		inline KeyPair GetKeyPairFromBinary(const KeyPairBinary& binary)
		{
			return {
				.privateKey = GetKeyFromBinary<CryptoPP::RSA::PrivateKey>(binary.privateKey),
				.publicKey = GetKeyFromBinary<CryptoPP::RSA::PublicKey>(binary.publicKey),
			};
		}

		// helper function encrypting a chunk of memory
		// please note that RSA only handle small chunks of memory (maximum size depends on key length)
		inline BINARY Encrypt(const void* memory, size_t size, const CryptoPP::RSA::PublicKey& publicKey)
		{
			// static threadsafe random pool
			thread_local CryptoPP::AutoSeededRandomPool rng;

			// creating encryption object
			CryptoPP::RSAES_OAEP_SHA_Encryptor encryption(publicKey);

			// allocating output binary
			BINARY encrypted(encryption.CiphertextLength(size));

			encryption.Encrypt(rng, static_cast<const CryptoPP::byte*>(memory), size, encrypted.data());
			return encrypted;
		}

		// helper function decrypting a chunk of memory
		// please note that RSA only handle small chunks of memory (maximum size depends on key length)
		inline BINARY Decrypt(const void* memory, size_t size, const CryptoPP::RSA::PrivateKey& privateKey)
		{
			// static threadsafe random pool
			thread_local CryptoPP::AutoSeededRandomPool rng;

			// creating decryption object
			CryptoPP::RSAES_OAEP_SHA_Decryptor decryption(privateKey);

			// allocating output memory
			BINARY plain(decryption.MaxPlaintextLength(size));
			auto result =
				decryption.Decrypt(rng, static_cast<const CryptoPP::byte*>(memory), size, plain.data());

			// truncating output memory
			plain.resize(result.messageLength);
			return plain;
		}

		// helper function encrypting a string
		// please note that RSA only handle small strings (maximum size depends on key length)
		inline std::string EncryptString(const std::string& input, const CryptoPP::RSA::PublicKey& publicKey)
		{
			// static threadsafe random pool
			thread_local CryptoPP::AutoSeededRandomPool rng;

			// creating encryption object
			CryptoPP::RSAES_OAEP_SHA_Encryptor enc(publicKey);

			// allocating output memory
			std::string encrypted;
			CryptoPP::StringSource ss1(
				input, true, new CryptoPP::PK_EncryptorFilter(rng, enc, new CryptoPP::StringSink(encrypted)));
			return encrypted;
		}

		// helper function decrypting a string
		// please note that RSA only handle small strings (maximum size depends on key length)
		inline std::string DecryptString(const std::string& Input, const CryptoPP::RSA::PrivateKey& PrivKey)
		{
			// static threadsafe random pool
			thread_local CryptoPP::AutoSeededRandomPool rng;

			// allocating output memory
			std::string plain;
			CryptoPP::RSAES_OAEP_SHA_Decryptor dec(PrivKey);
			CryptoPP::StringSource ss2(
				Input, true, new CryptoPP::PK_DecryptorFilter(rng, dec, new CryptoPP::StringSink(plain)));
			return plain;
		}

	}  // namespace RSA

	// RSA only supports small chunks of memory
	// so we have to mix it using AES to handle larger memory chunks
	namespace MIX
	{
		struct MIX_BINARY
		{
			BINARY encrypted;
			BINARY key;
		};

		// helper function encrypting a chunk of memory
		// mixed use of RSA + AES to handle larger chunk of memory
		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH>
		inline MIX_BINARY Encrypt(const void* memory, size_t size, const CryptoPP::RSA::PublicKey& publicKey)
		{
			MIX_BINARY mixBinary;

			// generating random AES key
			const auto aeskey = KryptoPP::AES::GetRandomKEY<KEY_SIZE>();

			// encrypting input memory using aes
			const auto binary = KryptoPP::AES::Encrypt(memory, size, aeskey);

			// encrypting aes key
			const auto aeskeyEncrypted = KryptoPP::RSA::Encrypt(aeskey.data(), aeskey.size(), publicKey);

			// returning values
			return {
				.encrypted = binary,
				.key = aeskeyEncrypted,
			};
		}

		// wrapper that get input argument BINARY
		// helper function encrypting a chunk of memory
		// mixed use of RSA + AES to handle larger chunk of memory
		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH>
		inline MIX_BINARY Encrypt(const BINARY& binary, const CryptoPP::RSA::PublicKey& publicKey)
		{
			return KryptoPP::MIX::Encrypt<KEY_SIZE>(binary.data(), binary.size(), publicKey);
		}

		// helper function decrypting a chunk of memory
		// mixed use of RSA + AES to handle larger chunk of memory
		template <size_t KEY_SIZE = CryptoPP::AES::MAX_KEYLENGTH>
		inline BINARY Decrypt(const MIX_BINARY& mixBinary, const CryptoPP::RSA::PrivateKey& privateKey)
		{
			// decrypting aes key using rsa
			const auto aeskeyBytes =
				KryptoPP::RSA::Decrypt(mixBinary.key.data(), mixBinary.key.size(), privateKey);

			// checking aes key size must match KEY_SIZE
			if (aeskeyBytes.size() != KEY_SIZE)
				throw CryptoPP::Exception(CryptoPP::Exception::DATA_INTEGRITY_CHECK_FAILED,
										  "Got an unexpected AES KEY length");

			// obtaining aes key
			const auto& aeskey = *reinterpret_cast<const KryptoPP::AES::KEY<KEY_SIZE>*>(aeskeyBytes.data());

			// decrypting memory using aes
			return KryptoPP::AES::Decrypt(mixBinary.encrypted, aeskey);
		}
	}  // namespace MIX

}  // namespace KryptoPP

#endif	// INCLUDE_KRYPTOPP_KRYPTOPP_H
