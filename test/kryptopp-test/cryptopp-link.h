#ifndef INCLUDE_KRYPTOPP_CRYPTOPP_LINK_H
#define INCLUDE_KRYPTOPP_CRYPTOPP_LINK_H

#ifdef _WIN64
	#define K_CRYPTOPP_ARCH "x64"
#else
	#define K_CRYPTOPP_ARCH "Win32"
#endif

#ifdef _DEBUG
	#define K_CRYPTOPP_CONFIGURATION "Debug"
#else
	#define K_CRYPTOPP_CONFIGURATION "Release"
#endif

#define K_CRYPTOPP_OUTPUT "Output"	// actually not supporting MD
#define K_CRYPTOPP_LIB_NAME \
	K_CRYPTOPP_ARCH "\\" K_CRYPTOPP_OUTPUT "\\" K_CRYPTOPP_CONFIGURATION "\\cryptlib.lib"

#pragma comment(lib, K_CRYPTOPP_LIB_NAME)

#endif	// INCLUDE_KRYPTOPP_CRYPTOPP_LINK_H
