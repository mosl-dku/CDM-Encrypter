all:
	g++ encrypter.cpp -I ../boringssl/include/ -L ../boringssl/build/crypto -L ../boringssl/build/ssl/  -lcrypto -lssl -lpthread -lz -std=c++11 -o encrypter
