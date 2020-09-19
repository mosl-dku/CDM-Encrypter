#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <zlib.h>
#include <openssl/aead.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <iostream>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <streambuf>
using namespace std;

uint8_t *key;
uint8_t *out;
uint8_t dout[1024];
uint8_t fin[1024];
size_t fin_len = 1024;
size_t bufsize = 1024;
size_t out_len;
size_t out_buflen;
size_t dout_len = 1024;
size_t buf_len = 1024;
size_t nonce_len = 0;
std::string input_data;
char enc_output_filename[256];

RSA *pPrivKey;
RSA *pPubKey;
FILE *pFile;
unsigned char cipher[256], plain[256], cipher2[256];

std::string ReplaceAll(std::string str, const std::string &from, const std::string &to)
{
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos)
    {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    return str;
}

RSA *RetrivePrivKeyFromFile(const char *file_name)
{
    BIO *keybio = BIO_new(BIO_s_file());
    BIO_read_filename(keybio, file_name);
    RSA *output = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
    BIO_free(keybio);
    return output;
}

RSA *RetrivePubKeyFromX509(const char *file_name)
{
    BIO *certbio = BIO_new(BIO_s_file());
    BIO_read_filename(certbio, file_name);
    RSA *output = EVP_PKEY_get0_RSA(
                    X509_get_pubkey(
                        PEM_read_bio_X509(certbio, NULL, 0, NULL)));
    BIO_free(certbio);
    return output;
}

int WriteToFS(const char *file_name, unsigned char* c)
{
    BIO *outbio = BIO_new(BIO_s_file());
    BIO_write_filename(outbio, file_name);
    int nrbytes = BIO_write(outbio,c,256);
    BIO_free(outbio);
    return nrbytes;
}

int ReadFromFS(const char *file_name, unsigned char* p)
{
    BIO *inputbio = BIO_new(BIO_s_file());
    BIO_read_filename(inputbio, file_name);
    int nrbytes = BIO_read(inputbio,p,256);
	BIO_free(inputbio);
    return nrbytes;
}

uint8_t *RetriveKeyFromString(std::string stf, size_t key_size)
{
    uint8_t *key = new uint8_t[key_size];
    unsigned long ul;
    char *dummy;

    for (int i = 0; i < key_size;)
    {
        ul = strtoul(stf.substr(i * 2, 8).c_str(), &dummy, 16);
        key[i++] = (ul & 0xff000000) >> 24;
        key[i++] = (ul & 0xff0000) >> 16;
        key[i++] = (ul & 0xff00) >> 8;
        key[i++] = (ul & 0xff);
    }

    return key;
}

int main(int argc, char* argv[])
{

	if ((argc != 4) && (argc != 5)) {
		printf("usage: encrypter key_path_dir key_value input_file output_file\n");
		printf("note that you should have private.key, public.crt in the key_path_dir\n");
		printf("note that you should provide 256 bit key stream in string\n");
		return 0;
	}
	struct stat sbuf;
	char *key_path_dir = argv[1];
	// no valid key_path_dir
	if (stat(key_path_dir, &sbuf) == -1) {
		printf("No valid key_path_dir directory\n\n");
		printf("usage: encrypter key_path_dir key_value input_file output_file\n");
		printf("note that you should have private.key, public.crt in the key_path_dir\n");
		printf("note that you should provide 256 bit key stream in string\n");

		return 0;
	}

    int key_size = 32;
	std::string input_key(argv[2]);
	if (strncmp("-1", argv[2], 2) == 0) {
		// 256 bit key stream (32bytes)
		std::string key("f2 fc e5 0d c7 91 9c d6 07 7e 60 35 3e c9 ab d5 a0 a8 4a 2d 7d a5 07 e8 34 a7 e0 c0 6d ea bc 20");
		printf("default_key_value: %s\n", key.c_str());
		input_key = key;
	} else {
		printf("input key_value: %s\n", input_key.c_str());
	}

	if  (stat(argv[3], &sbuf) == -1) {
		printf("Invalid encrypting input file, we use default sample input_data\n\n");
		printf("usage: encrypter key_path_dir key_value input_file output_file\n");
		printf("note that you should have private.key, public.crt in the key_path_dir\n");
		printf("note that you should provide 256 bit key stream in string\n");
		std::string sample_input_data = "The Common Data Model standard defines a common language for business entities covering, over time, the full range of business processes across \
    sales, services, marketing, operations, finance, talent, and commerce and for the Customer, People, and Product entities at the core of a company's business processes.";

		input_data = sample_input_data;
		return 0;
	}
	memset(enc_output_filename, 0, sizeof(enc_output_filename));
	if (argc == 4) {
		sprintf(enc_output_filename, "%s.enc", argv[3]);
	} else if (argc == 5) {
		memcpy(enc_output_filename, argv[4], strlen(argv[4]));
	} else {
		printf("usage: encrypter key_path_dir key_value input_file output_file\n");
		printf("note that you should have private.key, public.crt in the key_path_dir\n");
		printf("note that you should provide 256 bit key stream in string\n");
		return 0;
	}


	char Kpriv[256];
	char Kpub[256];
	sprintf(Kpriv, "%s/private.key", key_path_dir);
	sprintf(Kpub, "%s/public.crt", key_path_dir);
    pPrivKey = RetrivePrivKeyFromFile(Kpriv);
    pPubKey = RetrivePubKeyFromX509(Kpub);

    int sig_len = RSA_private_encrypt(input_key.length(), (const unsigned char*)input_key.c_str(),
                        cipher, pPrivKey, RSA_PKCS1_PADDING);

    int wrlen = WriteToFS("enc_key",cipher);
    int rdlen = ReadFromFS("enc_key",cipher2);
	cout << "wrlen: " << wrlen << " rdlen: " << rdlen << std::endl;

	int plen;
    plen = RSA_public_decrypt(RSA_size(pPubKey), cipher2, plain, pPubKey, RSA_PKCS1_PADDING);
	cout << "sig_len: " << sig_len << " plen: " << plen<< std::endl;

        ERR_load_crypto_strings();
        char * err = (char *)malloc(130);
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);

    cout << "[DEBUG] Original input_key :\n"
         << input_key << endl;
    cout << "[DEBUG] Chiper :\n"
         << cipher << endl;
    cout << "[DEBUG] de-cipher input_key :\n"
         << plain << endl;

    uint8_t *key = RetriveKeyFromString(
        ReplaceAll(input_key, std::string(" "), std::string("")), 32);
    std::cout << "[DEBUG] AES_GCM 256 Key :";
    for (int i = 0; i < key_size; i = i + 1)
        printf("%02x ", key[i]);
    std::cout << std::endl;

	std::ifstream t(argv[3]);

	t.seekg(0, std::ios::end);
	input_data.reserve(t.tellg());
	t.seekg(0, std::ios::beg);

	input_data.assign((std::istreambuf_iterator<char>(t)),
            std::istreambuf_iterator<char>());

	t.close();

    Bytef *in = (Bytef *)input_data.c_str();
    //cout << "[DEBUG] Input Data : " << endl;
    //cout << input_data << endl;

    unsigned long in_len = input_data.length();
    unsigned long nCompressedsize = in_len;

    Bytef *pCompressedData = new Bytef[in_len];
	memset(pCompressedData, 0, in_len);

    int nResult = compress(pCompressedData, &nCompressedsize, in, in_len);
    cout << "[DEBUG] Compressed Data ("<< nCompressedsize <<"): " << endl;
    cout << pCompressedData << endl;

	out_buflen = (nCompressedsize << 4) + 32;
	out = new uint8_t[out_buflen];

    const EVP_AEAD *aead = EVP_aead_aes_256_gcm();
    static const unsigned char nonce[32] = {0};
    size_t buf_len, nonce_len;
    EVP_AEAD_CTX ctx;
    EVP_AEAD_CTX_init(&ctx, aead, key, EVP_AEAD_key_length(aead), EVP_AEAD_DEFAULT_TAG_LENGTH, NULL);
    nonce_len = EVP_AEAD_nonce_length(aead);

    EVP_AEAD_CTX_seal(&ctx, out, &out_len, out_buflen, nonce, nonce_len, pCompressedData, nCompressedsize, NULL, 0);

    cout << "[DEBUG] Compressed and Encrypted message ("<< out_len <<"): " << endl;
    cout << out << endl;
    EVP_AEAD_CTX_cleanup(&ctx);

    std::ofstream out_file;
	out_file.open(enc_output_filename, std::ofstream::out | std::ofstream::binary);
	if (out_file.is_open()) {
		out_file.write((char *)out, out_len);
		out_file.close();
		cout << "[DEBUG] file written "<< out_len <<" bytes" << std::endl;
	} else {
		cout << "filename: " << enc_output_filename << std::endl;
	}
}
