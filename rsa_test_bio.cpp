#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <iostream>
#include <string.h>

using namespace std;
EVP_PKEY *temp;
RSA *pPrivKey;
RSA *pPubKey;
FILE *pFile;
const BIGNUM *val;
BIO *certbio = NULL;
BIO *keybio = NULL;
X509 *cert = NULL;
unsigned char msg[] = "Test RSA Encryption and Decryption";
unsigned char chiper[256], plain[256];

int main()
{
/*RETRIVE RSA PRIVATEKEY FROM KEYFILE*/
    keybio = BIO_new(BIO_s_file());
    BIO_read_filename(keybio, "private.key");
    pPrivKey = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);

    val = RSA_get0_n(pPrivKey);
    cout << BN_bn2hex(val) << endl;
    val = RSA_get0_d(pPrivKey);
    cout << BN_bn2hex(val) << endl;

/*RETRIVE RSA PUBKEY FROM X509 FORMAT CERT*/

    certbio = BIO_new(BIO_s_file());
    BIO_read_filename(certbio, "public.crt");
    /*load cert, retrive EVP_PKEY, extract RSA Public Key*/
    cert = PEM_read_bio_X509(certbio, NULL, 0, NULL);
    temp = X509_get_pubkey(cert);
    pPubKey = EVP_PKEY_get0_RSA(temp);

    val = RSA_get0_n(pPubKey);
    cout << BN_bn2hex(val) << endl;
    val = RSA_get0_e(pPubKey);
    cout << BN_bn2hex(val) << endl;
/*RSA ENCRYPTION WITH PRIVATE KEY*/
    int chiper_len = RSA_private_encrypt(strlen((const char*)msg), msg, 
                                        chiper, pPrivKey, RSA_PKCS1_PADDING);
    /*RSA_private_encrypt only supports RSA_PKCS1_PADDING or RSA_NO_PADDING*/
    cout<<"length :\n" <<chiper_len<<endl;
    cout<<"chiper text :\n"<<chiper<<endl;
/*RSA ENCRYPTION WITH PRIVATE KEY*/
    int plain_len = RSA_public_decrypt(sizeof(chiper), chiper, 
                                        plain, pPubKey, RSA_PKCS1_PADDING);
    cout<<"length :\n" <<plain_len<<endl;
    cout<<"Plain text :\n"<<plain<<endl;
}