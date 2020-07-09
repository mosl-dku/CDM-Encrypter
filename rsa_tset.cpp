#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>


using namespace std;
FILE *fp_public, *fp_private;

int main()
{
    RSA *public_key_;
    RSA *private_key_;

    fp_public = fopen("public.crt", "r");
    fp_private = fopen("private.key", "r");
    
    if(!PEM_read_RSAPublicKey(fp_public, &public_key_, 0, 0))
        cout <<"read RSAPublicKey failed\n";
    
    if(!PEM_read_RSAPrivateKey(fp_private, &private_key_, 0, 0))
        cout << "read RSAPrivateKey failed\n";
    
    free(public_key_);
    free(private_key_);
    fcloseall();
    return 0;
}
