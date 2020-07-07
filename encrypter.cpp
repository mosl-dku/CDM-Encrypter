#include <openssl/aead.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <zlib.h>

using namespace std;

uint8_t *key;
uint8_t out[1024];
uint8_t dout[1024];
uint8_t fin[1024];
size_t fin_len=1024;
size_t bufsize = 1024;
size_t dout_len = 1024;
size_t buf_len = 1024;
size_t nonce_len =0;

std::string ReplaceAll(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    return str;
}

uint8_t* RetriveKeyFromString(std::string stf,size_t key_size){
  uint8_t *key=new uint8_t[key_size];
  unsigned long ul;
  char *dummy;
  
  for(int i=0; i<key_size; ){
    ul = strtoul(stf.substr( i*2, 8).c_str(), &dummy, 16);
    key[i++] = (ul & 0xff000000)>>24;
    key[i++] = (ul & 0xff0000)>>16;
    key[i++] = (ul & 0xff00)>>8;
    key[i++] = (ul & 0xff);
  }

  return key;
}

int main(){
    
    int key_size = 32;
    size_t out_len = sizeof(out);
    std::string input_key = "f2 fc e5 0d c7 91 9c d6 07 7e 60 35 3e c9 ab d5 a0 a8 4a 2d 7d a5 07 e8 34 a7 e0 c0 6d ea bc 20";
    uint8_t * key = RetriveKeyFromString(ReplaceAll(input_key,std::string(" "),std::string("")), 32);
    std::cout <<"[DEBUG] AES_GCM 256 Key :";
    for(int i =0; i<key_size ;i=i+1)
        printf("%02x ", key[i]);
    std::cout <<std::endl;


    string input_data= "The Common Data Model standard defines a common language for business entities covering, over time, the full range of business processes across \
    sales, services, marketing, operations, finance, talent, and commerce and for the Customer, People, and Product entities at the core of a company's business processes.";

    Bytef *in = (Bytef *)input_data.c_str();
    cout<<"[DEBUG] Input Data : "<<endl;
    cout<<input_data<<endl;


    unsigned long in_len = input_data.length();
    unsigned long nCompressedsize = in_len;

    Bytef *pCompressedData = new Bytef[256];

    int nResult = compress(pCompressedData, &nCompressedsize, in, in_len);
    cout<<"[DEBUG] Compressed Data : "<<endl;
    cout<<pCompressedData<<endl;

    const EVP_AEAD *aead = EVP_aead_aes_256_gcm();
    static const unsigned char nonce[32] = {0};
    size_t buf_len, nonce_len;
    EVP_AEAD_CTX ctx;
    EVP_AEAD_CTX_init(&ctx, aead, key, EVP_AEAD_key_length(aead),EVP_AEAD_DEFAULT_TAG_LENGTH, NULL);
    nonce_len = EVP_AEAD_nonce_length(aead);


    EVP_AEAD_CTX_seal(&ctx, out, &out_len, bufsize, nonce, nonce_len, pCompressedData, nCompressedsize, NULL, 0);
    
    
    cout<<"[DEBUG] Compressed and Encrypted message : "<<endl;
    cout << out<<endl;
    
    FILE *out_file = fopen("enc_data","wb");
    if(out_file != NULL)
    {
        //printf("%d\n",out_len);
        fwrite( out, out_len, 1, out_file);
    }
   
    fclose(out_file);
    EVP_AEAD_CTX_cleanup(&ctx);


}
