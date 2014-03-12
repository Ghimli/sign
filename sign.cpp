#include <stdio.h>
#include <string>
#include <openssl/sha.h>
#include <vector>
using namespace std;
#include "util.h"
#include "key.h"

const string strMessageMagic = "Bitmaszyna.pl API:\n";
CKey key;
vector<unsigned char> v,vsig;
bool bb;
string msg,signature;
SHA256_CTX ctx;
uint256 hash1,hash2;

static const string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
	string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	while (in_len--) {
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for(i = 0; (i <4) ; i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i)
	{
		for(j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while((i++ < 3)) ret += '=';
	}

	return ret;

}

int main(int argc,char *argv[]) {

if (argc!=3)
{
    fprintf(stderr,"sign <secret> <message>\n");
    return(255);
}

v=DecodeBase64(argv[1],&bb);
if (bb)
{
    fprintf(stderr,"invalid secret\n");
    return(255);
}
msg=argv[2];
key.SetSecret(v);
SHA256_Init(&ctx);
SHA256_Update(&ctx,strMessageMagic.c_str(),strMessageMagic.size());
SHA256_Update(&ctx,msg.c_str(),msg.size());
SHA256_Final((unsigned char *)&hash1,&ctx);
SHA256((unsigned char *)&hash1,sizeof(hash1),(unsigned char *)&hash2);
if (!key.SignCompact(hash2, vsig)) {
        printf("Sign failed\n");
}
signature=base64_encode(&vsig[0],vsig.size());
printf("%s\n",signature.c_str());
}
