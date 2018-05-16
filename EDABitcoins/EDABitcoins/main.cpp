#include <iostream>
#include <vector>
#include <time.h>
#include "cryptlib.h"
#include "picosha2.h"
#include "osrng.h"
#include "eccrypto.h"
#include "oids.h"

using namespace std;
using namespace picosha2;
using namespace CryptoPP;

#define MAX_NMBR_OF_CEROS_ON_HASH 5
#define RUNS_PER_CERO 10

void main(void)
{
	srand(time(NULL));
	string src_str = "The quick brown fox jumps over the lazy dog";
	vector<unsigned char> hash(k_digest_size);
	vector<float> avgIterations(MAX_NMBR_OF_CEROS_ON_HASH);
	AutoSeededRandomPool autoSeededRandomPool;
	ECDSA<ECP, SHA256>::PrivateKey privateKey;
	privateKey.Initialize(autoSeededRandomPool, ASN1::secp160r1());
	bool result = privateKey.Validate(autoSeededRandomPool, 3);
	if (!result)
	{
		cout << "private key is not valid!";
		return;
	}
	ECDSA<ECP, SHA256>::PublicKey publicKey;
	privateKey.MakePublicKey(publicKey);






	/*for (unsigned int i = 1; i < MAX_NMBR_OF_CEROS_ON_HASH; i++) //Para cada cantidad de ceros
	{
		for (unsigned int j = 0; j < RUNS_PER_CERO; j++) //Se corren muchas veces
		{
			unsigned int k = 0;
			bool exit = false;
			string aux = to_string(rand()) + "The quick brown fox jumps over the lazy dog" ;
			while (!exit)
			{
				k++;
				string aux2 = aux + to_string(k);
				hash256(aux2.begin(), aux2.end(), hash.begin(), hash.end());
				for (unsigned int l = 0; l < i; l++)
				{
					if (l == i - 1 && hash[l] == 0)
						exit = true;
					else if (hash[l] != 0)
						break;
				}
				
			}
			avgIterations[i] += k;
		}
		avgIterations[i] = avgIterations[i] / (float)RUNS_PER_CERO;
	}

	std::string hex_str = picosha2::bytes_to_hex_string(hash.begin(), hash.end());*/
}