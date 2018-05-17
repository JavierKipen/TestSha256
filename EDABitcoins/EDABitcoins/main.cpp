#include <iostream>
#include <vector>
#include <time.h>
#include "cryptlib.h"
//#include "picosha2.h"
#include "osrng.h"
#include "eccrypto.h"
#include "oids.h"

using namespace std;
//using namespace picosha2;
using namespace CryptoPP;

#define MAX_NMBR_OF_CEROS_ON_HASH 5
#define RUNS_PER_CERO 10

#define PRIVATE_KEY_CHARS 20
#define PUBLIC_KEY_CHARS 20

void getSignature(vector<byte> &privateKeyData, vector<byte> &publicKey);

void main(void)
{
	
	srand(time(NULL));
	AutoSeededRandomPool autoSeededRandomPool; //No se que es
	/*Las cosas que necesitaríamos por cliente*/
	ECDSA<ECP, SHA256>::PrivateKey privateKey;
	ECDSA<ECP, SHA256>::PublicKey publicKey;
	//byte privKeyByteArray[PRIVATE_KEY_CHARS], pubKeyXByteArray[PRIVATE_KEY_CHARS], pubKeyYByteArray[PRIVATE_KEY_CHARS];
	vector<byte> privKeyByteArray(PRIVATE_KEY_CHARS), pubKeyXByteArray(PRIVATE_KEY_CHARS), pubKeyYByteArray(PRIVATE_KEY_CHARS), pubKeyByteArray(2*PRIVATE_KEY_CHARS);
	vector<byte> privKeyHash, trueSignature;
	/*Inicializaciones para crear*/
	privateKey.Initialize(autoSeededRandomPool, ASN1::secp160r1());
	bool result = privateKey.Validate(autoSeededRandomPool, 3);
	if (!result)
		cout << "private key is not valid!";
	result = false;
	privateKey.MakePublicKey(publicKey); //A partir de la private key se genera la public
	const Integer &privateKeyInteger = privateKey.GetPrivateExponent(); //La key posta
	const ECP::Point &point = publicKey.GetPublicElement();
	privateKeyInteger.Encode(privKeyByteArray.data(), privateKeyInteger.ByteCount()); //Guardamos en el arreglo de byte la priv key en chars
	point.x.Encode(pubKeyXByteArray.data(), point.x.ByteCount());
	point.y.Encode(pubKeyYByteArray.data(), point.y.ByteCount());
	privKeyByteArray.clear();
	//privKeyByteArray.emplace_back(pubKeyXByteArray);
	//privKeyByteArray.emplace_back(pubKeyYByteArray);
	//Ahi ya estan las priv y las pub keys. Ahora se va a hacer las signatures:

	ECDSA<ECP, SHA256>::Signer signer(privateKey); //Creamos el signador
	result = signer.AccessKey().Validate(autoSeededRandomPool, 3);
	if (!result)
		cout << "failed to create signer" << result;
	result = false;
	size_t siglen = signer.MaxSignatureLength();
	vector<byte> signature(siglen, 0x00); //Aqui guardaremos la signature
	string src_str = "Transaction data in the future";
	siglen = signer.SignMessage(autoSeededRandomPool, (const byte*)src_str.data(), src_str.size(), (byte*)signature.data());


	ECDSA<ECP, SHA256>::Verifier verifier(publicKey);
	result = verifier.VerifyMessage((const byte*)src_str.data(), src_str.size(), (const byte*)signature.data(), signature.size());
	if (result)
		cout << "Verified signature on message";
	result = false;
	//Ahora intentemos hacer una firma falsa
	ECDSA<ECP, SHA256>::PrivateKey privateKeyFake;
	privateKeyFake.Initialize(autoSeededRandomPool, ASN1::secp160r1());
	result = privateKeyFake.Validate(autoSeededRandomPool, 3);
	if (!result)
		cout << "private key is not valid!";
	result = false;
	ECDSA<ECP, SHA256>::Signer fakeSigner(privateKeyFake); //Creamos el signador
	result = fakeSigner.AccessKey().Validate(autoSeededRandomPool, 3);
	if (!result)
		cout << "failed to create signer" << result;
	result = false;
	siglen = fakeSigner.MaxSignatureLength();
	vector<byte> signatureFake(siglen, 0x00); //Aqui guardaremos la signature
	siglen = fakeSigner.SignMessage(autoSeededRandomPool, (const byte*)src_str.data(), src_str.size(), (byte*)signatureFake.data());
	
	
	
	result = verifier.VerifyMessage((const byte*)src_str.data(), src_str.size(), (const byte*)signatureFake.data(), signatureFake.size());
	if (result)
		cout << "Verified signature on message";
	result = false;




	/*
	srand(time(NULL));
	string src_str = "The quick brown fox jumps over the lazy dog";
	vector<unsigned char> hash(k_digest_size);
	vector<float> avgIterations(MAX_NMBR_OF_CEROS_ON_HASH);
	for (unsigned int i = 1; i < MAX_NMBR_OF_CEROS_ON_HASH; i++) //Para cada cantidad de ceros
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

void getSignature(vector<byte> &privateKeyData, vector<byte> &publicKey)
{

}