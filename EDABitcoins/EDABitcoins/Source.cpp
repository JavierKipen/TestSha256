#include "cryptlib.h"
#include "osrng.h"
#include "eccrypto.h"
#include "oids.h"
#include "hex.h"
#include "sha3.h"

using namespace std;
using namespace CryptoPP;

#define PRIVATE_KEY_CHARS 32
#define PUBLIC_KEY_CHARS 64

ECDSA<ECP, SHA256>::PrivateKey generatePrivKey();
vector<byte> getSignature(ECDSA<ECP, SHA256>::PrivateKey &privKey, string &data);
bool verifySignature(ECDSA<ECP, SHA256>::PublicKey &pubKey, string &data, vector<byte> &signature);
void showData(ECDSA<ECP, SHA256>::PrivateKey &pubKey, ECDSA<ECP, SHA256>::PublicKey &privKey, vector<byte> &signature);
void hexPrint(vector<byte> &dataToPrint);

void main(void)
{
	ECDSA<ECP, SHA256>::PrivateKey privateKey, fakePrivKey;
	ECDSA<ECP, SHA256>::PublicKey publicKey;
	privateKey = generatePrivKey();
	privateKey.MakePublicKey(publicKey); //A partir de la private key se genera la public

	/*Se firmará un conjunto de datos de manera que cualquier usuario pueda verificar que la firma es válida*/
	string dataToSign = "Transaction data in the future";
	vector<byte> signature = getSignature(privateKey, dataToSign); //Firmamos un mensaje con la private key generada.
	bool checkSig = verifySignature(publicKey, dataToSign, signature); //Cualquier podrá chequear la validez de la firma (checksig=true)
	
	showData(privateKey, publicKey, signature); //Mostramos los datos en hexa
	/*Ahora se intentará firmar con una private key que no corresponde con la public key:*/
	fakePrivKey = generatePrivKey();
	signature = getSignature(fakePrivKey, dataToSign); //Firmamos un mensaje con la private key generada.
	checkSig = verifySignature(publicKey, dataToSign, signature); //Se comprueba que la firma no es válida. (checksig=false)

	/*Por último, se hará un ejemplo de como se calculará el hash sha256, sea para bloques o para transacciones*/
	SHA256 hash;
	string message = "abcdefghijklmnopqrstuvwxyz";
	string digest;
	StringSource s(message, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
	cout << "Hash of the message: ";
	cout << digest << endl; 
}
ECDSA<ECP, SHA256>::PrivateKey generatePrivKey()
{
	AutoSeededRandomPool autoSeededRandomPool;
	ECDSA<ECP, SHA256>::PrivateKey privateKey;
	
	//privateKey.Initialize(autoSeededRandomPool, ASN1::secp160r1());
	privateKey.Initialize(autoSeededRandomPool, ASN1::secp256k1());
	bool result = privateKey.Validate(autoSeededRandomPool, 3);
	if (!result)
		cout << "private key is not valid!";
	return privateKey;
}

vector<byte> getSignature(ECDSA<ECP, SHA256>::PrivateKey &privKey,string &data)
{
	AutoSeededRandomPool autoSeededRandomPool;
	ECDSA<ECP, SHA256>::Signer signer(privKey); //Creamos el signador
	bool result = signer.AccessKey().Validate(autoSeededRandomPool, 3);
	if (!result)
		cout << "failed to create signer" << result;
	size_t siglen = signer.MaxSignatureLength();
	vector<byte> signature(siglen, 0x00); //Aqui guardaremos la signature
	siglen = signer.SignMessage(autoSeededRandomPool, (const byte*)data.data(), data.size(), (byte*)signature.data());
	return signature;
}

bool verifySignature(ECDSA<ECP, SHA256>::PublicKey &pubKey, string &data, vector<byte> &signature)
{
	ECDSA<ECP, SHA256>::Verifier verifier(pubKey);
	return  verifier.VerifyMessage((const byte*)data.data(), data.size(), (const byte*)signature.data(), signature.size());
}
void showData(ECDSA<ECP, SHA256>::PrivateKey &privKey, ECDSA<ECP, SHA256>::PublicKey &pubKey, vector<byte> &signature)
{
	vector<byte> privKeyByteArray(PRIVATE_KEY_CHARS), pubKeyByteArray(PUBLIC_KEY_CHARS);
	const Integer &privateKeyInteger = privKey.GetPrivateExponent(); //La key posta
	privateKeyInteger.Encode(privKeyByteArray.data(), privateKeyInteger.ByteCount());
	unsigned int auxx = privateKeyInteger.ByteCount();
	cout << "Public Key: ";
	hexPrint(privKeyByteArray);

	vector<byte> aux(PUBLIC_KEY_CHARS / 2);
	const ECP::Point &point = pubKey.GetPublicElement();
	point.x.Encode(aux.data(), point.x.ByteCount());
	pubKeyByteArray.clear();
	pubKeyByteArray.insert(pubKeyByteArray.end(), aux.begin(), aux.end());
	point.y.Encode(aux.data(), point.y.ByteCount());
	pubKeyByteArray.insert(pubKeyByteArray.end(), aux.begin(), aux.end());
	cout << "Private Key: ";
	hexPrint(pubKeyByteArray);

	cout << "Signature: ";
	hexPrint(signature);
}
void hexPrint(vector<byte> &dataToPrint)
{
	CryptoPP::HexEncoder encoder;
	string output;
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(dataToPrint.data(), dataToPrint.size());
	encoder.MessageEnd();
	cout << output << endl;
}

/*
//Código para probar cuanto tiempo tarda un hash
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

std::string hex_str = picosha2::bytes_to_hex_string(hash.begin(), hash.end()); */ 