#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <iostream>
#include <cstring>

#define BITS 3072

std::string publicKeyFile = "public.pem";
std::string privateKeyFile = "private.pem";

bool GenerateKeys();
bool EncryptMessage(const char*, const int, unsigned char*&, int&);
bool DecryptMessage(const unsigned char*, const int, char*&, int&);

bool GenerateKeys()
{
	bool returnValue = false;	

	//initialize public exponent
	unsigned long e = RSA_F4; //65537 - recommended public exponent
	BIGNUM *bne = BN_new();
	BN_set_word(bne,e);	

	//generate new key pair
	RSA* rsaStruct = RSA_new();
	if(1 == RSA_generate_key_ex(rsaStruct,BITS,bne,NULL))
	{

		//write generated keys to files
		FILE* publicFP = NULL;
		FILE* privateFP = NULL;
		if((NULL != (publicFP = fopen(publicKeyFile.c_str(),"w"))) && (NULL != (privateFP = fopen(privateKeyFile.c_str(),"w"))))
		{
			if((1 == PEM_write_RSAPublicKey(publicFP,rsaStruct)) && (1 == PEM_write_RSAPrivateKey(privateFP,rsaStruct,NULL,NULL,0,NULL,NULL)))
			{	
				printf("\nSuccessfully wrote private and public keys to files");
				returnValue = true;
			}
			else
			{
				printf("\nFailed to write private and public keys to files");
			}
		}
		else
		{
			printf("\nFailed to open private and public key files for writing");
		}
		fclose(publicFP);
		fclose(privateFP);
	}
	else
	{
		printf("\nFailed to generate new key pair");
	}
	
	return returnValue;
}

bool EncryptMessage(const char* plainTextMessage, const int plainTextMessageLength, unsigned char* &encryptedMessage, int& encryptedMessageLength)
{
	bool returnValue = false;
	
	//retrieve private key from file
	BIO *publicKeyBio = BIO_new_file(publicKeyFile.c_str(),"r");
	if(NULL != publicKeyBio)
	{
		RSA* rsaStruct = NULL;
		rsaStruct = PEM_read_bio_RSAPublicKey(publicKeyBio,NULL,NULL,NULL);
		if(NULL != rsaStruct)
		{
			//allocate size of 3072 bits for encrypted message based on modulus size
			if(NULL != (encryptedMessage = (unsigned char*)malloc(sizeof(unsigned char) * RSA_size(rsaStruct))))
			{
				memset(encryptedMessage,'\0',RSA_size(rsaStruct));

				//encrypt message
				if(-1 != (encryptedMessageLength = RSA_public_encrypt(plainTextMessageLength,(unsigned char*)plainTextMessage,encryptedMessage,rsaStruct,RSA_PKCS1_OAEP_PADDING)))
				{
					returnValue = true;
				}
				else
				{
					printf("\nFailed to encrypt message");
				}
			}
			else
			{
				printf("\nFailed to allocate enough memory for encrypted message");
			}	
		}
		else
		{
			printf("\nFailed to read the public key into the rsa structure");
		}
	}
	else
	{
		printf("\nFailed to read the public key from the file");
	}

	return returnValue;
}

bool DecryptMessage(const unsigned char* encryptedMessage, const int encryptedMessageLength, char*& decryptedMessage, int& decryptedMessageLength)
{
	bool returnValue = false;
	
		//retrieve public key from file
		BIO *privateKeyBio = BIO_new_file(privateKeyFile.c_str(),"r");
		if(NULL != privateKeyBio)
		{
			RSA* rsaStruct = NULL;
			rsaStruct = PEM_read_bio_RSAPrivateKey(privateKeyBio,NULL,NULL,NULL);
			if(NULL != rsaStruct)
			{
				//allocate size of 3072 bits for encrypted message based on modulus size
				if(NULL != (decryptedMessage = (char*)malloc(sizeof(char) * RSA_size(rsaStruct))))
				{
					memset(decryptedMessage,'\0',RSA_size(rsaStruct));

					//encrypt message
					if(-1 != (decryptedMessageLength = RSA_private_decrypt(encryptedMessageLength,encryptedMessage,(unsigned char*) decryptedMessage,rsaStruct,RSA_PKCS1_OAEP_PADDING)))
					{
						returnValue = true;
					}
					else
					{
						printf("\nFailed to decrypt message");
					}
				}
				else
				{
					printf("\nFailed to allocate enough memory for decrypted message");
				}	
			
			}
			else
			{
				printf("\nFailed to read the private key into the rsa structure");
			}
		}
		else
		{
			printf("\nFailed to read the private key from the file");
		}

	return returnValue;
}

int main(int argc, char** argv)
{
	if(GenerateKeys())
	{
		char message[100];
		printf("\nEnter message to be encrypted: ");
		fgets(message, 100, stdin);

		unsigned char* encryptedMessage = NULL;
		int eLength = 0;

		if(EncryptMessage(message,strlen(message),encryptedMessage,eLength))
		{
			printf("\nEncrypted message = %s",encryptedMessage);

			char* decryptedMessage = NULL;
			int dLength = 0;

			if(DecryptMessage(encryptedMessage,eLength,decryptedMessage,dLength))
			{
				printf("\nDecrypted message = %s",decryptedMessage);
			}
			else
			{
				//do nothing - error message comes from function
			}
				delete decryptedMessage;
				decryptedMessage = NULL;
		}
		else
		{
			//do nothing - error message comes from function
		}	

		delete encryptedMessage;
		encryptedMessage = NULL;
	}
	else
	{
		//do nothing - error message comes from function
	}
	return 0;
}
