#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <exception>

#include <openssl/evp.h>
#include <openssl/aes.h>

unsigned char key[32] = {58, 0x04, 0x69, 0xdb, 0x24, 0xac, 0x0c, 0x5e, 0x63, 0x61, 0x98, 0x81, 0x3c, 0xe1, 0xcf, 0x87, 0x79, 0xed, 0xd3, 0x5e, 0x09, 0xe1, 0xf6, 0xdb, 0xa4, 0x5f, 0xa1, 0x13, 0x99, 0x17, 0xd6, 0x3a};
unsigned char iv[32] = {0xc8, 0x28, 0x4c, 0xb6, 0xe9, 0xda, 0xea, 0x77, 0x7a, 0xa6, 0x9d, 0x2d, 0x7b, 0x16, 0xdb, 0x65, 0x64, 0xbd, 0xd5, 0x03, 0x0c, 0xfd, 0x45, 0xeb, 0xc6, 0xd8, 0xd9, 0x60, 0x28, 0x1a, 0x73, 0x79};

bool EncryptMessage(const char *plainText, const int plainTextMessageLength, unsigned char *&encryptedMessage, int &encryptedMessageLength);
bool DecryptMessage(const unsigned char *encrypteMessage, const int encryptedMessageLength, unsigned char *&decryptedMessage, int &decryptedMessageLength);

bool EncryptMessage(const char *plainText, const int plainTextMessageLength, unsigned char *&encryptedMessage, int &encryptedMessageLength)
{
	bool returnValue = false;

	try
	{
		int s_len = (plainTextMessageLength / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
		int i_len = 0;
		int f_len = 0;

		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		EVP_CIPHER_CTX_init(ctx);

		if ((encryptedMessage = (unsigned char *)malloc(sizeof(unsigned char) * s_len)) != NULL)
		{
			if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) > 0)
			{
				if (EVP_EncryptUpdate(ctx, encryptedMessage, &i_len, (const unsigned char *)plainText, plainTextMessageLength) > 0)
				{
					if (EVP_EncryptFinal(ctx, encryptedMessage + i_len, &f_len) > 0)
					{
						encryptedMessageLength = i_len + f_len;
						returnValue = true;
					}
					else
					{
					}
				}
				else
				{
				}
			}
			else
			{
			}
		}
		else
		{
		}
	}
	catch (const std::exception &e)
	{
		printf("\nException: %s", e.what());
	}

	return returnValue;
}

bool DecryptMessage(const unsigned char *encrypteMessage, const int encryptedMessageLength, unsigned char *&decryptedMessage, int &decryptedMessageLength)
{
	bool returnValue = false;
	try
	{
		int s_len = encryptedMessageLength;
		int i_len;
		int f_len;

		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

		if ((decryptedMessage = (unsigned char *)malloc(sizeof(unsigned char) * s_len)) != NULL)
		{
			if (EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, iv) > 0)
			{
				if (EVP_DecryptUpdate(ctx, decryptedMessage, &i_len, encrypteMessage, encryptedMessageLength) > 0)
				{
					if (EVP_DecryptFinal_ex(ctx, decryptedMessage + i_len, &f_len) > 0)
					{
						decryptedMessageLength = i_len + f_len;
						returnValue = true;
					}
					else
					{
					}
				}
				else
				{
				}
			}
			else
			{
			}
		}
		else
		{
		}
	}
	catch (const std::exception &e)
	{
		printf("\nException %s", e.what());
	}

	return returnValue;
}

int main(int argc, char **argv)
{
	char message[100];
	printf("\nEnter message to be encrypted: ");
	fgets(message, 100, stdin);

	unsigned char *encryptedMessage = NULL;
	int encryptedMessageLength = 0;

	if (EncryptMessage(message, strlen(message), encryptedMessage, encryptedMessageLength) > 0)
	{
		printf("\nEncrypted Message = %s", (char *)encryptedMessage);

		unsigned char *decryptedMessage = NULL;
		int decryptedMessageLength = 0;

		if (DecryptMessage(encryptedMessage, encryptedMessageLength, decryptedMessage, decryptedMessageLength))
		{
			printf("\nDecrypted Message = %s", (char *)decryptedMessage);
		}
		else
		{
			printf("\nFailed to decrypt message");
		}
	}
	else
	{
		printf("\nFailed to encrypt message");
	}

	return 0;
}
