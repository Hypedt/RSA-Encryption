#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>

#define NBITS 256

void task1(void);
void task2(void);
void task3(void);
void task4(void);
void task5(void);

//Print out the Big Num
void printBN(char* msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
	//Clear the string
    OPENSSL_free(number_str);
}

//Converts the hexdecimals to integers
int hex_int(char c)
{
    if (c >= 97)
        c = c - 32;
    int first = c / 16 - 3;
    int second = c % 16;
    int result = first * 10 + second;
    if (result > 9) result--;
    return result;
}

//Converts hex 
int hex_ascii(const char c, const char d)
{
	int high = hex_int(c) * 16;
	int low = hex_int(d);
	return high+low;
}

//Converts and print out Hex to ASCII
void hex_printout(const char* st)
{
	int length = strlen(st);
	if (length % 2 != 0) {
		printf("%s\n", "invalid hex length");
		return;
	}
	//take in every 2 characters and convert to ascii
	int i;
	char buf = 0;
	for(i = 0; i < length; i++) {
		if(i % 2 != 0)
			printf("%c", hex_ascii(buf, st[i]));
		else
		    buf = st[i];
	}
	printf("\n");
}

BIGNUM* create_privateKey(BIGNUM *p, BIGNUM *q, BIGNUM* e)
{
	//Initialize and instantiate BIGNUM variables
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* p_minus_1 = BN_new();
	BIGNUM* q_minus_1 = BN_new();
	BIGNUM* one = BN_new();
	BIGNUM* tt = BN_new();

	//Set of formulas to calaculate the key
	BN_dec2bn(&one, "1");
	BN_sub(p_minus_1, p, one);
	BN_sub(q_minus_1, q, one);
	BN_mul(tt, p_minus_1, q_minus_1, ctx);
	
	//Return the key after doing the inverse 
	BIGNUM* result = BN_new();
	BN_mod_inverse(result, e, tt, ctx);
	BN_CTX_free(ctx);
	return result;
}

//Encryption function
BIGNUM* encrypt(BIGNUM* message, BIGNUM* mod, BIGNUM* publicKey)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* encrypt = BN_new();
	BN_mod_exp(encrypt, message, mod, publicKey, ctx);
	BN_CTX_free(ctx);
	return encrypt;
}

//Decryption function
BIGNUM* decrypt(BIGNUM* encrypt, BIGNUM* privateKey, BIGNUM* publicKey)
{
	/*
		compute the original message: (message ^ mod) ^ pub_key
	*/
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* decrypt = BN_new();
	BN_mod_exp(decrypt, encrypt, privateKey, publicKey, ctx);
	BN_CTX_free(ctx);
	return decrypt;
}

int main(int argc, char** argv)
{
	int choice;
	do
	{
		printf("\nMenu:\n");
		printf("1. Task1\n");
		printf("2. Task2\n");
		printf("3. Task3\n");
		printf("4. Task4\n");
		printf("5. Task5\n");
		printf("6. Quit\n");
		scanf("%d", &choice);

		//Loops until 6 is entered
		switch (choice)
		{
			case 1: task1(); //Start Task 1
			break;
			case 2: task2(); //Start Task 2
			break;
			case 3: task3(); //Start Task 3
			break;
			case 4: task4(); //Start Task 4
			break;
			case 5: task5(); //Start Task 5
			break;
			case 6: printf("Quitting Program!\n"); 
			exit(0); //Stops the program
			break;
			default:printf("Invalid Choice!\n");
			break;
		}

	}while (choice != 6);

	return 0;
	
}

//Task 1
void task1(void)
{
	//initialize and instantiate the variables
	BIGNUM *p = BN_new();
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");

	BIGNUM *q = BN_new();
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");

	BIGNUM *e = BN_new();
	BN_hex2bn(&e, "0D88C3");

	//Run the function to create a key
	BIGNUM* privateKey = create_privateKey(p,q,e);

	//Run PrintBN function and print out the key
	printBN("The private key for TASK1 is: ", privateKey);

}

//Task 2
void task2(void)
{
	BIGNUM* privateKey = BN_new();
	BN_hex2bn(&privateKey, 
	"74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	BIGNUM* publicKey = BN_new();
	BN_hex2bn(&publicKey,
	"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	printBN("The public key is: ", publicKey);

	BIGNUM* mod = BN_new();
	BN_hex2bn(&mod, "010001");

	BIGNUM* message = BN_new();
	//Original Message: A top secret!
	BN_hex2bn(&message, "4120746f702073656372657421");
	
	//Original Message hexdecimals
	printBN("the plaintext message for task2 is: ", message);
	//Encrypt the message
	BIGNUM* enc = encrypt(message, mod, publicKey);
	printBN("the encrypted message for task2 is: ", enc);
	
	//Decrypt the message to check its encryption is correct
	BIGNUM* dec = decrypt(enc, privateKey, publicKey);
	printf("the decrypted message for task2 is: ");
	//Returns the original message string
	hex_printout(BN_bn2hex(dec));
	printf("\n");
}

//Task 3
void task3(void)
{
	BIGNUM* privateKey = BN_new();
	BN_hex2bn(&privateKey, 
	"74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	BIGNUM* publicKey = BN_new();
	BN_hex2bn(&publicKey, 
	"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	printBN("The public key is: ", publicKey);

	BIGNUM* mod = BN_new();
	BN_hex2bn(&mod, "010001");

	BIGNUM* enc = BN_new();
	BN_hex2bn(&enc, 
	"8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

	//decrypt the message
	BIGNUM* dec = decrypt(enc, privateKey, publicKey);
	printf("the decrypted message for task3 is: ");
	//Returns the message: The password is dees
	hex_printout(BN_bn2hex(dec));
	printf("\n");

}

//Task 4
void task4(void)
{
	BIGNUM* privateKey = BN_new();
	BN_hex2bn(&privateKey,
	"74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	BIGNUM* publicKey = BN_new();
	BN_hex2bn(&publicKey,
	"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	printBN("The public key is: ", publicKey);

	BIGNUM* mod = BN_new();
	BN_hex2bn(&mod, "010001");
	
	BIGNUM* task4EditMessage = BN_new();
	BIGNUM* task4OriginalMessage = BN_new();
	//Original Message
	BN_hex2bn(&task4OriginalMessage,
	"49206f776520796f75202432303030");
	//Edited Message
	BN_hex2bn(&task4EditMessage, 
	"49206f776520796f75203030302e");

	//printout the original signature
	BIGNUM* enc2 = encrypt(task4OriginalMessage, privateKey, publicKey);
	printBN("The old signature for task4 is: ", enc2);
	//printout the edited signature
	BIGNUM* enc = encrypt(task4EditMessage, privateKey, publicKey);
	printBN("The new signature for task4 is: ", enc);

	BIGNUM* dec = decrypt(enc, mod, publicKey);
	BIGNUM* dec2 = decrypt(enc2, mod, publicKey);
	//printout both messages.
	printf("The original message for task4 is: ");
	hex_printout(BN_bn2hex(dec2));
	printf("The message for task4 is: ");
	hex_printout(BN_bn2hex(dec));
	printf("\n");

}

//Task 5
void task5(void)
{
	BIGNUM* task5Message = BN_new();
	BN_hex2bn(&task5Message, 
	"4c61756e63682061206d697373696c65");

	BIGNUM* sign = BN_new();
	BN_hex2bn(&sign,
	"643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

	BIGNUM* publicKey = BN_new();
	BN_hex2bn(&publicKey,
	"AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

	BIGNUM* mod = BN_new();
	BN_hex2bn(&mod, "010001");
	//Decrypt the message using the signature
	BIGNUM* dec = decrypt(sign, mod, publicKey);
	printf("The message for task5 is: ");
	//Message should match: Launch a missile.
	hex_printout(BN_bn2hex(dec));
	printf("\n");

}
