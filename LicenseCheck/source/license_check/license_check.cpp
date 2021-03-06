// license_check.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

int my_strlen(char* s)
{
	int n = 0;
	char* t = s;
	OBFU_ONE();
	while (*t++)
	{
		CheckDebug();
		++n;
		OBFU_THR();
	}
	return n;
}

unsigned int get_key_hash(char* key)
{
	unsigned int* k = (unsigned int*)key;
	unsigned int hash = 0;

	OBFU_TWO();

	char buff[5] = { 0,0,0,0,0 };
	char* pend = 0;
	OBFU_THR();
	for (int i = 0; i < 4; ++i)
	{
		*(unsigned int*)buff = k[i];
		long int a = strtol(buff, &pend, 30);
		CheckDebug();
		if (a == 0)
		{
			__asm
			{
				xor eax, eax
				call [eax]
			};
		}
		OBFU_ONE();
		hash ^= a;
	}

	return hash;
}

int main(int argc, char** argv)
{
	if (argc < 3)
	{
		printf("Usage: %s <email> <license key>\n", argv[0]);
		return 1;
	}

	//argv[1] = "mzisthebest@notarealemail.com";
	//argv[2] = "aaaabbbbccccdddd";

	OBFU_FIVE();

	int len = my_strlen(argv[2]);

	OBFU_FOUR();

	if (len != 16)
	{
		OBFU_TWO();
		return -1;
	}

	OBFU_THR();
	int email_len = my_strlen(argv[1]);

	if (email_len < 10)
		return -2;

	int email_key = 0x0aed0dea;
	int post_at_sign = 0;
	OBFU_ONE();
	for (int i = 0; i < email_len; ++i)
	{
		OBFU_FIVE();
		if (argv[1][i] == '@')
			post_at_sign = 1;
		OBFU_TWO();
		if (post_at_sign)
			email_key ^= argv[1][i];
		else
			email_key += argv[1][i];
	}

	OBFU_FOUR();
	if (email_key != 0x0aed12f1)
		return -3;

	//easectf0r3ndom00
	OBFU_THR();
	unsigned int hash = get_key_hash(argv[2]);
	if ((hash ^ email_key ^ 0x0aecbcc2) == 0)
	{
		OBFU_ONE();
		puts("correct!");
	}

	return 0;
}

