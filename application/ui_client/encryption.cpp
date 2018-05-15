
//	Author: 
//	burluckij@gmail.com
//	(c) Burlutsky Stanislav 2006 - 2014

#include "encryption.h"

ulong Encryptor_64::f(ulong L, ulong key)
{
	t_4b val;
	ulong mod_left = L ^ key;
	pt_4b ptr32Data = (pt_4b)&mod_left;

	val.l0 = ptr32Data->l0 ^ ptr32Data->l3;
	val.l1 = ptr32Data->l2 ^ ptr32Data->l3;
	val.l2 = ptr32Data->l1 ^ ptr32Data->l3;
	val.l3 = ptr32Data->l2 ^ ptr32Data->l3;

	return val.data_32;
}

ulong Encryptor_64::get_key(uint64_t key_64, int i)
{
	pkey_t_64 pkey_buf = (pkey_t_64)&key_64;
	int n = (i*2) % key_t_size;

	key_64 = (key_64 << n) | (key_64 >> (key_t_size - n));
	return pkey_buf->low.data_32;
}

void Encryptor_64::crypt(ulong* left, ulong* right, uint64_t key_64, int rounds)
{
	ulong temp;

	for(int i = 0; i < rounds; i++)
	{
		temp = *right ^ f(*left, get_key(key_64, i));
		*right = *left;
		*left = temp;
	}
}

void Encryptor_64::decrypt(ulong* left, ulong* right, uint64_t key_64, int rounds)
{
	ulong temp;

	for(int i = rounds - 1; i >= 0; i--)
	{
		temp = *left ^ f(*right, get_key(key_64, i));
		*left = *right;
		*right = temp;
	}	
}

void Encryptor_64::crypt_data(const char* pbuf, int length, uint64_t key_64, int rounds)
{
	for(const char* end = pbuf+length; pbuf<end; pbuf += sizeof(ulong)*2)
	{
		crypt((ulong*)pbuf, ((ulong*)(pbuf + sizeof(ulong))), key_64, rounds);
	}
}

void Encryptor_64::decrypt_data(const char* pbuf, int length, uint64_t key_64, int rounds)
{
	for (const char* end = pbuf + length; pbuf<end; pbuf += sizeof(ulong)* 2)
	{
		decrypt((ulong*)pbuf, ((ulong*)(pbuf + sizeof(ulong))), key_64, rounds);
	}
}
