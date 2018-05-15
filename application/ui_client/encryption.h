
//	Author: 
//			burluckij@gmail.com
//		(c) Burlutsky Stanislav 2006 - 2014

#include <bitset>
#include <stdint.h>

typedef unsigned long	ulong;
typedef unsigned char	uchar;
static const int key_t_size = 64;
//typedef std::bitset<key_t_size> key_t;
//key_t key_64;

typedef struct t_4b
{
	union 
	{
		ulong data_32;

		struct 
		{
			uchar l0: 8;
			uchar l1: 8;
			uchar l2: 8;
			uchar l3: 8;
		};
	};

}t_4b, *pt_4b;

typedef struct key_t_64
{
	union 
	{
		char buf[8];
		uint64_t data64;

		struct 
		{
			t_4b low;
			t_4b high;
		};
	};
}key_t_64, *pkey_t_64;

t_4b operator^(const t_4b& rhs, const t_4b& lhs)
{
	t_4b res = rhs;
	res.data_32 ^= lhs.data_32;
	return res;
}

t_4b operator^(const t_4b& rhs, ulong lhs)
{
	t_4b res;
	res.data_32 = rhs.data_32 ^ lhs;
	return res;
}

// The class implements simple 64 bit encryption using Feistel network
class Encryptor_64
{
private:

	// Generating function
	static ulong f(ulong L, ulong key);

	// Generate 32 bit key from 64 bit key
	static ulong get_key(uint64_t key_64, int i);

public:

	// Encrypts two 32 bit values
	static void crypt(ulong* left, ulong* right, uint64_t key_64, int rounds = 10);

	// Decrypts two 32 bit values
	static void decrypt(ulong* left, ulong* right, uint64_t key_64, int rounds = 10);

	// Encrypts array of bytes
	// length - count of bytes in pbuf, must be a multiple to eight bytes
	static void crypt_data(const char* pbuf, int length, uint64_t key_64, int rounds = 10);

	// Decrypts array of bytes
	// length - count of bytes in pbuf, must be a multiple to eight bytes
	void decrypt_data(const char* pbuf, int length, uint64_t key_64, int rounds = 10);
};
