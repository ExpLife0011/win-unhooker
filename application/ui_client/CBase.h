//      (c)VsoftLab 2006 - 2013
//		Author: burluckij@gmail.com	

#ifndef CBASE_H
#define CBASE_H


#define null_str			'\0'
#define null				NULL
#define true				1
#define false				0
#define VS_ERROR			-1		


class CBase {
public:
	CBase(void)
	{
		pstrtok = null;
	};

private:
	char* pstrtok;

public:

	static int kstrlen(const char* pstr)
	{
		int i = 0;
		for(i=0; pstr && pstr[i]; i++);
		return i;
	}

	static int kstrcpy(char* pstr_to, const char* pstr_out)
	{
		int k = 0;
		int i = 0;

		if (pstr_to==NULL || pstr_out==NULL)
			return NULL;

		for(k = kstrlen(pstr_out); k; k--, i++)
			pstr_to[i] = pstr_out[i];

		pstr_to[i] = 0;
		return 1;
	}

	// successful: 0 !error: -1
	static int kstrcmp(const char* pstr1, const char* pstr2)
	{
		int i = 0;
		int k = 0;

		if ((pstr1 == NULL) || (pstr2 == NULL))
			return -1;

		if ((k=kstrlen(pstr1)) != kstrlen(pstr2))
			return -1;

		while(k--)
		{
			if (pstr1[i] != pstr2[i])
				return -1;

			i++;
		}

		return 0;
	}

	static char* toLowA(__inout char* szString)
	{
		int length = kstrlen(szString);
		for(int i=0; i<length; i++)
			if('A'<=szString[i] && szString[i]<='Z')
				szString[i] = szString[i] - 'A' + 'a';

		return szString;
	}

	static int kstrcmp_Aa(__in const char* str1, __in const char* str2)
	{
		int k = 0;
		char posChar = 0;

		if(kstrcmp(str1, str2) == 0)
			return 0;

		if (str1==0 || str2==0){
			return -1;
		}

		if ((k = kstrlen(str1)) != kstrlen(str2)){
			return -1;
		}

		for(int i=0; i<k; i++)
		{
			if (str1[i] != str2[i])
			{
				if(('A'<=str1[i] && str1[i]<='Z') && ('a'<=str2[i] && str2[i]<='z'))
				{
					posChar = str1[i] - 'A' + 'a';
					if(posChar == str2[i])
						continue;
				} else if(('a'<=str1[i] && str1[i]<='z') && ('A'<=str2[i] && str2[i]<='Z'))
				{
					posChar = str1[i] - 'a' + 'A';
					if(posChar == str2[i])
						continue;
				}

				return -1;
			}
		}

		return 0;
	}

	static int kstrncmp_Aa(const char* pstr, const char* pstr_cmp, int length)
	{
		int k = 0;
		char posChar = 0;

		if (pstr==0 || pstr_cmp==0)
			return -1;

		if ((k = kstrlen(pstr)) != kstrlen(pstr_cmp))
			return -1;

		for(int i =0;/*k-- && */i<length;i++) {
			if (pstr[i] != pstr_cmp[i]){
				if(('A'<=pstr[i] && pstr[i]<='Z') && ('a'<=pstr_cmp[i] && pstr_cmp[i]<='z'))
				{
					posChar = pstr[i] - 'A' + 'a';
					if(posChar == pstr_cmp[i])
						continue;
				} else if(('a'<=pstr[i] && pstr[i]<='z') && ('A'<=pstr_cmp[i] && pstr_cmp[i]<='Z'))
				{
					posChar = pstr[i] - 'a' + 'A';
					if(posChar == pstr_cmp[i])
						continue;
				}

				return -1;
			}
		}

		return 0;
	}

	static int kstrncmp(const char* pstr, const char* pstr_cmp, int count)
	{
		int i = 0;
		int len = 0;

		if (!pstr || !pstr_cmp)
			return NULL;

		if (len = kstrlen(pstr) < count)
			count = len;

		for(; count--; i++)
			if (pstr[i] != pstr_cmp[i])
				return 0;

		return 1;
	}

	static int kstrncpy(char* pdest, const char* psrc, int ncopy)
	{
		int i = 0 ;

		if (!pdest || !psrc)
			return null;

		if (kstrlen(psrc) > ncopy)
			return 0;

		do
		{
			pdest[i] = psrc[i];
		}while((ncopy--) && psrc[i++]);

		pdest[i] = 0;
		return true;
	}

	static const char* kstrstr(__in const char* cmp, __in const char* srch)
	{
		int i,n;

		for(n=0; n<=kstrlen(cmp); n++)
			for(i=0; srch[i]==cmp[n+i] && cmp[n+i]!=0; i++)
				if(i==kstrlen(srch)-1)
					return &cmp[n];

		return NULL;
	}

// 	static const char* kstrstr_Aa(__in const char* cmp, __in const char* srch)
// 	{
// 		int i,n;
// 
// 		for(n=0; n<=kstrlen(cmp); n++)
// 		{
// 			for(i=0; srch[i]==cmp[n+i] && cmp[n+i]!=0; i++)
// 			{
// 				if(i == kstrlen(srch) - 1)
// 				{
// 					return &cmp[n];
// 				}
// 			}
// 		}
// 
// 		return NULL;
// 	}

	static void kmemcpy(__out char* pdest, __in const char* psrc, __in int count_byte)
	{
		for(int i = 0; count_byte; count_byte--) {
			pdest[i] = psrc[i];
			i++;
		}
	}

	static void kset_zeromem(__out void* pmem, __in int count_byte)
	{
		int i = 0;

		if(pmem)
			for(char* zbite = (char*)pmem; count_byte; count_byte--, i++)
				zbite[i] = 0;
	}

	static int kstrcat(__inout char* str, __in const char* str_cn)
	{
		int i = 0;
		char* new_string = NULL;
		int str2_len = kstrlen(str_cn);

		if((str==0) || (str_cn==0))
			return NULL;

		new_string = &str[kstrlen(str)+1];
		while(str2_len--) {
			new_string[i] = str_cn[i];
			i++;
		}
		new_string[i] = 0;
		return 1;
	}

	static int kstrncat(__inout char* str, __in const char* str_cn, __in int count)
	{
		int i = 0;
		char* new_string = NULL;

		if(str==NULL || str_cn==NULL)
			return NULL;

		for(new_string = &str[kstrlen(str)+1]; count; count--) {
			new_string[i] = str_cn[i];
			i++;
		}

		new_string[i] = 0;
		return 1;
	}

	static char* kstrchr(char* str, char ch)
	{
		int i = 0;
		int len = 0;

		if (!str)
			return NULL;

		len = kstrlen(str);
		while (len--) {
			if (str[i] == ch)
				return &str[i];
			i++;
		}

		return NULL;
	}

	static void* kmemset(void* mem, char ch, int count)
	{
		int i = 0;
		char* pmm = NULL;

		if (mem!=NULL)
			for (pmm = (char*)mem; count; count--)
				pmm[i] = ch;

		return mem;
	}

	static void* kmemchr(const void* buffer, char ch, int count)
	{
		int i = 0;
		char* pmem = NULL;

		if (buffer)
			for (pmem = (char*)buffer; count; count--)
				if(pmem[i] == ch)
					return &pmem[i];

		return NULL;
	}

	static int kmemcmp(void* buf1, void* buf2, int size_cmp)
	{
		int i = 0;
		char* mem1 = NULL;
		char* mem2 = NULL;

		if (!buf1 || !buf2)
			return NULL;

		mem1 = (char*)buf1;
		mem2 = (char*)buf2;

		while(size_cmp--) {
			if (mem1[i] != mem2[i])
				return 0;
			i++;
		}

		return 1;
	}

	static int kstrcspn(char* str1, char* str2)
	{
		int i = 0;
		int len = 0;

		if (!str1 || !str2)
			return -1;

		len = kstrlen(str1);
		while (len--) {
			if (kstrchr(str2, str1[i]))
				return i;
			i++;
		}

		return -1;
	}

	static int kstrspn(char* str1, char* str2)
	{
		int i = 0;
		int len = 0;
		char* pch = NULL;

		if (!str1 || !str2)
			return -1;

		len = kstrlen(str1);

		while(len--) {
			if (!kstrchr(str2, str1[i]))
				return i;
			i++;
		}

		return NULL;
	}

	static char* kstrrchr(char* str, char ch)
	{
		int len = 0;

		if (!str)
			return NULL;

		len = kstrlen(str);
		while(len--)
			if (str[len] == ch)
				return &str[len];

		return NULL;
	}

	static char* kstrpbrk(char* str1, char* str2)
	{
		int i = 0;
		int len = 0;

		if (!str1 || !str2)
			return NULL;

		len = kstrlen(str1);

		while(len--) {
			if (kstrchr(str2, str1[i]))
				return &str1[i];
			i++;
		}

		return NULL;
	}

	/*		"abcd, uol. "	", ."	*/
	char* kstrtok(char* str, char* lex)
	{
		int i = 0;
		char* look_up = NULL;

		if (!lex)
			return NULL;

		if (str)
			pstrtok = str;

		if (!kstrlen(pstrtok))
			return NULL;

		i = kstrspn(pstrtok, lex);

		if (i == -1)
			return NULL;

		/*	offset word		*/
		pstrtok += i;
		look_up = pstrtok;
		if (pstrtok = kstrpbrk(look_up, lex)) {
			pstrtok[0] = 0;
			pstrtok++;
		}

		return look_up;
	}

	static int katoi(char* pnum)
	{
		int i = 0;
		int n = 0;
		int signed_flag = 1;

		if(!pnum)
			return -1;

		if(pnum[0] == '-') {
			pnum +=1;
			signed_flag = -1;
		}

		while(pnum[i]) {
			if(pnum[i]>='0' && pnum[i]<='9')
				n = n*10 + pnum[i] - '0';
			else
				return -1;

			i++;
		}

		return n*signed_flag;
	}

	static int isdevide(int i)
	{
		return i%2>0?0:1;

// 		if(i%2)
// 			return 0;
// 		else
// 			return 1;
	}

	static int dec_count(int i)
	{
		int n = 10;
		int count = 1;

		if(i%10)
			return 0;

		while(n!=i) {
			n = n * 10;
			count++;
		}

		return count;
	}

	static void kitoa(int n, char* psz)
	{
		int c = 0;
		int ln = 0, d = 1;

		if(n<0) {
			psz[c++]='-';
			n = n*(-1);
		}

		for(ln=1;n/ln;ln*=10);
		ln/=10;

		while (n) {
			psz[c++] = '0' + n/ln;
			if(!(n%=ln)) {
				d = dec_count(ln);
				while(d--)
					psz[c++]='0';
				break;
			} else if(n<10) {
				psz[c++]='0'+n;
				break;
			}
			ln/=10;
		}

		if(!c)
			psz[c++]='0';

		psz[c] = 0;
	}

	/* return count of set bits */
	static int kfast_cnsetbits(unsigned char n)
	{
		int i = 0;
		while(n) {
			if(n%2)
				i++;
			n/=2;
		}

		return i;
	}

	static int kcn_bits(char* p, int cn)
	{
		int n = 0;
		while(cn--)
			n += kfast_cnsetbits(*(p++));

		return n;
	}
};
#undef null
#endif
