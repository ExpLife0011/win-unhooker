/**********************************************************************
 * (c) Vsoft Lab
 * e-mail: burluckij@gmail.com
 **********************************************************************/

#include "kstr.h"

static char* pstrtok = 0;

/*	returned length without null symbol	*/
int kstrlen(const char* pstr)
{
	int i = 0;
	for(i=0; pstr && pstr[i]; i++);
	return i;
}

int kstrcpy(char* pstr_to, char* pstr_out)
{
	int k = 0;
	int i = 0;
	if (!pstr_to || !pstr_out) return 0;
	k = kstrlen(pstr_out);
	while(k--) {
		pstr_to[i] = pstr_out[i];
		i++;
	}
	pstr_to[i] = 0;
	return 1;
}

// successful: 0 !error: -1
int kstrcmp(char* pstr, char* pstr_cmp)
{
	int i = 0;
	int k = 0;

	if (pstr==0 || pstr_cmp==0) return -1;
	if (kstrlen(pstr) != kstrlen(pstr_cmp)) return -1;
	k = kstrlen(pstr);
	while(k--) {
		if (pstr[i] != pstr_cmp[i]) return -1;
		i++;
	}
	return 0;
}

char* toLowA(char* s)
{
	int i;
	for(i=kstrlen(s); i>=0; i--)
		if('A'<=s[i] && s[i]<='Z')
			s[i] = s[i] - 'A' + 'a';

	return s;
}

int kstrcmp_Aa(char* str1, char* str2)
{
	int k = 0,i;
	char posChar = 0;
	if (str1==0 || str2==0) return -1;
	if ((k = kstrlen(str1)) != kstrlen(str2)) return -1;
	for(i=0; i<k; i++)
		if (str1[i] != str2[i]){
			if(('A'<=str1[i] && str1[i]<='Z') && ('a'<=str2[i] && str2[i]<='z')){
				posChar = str1[i] - 'A' + 'a';
				if(posChar == str2[i]) continue;
			} else if(('a'<=str1[i] && str1[i]<='z') && ('A'<=str2[i] && str2[i]<='Z')){
				posChar = str1[i] - 'a' + 'A';
				if(posChar == str2[i]) continue;
			}
			return -1;
		}
	return 0;
}

int kstrncmp_Aa(char* pstr, char* pstr_cmp, int length)
{
	int k = 0,i;
	char posChar = 0;
	if (pstr==0 || pstr_cmp==0) return -1;
	if ((k = kstrlen(pstr)) != kstrlen(pstr_cmp)) return -1;

	for(i=0;/*k-- && */i<length;i++) {
		if (pstr[i] != pstr_cmp[i]){
			if(('A'<=pstr[i] && pstr[i]<='Z') && ('a'<=pstr_cmp[i] && pstr_cmp[i]<='z')){
				posChar = pstr[i] - 'A' + 'a';
				if(posChar == pstr_cmp[i]){continue;}
			} else if(('a'<=pstr[i] && pstr[i]<='z') && ('A'<=pstr_cmp[i] && pstr_cmp[i]<='Z')){
				posChar = pstr[i] - 'a' + 'A';
				if(posChar == pstr_cmp[i]){continue;}
			}
			return -1;
		}
	}
	return 0;
}

int kstrncmp(char* pstr, char* pstr_cmp, int count)
{
	int i = 0;
	int len = 0;

	if (!pstr || !pstr_cmp) return 0;
	if (len = kstrlen(pstr) < count) count = len;
	while(count--) {
		if (pstr[i] != pstr_cmp[i])
			return 0;
		i++;
	}

	return 1;
}

int kstrncpy(char* pstr_to, char* pstr_out, int ncopy)
{
	int i = 0 ;
	if (!pstr_to || !pstr_out) return 0;
	if (kstrlen(pstr_out) > ncopy) return 0;
	do{
		pstr_to[i] = pstr_out[i];
	}while((ncopy--) && pstr_out[i++]);
	pstr_to[i] = '\0';
	return 1;
}

const char* kstrstr(const char* cmp, const char* srch)
{
	int i,n;

	for(n=0; n<=kstrlen(cmp); n++)
		for(i=0; srch[i]==cmp[n+i] && cmp[n+i]!='\0'; i++)
			if(i==kstrlen(srch)-1)
				return &cmp[n];

	return 0;
}


int kmemcpy(char* cpy_in, char* cpy_from, int count_byte)
{
	int i = 0;
	while(count_byte--) {
		cpy_in[i] = cpy_from[i];
		i++;
	}

	return 1;
}

int kzeromem(void* pmem, int count_byte)
{
	int i = 0;
	char* zbite = 0;

	if(!pmem) return 0;

	zbite = (char*)pmem;
	while(count_byte--) {
		zbite[i] = 0x00;
		i++;
	}

	return 1;
}

int kstrcat(char* str, char* str_cn)
{
	int i = 0;
	char* new_string = 0;
	int str2_len = kstrlen(str_cn);
	if(!str || !str_cn) return 0;
	new_string = &str[kstrlen(str)+1];
	while(str2_len--) {
		new_string[i] = str_cn[i];
		i++;
	}
	new_string[i] = 0;
	return 1;
}

int kstrncat(char* str, char* str_cn, int count)
{
	int i = 0;
	char* new_string = 0;
	if(!str || !str_cn) return 0;
	new_string = &str[kstrlen(str)+1];
	while(count--) {
		new_string[i] = str_cn[i];
		i++;
	}

	new_string[i] = 0;
	return 1;
}

char* kstrchr(char* str, char ch)
{
	int i = 0;
	int len = 0;
	if (!str) return 0;
	len = kstrlen(str);
	while (len--) {
		if (str[i] == ch)
			return &str[i];
		i++;
	}

	return 0;
}

void* kmemset(void* mem, char ch, int count)
{
	int i = 0;
	char* pmm = 0;
	if (!mem) return 0;
	pmm = (char*)mem;
	while (count--)
		pmm[i] = ch;
	return mem;
}

void* kmemchr(void* buffer, char ch, int count)
{
	int i = 0;
	char* pmem = 0;
	if (!buffer) return 0;
	pmem = (char*)buffer;
	while (count--)
		if(pmem[i] == ch)
			return &pmem[i];

	return 0;
}

int kmemcmp(void* buf1, void* buf2, int size_cmp)
{
	int i = 0;
	char* mem1 = 0;
	char* mem2 = 0;
	if (!buf1 || !buf2) return 0;
	mem1 = (char*)buf1;
	mem2 = (char*)buf2;
	while(size_cmp--) {
		if (mem1[i] != mem2[i])
			return 0;
		i++;
	}

	return 1;
}

int kstrcspn(char* str1, char* str2)
{
	int i = 0;
	int len = 0;
	if (!str1 || !str2) return -1;
	len = kstrlen(str1);
	while (len--) {
		if (kstrchr(str2, str1[i]))
			return i;
		i++;
	}

	return -1;
}

int kstrspn(char* str1, char* str2)
{
	int i = 0;
	int len = 0;

	if (!str1 || !str2) return -1;
	len = kstrlen(str1);
	while(len--) {
		if (!kstrchr(str2, str1[i]))
			return i;
		i++;
	}

	return -1;
}

char* kstrrchr(char* str, char ch)
{
	int len = 0;
	if (!str) return 0;
	len = kstrlen(str);
	while(len--)
		if (str[len] == ch)
			return &str[len];

	return 0;
}

char* kstrpbrk(char* str1, char* str2)
{
	int i = 0;
	int len = 0;

	if (!str1 || !str2) return 0;
	len = kstrlen(str1);
	while(len--) {
		if (kstrchr(str2, str1[i]))
			return &str1[i];
		i++;
	}

	return 0;
}

/*		"abcd, uol. "	", ."	*/
char* kstrtok(char* str, char* lex)
{
	int i = 0;
	char* look_up = 0;
	if (!lex) return 0;
	if (str) pstrtok = str;
	if (!kstrlen(pstrtok)) return 0;
	i = kstrspn(pstrtok, lex);
	if (i == -1) return 0;

	/*	offset word		*/
	pstrtok += i;
	look_up = pstrtok;
	if (pstrtok = kstrpbrk(look_up, lex)) {
		pstrtok[0] = 0;
		pstrtok++;
	}

	return look_up;
}

int katoi(char* pnum)
{
	int i = 0;
	int n = 0;
	int signed_flag = 1;
	if(!pnum) return -1;

	if(pnum[0] =='-') {
		pnum +=1;
		signed_flag = -1;
	}

	while(pnum[i]!='\0') {
		if(pnum[i]>='0' && pnum[i]<='9')
			n = n*10 + pnum[i] - '0';
		else return(-1);
		i++;
	}

	return n*signed_flag;
}

int even_number(int i)
{
	if(i%2) return(0);
	else return(1);
}

int dec_count(int i)
{
	int n = 10;
	int count = 1;

	if(i%10 != 0)
		return 0;

	while(n!=i) {
		n = n * 10;
		count++;
	}

	return count;
}

void kitoa(int n, char* psz)
{
	int c = 0;
	int ln = 0, d = 1;

	if(n<0)
	{
		psz[c++]='-';
		n = n*(-1);
	}

	for(ln=1;n/ln;ln*=10);
	ln/=10;

	while (n)
	{
		psz[c++] = '0' + n/ln;
		if((n%=ln) == 0) {
			d = dec_count(ln);
			while(d--) {
				psz[c++]='0';
			}
			break;
		} else if(n<10) {
			psz[c++]='0'+n;
			break;
		}
		ln/=10;
	}

	if(!c) {
		psz[c++]='0';
	}
	psz[c] = '\0';
}

/* return count of set bits */
int kfast_cnsetbits(unsigned char n)
{
	int i = 0;
	while(n) {
		if(n%2)
			i++;
		n/=2;
	}
	return i;
}

int kcn_bits(char* p, int cn)
{
	int n = 0;
	while(cn--)
		n += kfast_cnsetbits(*(p++));

	return n;
}