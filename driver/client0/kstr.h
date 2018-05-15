/************************************************************************/
/*      (c)VsoftLab 2006 - 2012											
/*		Author: burluckij_s_a											
/************************************************************************/

#define strstr kstrstr
//#define memcpy kmemcpy
#define strcpy kstrcpy

/*	returned length without null symbol	*/
int kstrlen(const char* pstr);
int kstrcpy(char* pstr_to, char* pstr_out);
// successful: 0 !error: -1
int kstrcmp(char* pstr, char* pstr_cmp);
char* toLowA(char* s);
int kstrcmp_Aa(char* str1, char* str2);
int kstrncmp_Aa(char* pstr, char* pstr_cmp, int length);
int kstrncmp(char* pstr, char* pstr_cmp, int count);
int kstrncpy(char* pstr_to, char* pstr_out, int ncopy);
const char* kstrstr(const char* cmp, const char* srch);
int kmemcpy(char* cpy_in, char* cpy_from, int count_byte);
int kzeromem(void* pmem, int count_byte);
int kstrcat(char* str, char* str_cn);
int kstrncat(char* str, char* str_cn, int count);
char* kstrchr(char* str, char ch);
void* kmemset(void* mem, char ch, int count);
void* kmemchr(void* buffer, char ch, int count);
int kmemcmp(void* buf1, void* buf2, int size_cmp);
int kstrcspn(char* str1, char* str2);
int kstrspn(char* str1, char* str2);
char* kstrrchr(char* str, char ch);
char* kstrpbrk(char* str1, char* str2);
/*		"abcd, uol. "	", ."	*/
char* kstrtok(char* str, char* lex);
int katoi(char* pnum);
int even_number(int i);
int dec_count(int i);
void kitoa(int n, char* psz);
/* return count of set bits */
int kfast_cnsetbits(unsigned char n);
int kcn_bits(char* p, int cn);