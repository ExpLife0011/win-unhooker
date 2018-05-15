
//	Author: 
//	burluckij@gmail.com
//	(c) Burlutsky Stanislav 2006 - 2014

// These are structures description of all known malware objects

#ifndef REFOBJECT_H
#define REFOBJECT_H

#include <Windows.h>

enum MalwareType  {
	IAT_INTERCEPTOR = 1,
	EAT_INTERCEPTOR,
	SSDT_HOOK,
	INLINE_CODE,
	IRP_HANDLER_HOOK,
	DCOM_HIDDING,
	HEUR_SUSPICION,
	MALWARE_OBJECT,
	UNKNOWN_OBJECT
};

typedef struct _um_hook_info{
	char szLibName[MAX_PATH]; // module which contains functions
	char szApiName[MAX_PATH]; // function's name
	char szProc[MAX_PATH]; // process which contains interception module
	char szModule[MAX_PATH]; // the module where is intercepted function
	PVOID originalApiAddr; // address of original function
	PVOID piat; // address in the IAT
	PVOID pHookCall;	// interceptor
	char szHookLibrary[MAX_PATH];
	DWORD pid;
	bool hideObject;
}IAT_HOOK, *PIAT_HOOK;

typedef struct _INTERCEPTOR {
	MalwareType type;
	//ulong infSize;
	PVOID pInfo;
}INTERCEPTOR, *PINTERCEPTOR;



#endif // REFOBJECT_H
