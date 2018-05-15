
//	Author: 
//	burluckij@gmail.com
//	(c) Burlutsky Stanislav 2006 - 2014

#ifndef PE_H
#define PE_H

#ifndef _WINDOWS_
#include <windows.h>
#endif

#ifndef _PSAPI_H_
#include <Psapi.h>
#endif

#pragma comment(lib, "psapi")

#ifndef CBASE_H
#include "CBase.h"
#endif

#include <stdio.h>
#include <vector> 
#include <map> 
#include "System.h"

#define MIN_FILE_SIZE		1024
#define dll_export			__declspec(dllexport)
#define SECTION_ERROR		0x01
#define IMPORT_ERROR		0x02
#define EXPORT_ERROR		0x04
#define HEADER_ERROR		0x08
#define CRASH_INIT			0xFF
#define SUCCESS_INIT		0x00
#define TEMP_STRING_SIZE	1024

#define INVALID_SET_FILE_POINTER ((DWORD)-1)

typedef struct cstrmem_ {
	char* p; // pointer to ascii string
	ulong rsize; // region size
} mregion, *pmregion;

typedef struct _EXPORT_FN { // EXPORT 
	PVOID Api; 
	char* Name;
	DWORD Ordinal;
	PVOID forward_;
}EXPORT_FN, *PEXPORT_FN;

typedef struct IMPORT_FN {
	IMPORT_FN* next; // if it's last .next = NULL
	PVOID Api; // address of function
	char* ApiName; // pointer to the ascii string with name of function
	PVOID AddrFuncAddr; // address where is address of function
	WORD Ordinal; // ordinal number
}IMPORT_FN, *PIMPORT_FN;

typedef struct IMPORT_LIB_ {
	char* szLib;
	ulong length;
	PIMPORT_FN functions;
}IMPORT_LIB, *PIMPORT_LIB;

typedef struct _PE_FILE_HEADERS_STRUCT { // get data, without memory mapped
	IMAGE_DOS_HEADER fIMAGE_DOS_HEADER;
	IMAGE_NT_HEADERS fIMAGE_NT_HEADERS;
}PE_FILE_HEADERS_STRUCT, *PPE_FILE_HEADERS_STRUCT;

typedef	std::vector<EXPORT_FN>		ExportedFunsArray;
typedef ExportedFunsArray::iterator expfn_iter;
typedef std::pair<expfn_iter, expfn_iter> expfn_iter_pair;

typedef	std::vector<PIMPORT_LIB>	ImpFunPtrs;
typedef	std::map<char*, ImpFunPtrs>	ImpLibsMap;

// First time I will use list container, in a future it will be multimap or hash_set
typedef std::pair<IMPORT_LIB, std::list<IMPORT_FN> > IMPORTLIB_PAIR, *PIMPORTLIB_PAIR;
typedef std::list<IMPORTLIB_PAIR> DEPENDENT_LIBS, *PDEPENDENT_LIBS;

struct AsciiStrLess: public std::binary_function<const char*, const char*, bool>
{
	bool operator()(const char* pstr1, const char* pstr2) const
	{
		if(pstr1 && pstr2)
			return strlen(pstr1)<strlen(pstr2);
		else 
			return false;
	}
};

struct CmpExpByName: public std::binary_function<EXPORT_FN, const char*, bool>
{
	bool operator()(EXPORT_FN& fn, const char* name) const{
		return CBase::kstrcmp(fn.Name, name) == 0;
	}
};

struct CmpExpByAddr: public std::binary_function<EXPORT_FN, const PVOID, bool>
{
	bool operator()(EXPORT_FN& fn, const PVOID ptrFn) const{
		return fn.Api == ptrFn;
	}
};

struct CmpExpByOrdinal: public std::binary_function<EXPORT_FN, DWORD, bool>
{
	bool operator()(EXPORT_FN& fn, DWORD ordinal) const{
		return fn.Ordinal == ordinal;
	}
};

// This class assigned with a PortableExecutable file on a disc or memory
class PeFile: protected CBase {
public:
	PeFile();
	PeFile(const char*, unsigned char = 0); // use file mapping
	PeFile(PVOID, DWORD = 1, unsigned char = 0);

	PeFile* Load(const char*, unsigned char = 0);
	PeFile* Load(PVOID, DWORD = 1, unsigned char = 0);

	PIMPORT_LIB GetImport(ulong*) const;
	PEXPORT_FN GetExportApi(ulong*) const;

	PIMAGE_NT_HEADERS GetImageNtHeaders(void) const;
	PIMAGE_NT_HEADERS GetImageNtHeadersByFile(void) const;

	PVOID GetExportedFn(const char*) const;
	PVOID GetExportedFn(const WORD) const;
	char* GetExportedFn(const PVOID) const;

	PVOID GetImportedFn(__in const char*) const;
	char* GetImportedFn(__in const PVOID) const;

	// Receives empty container and fills information about all exported functions
	// Container consists of pointers to the EXPORTED_FN structures,
	// these structures will be in the valid state while a PeFile object which has returned them is loaded
	void Make_ExpFunPtrs(__out ExportedFunsArray exported_fns) const;
	ExportedFunsArray Make_ExpFunPtrs() const;

	// Returns information about exported function by its name
	PEXPORT_FN GetExportedFnInfo(const char* szFnName) const;

	// Returns information about imported function by its name
	PIMPORT_FN GetImportedFnInfo(const char* szFnName) const;

	// Returns pointer to the array of pointers to the sections headers
	PIMAGE_SECTION_HEADER* GetSections(__out const PWORD ptrLength) const;

	// Returns information about imported function by lib name and function name
	PIMPORT_FN GetImportedFnInfo(__in const char* szLib, __in const char* szFnName) const;

	const char* GetFilePath() const;

	void SetError(unsigned char);

	void Destroy();

	unsigned char GetError(void) const{
		return(m_error_flag);
	}

	PVOID GetBaseX(void) const {
		return(m_base_x); 
	};

	PVOID GetMapX(void) const {
		return(m_map_x); 
	};

	BOOL UseMap(void) const {
		return(m_use_map);
	};

	bool OtherProcess() const {
		return(m_otherProcess);
	}

	HANDLE ProcessHandle() const {
		return m_hProcess;
	}

	DWORD Pid() const {
		return m_dwPid;
	}

	~PeFile();

private:
	// General information

	// This flag is set when we work in context of different process
	bool m_otherProcess;
	DWORD m_dwPid;
	HANDLE m_hProcess;
	DWORD m_dwSizeHeaders; // size IMAGE_NT_HEADERS
	LONG m_e_lfanew; // offset to header
	DWORD m_SizeOptHeader; // size of optional header

	// Data which were read from memory after loading a module
	PIMAGE_NT_HEADERS m_pImageNtHeader;

	// Data which were read from a file on disk 
	PIMAGE_NT_HEADERS m_pfImageNtHeader;

	// Information about export section
	PEXPORT_FN m_export;
	ulong m_export_length;
	//ExpFunPtrs m_export_vec;

	// Information about import section
	PIMPORT_LIB m_import;
	ulong m_import_length;

	// section
	WORD m_countSections;
	PIMAGE_SECTION_HEADER *m_pSectionHeaders;

	// base address
	PVOID m_base_x;

	// information about mapping
	BOOL m_use_map;
	PVOID m_map_x; // address reflection
	HANDLE m_hfile; // handle of file
	HANDLE m_hmap; // handle of filemapping

	// error bitset, 0x00 is success
	unsigned char m_error_flag;

	// Full path to the file on disk, It is necessary that to read image file header from file
	char* m_szPeFile;

	// temporary buffer for work with strings
	// note(!): doesn't work with multi threading
	char m_StrTmpBuf[TEMP_STRING_SIZE];

protected:

	void print(char* s) {
		printf(s);
	}

private:
	bool load_pe_file(const char*);
	bool export_init(void);
	bool import_init(ulong* = NULL);
	bool section_init(void);
	bool BasicValidation(PVOID);
	void setValToNull(void);
	bool ReadNtHeadersByFile(char* szFile);
	bool InitBase(DWORD pid, PVOID pImageBase);
	PVOID readAndAlloc(PVOID readFrom, PVOID pBuf, SIZE_T bufSize) const;
	PVOID readAndAlloc(PVOID readFrom, SIZE_T bufSize) const;
	void Initialize(unsigned char f);
	BOOL getInfAboutString(__inout pmregion pcstr) const;
	char* CreateCopyAnsiString(char* pstr);
	ulong get_count_of_dependency_libs();
	//bool delay_import_init(void);
};

#endif // PE_H
