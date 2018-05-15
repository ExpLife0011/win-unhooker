
//      (c)VsoftLab 2006 - 2013
//		Author: burluckij@gmail.com	


#include "PE.h"

using namespace Memory;

//#define get_header_addr(hModule)		(void*)(hModule + (((PIMAGE_DOS_HEADER)hModule)->e_lfanew))
#define get_header_addr(x)				(m_pImageNtHeader)
#define lvar(x, y)						(readAndAlloc(x, y, sizeof(y)))

PeFile::PeFile(const char* szFile, unsigned char f)
{
	setValToNull();
	this->Load(szFile, f);
}

PeFile::PeFile(PVOID pModule, DWORD pid, unsigned char f)
{
	setValToNull();

	if(pid == 1)
		pid = GetCurrentProcessId();

	this->Load(pModule,  pid, f);
}

// Here I have to get: ProcessId, Offset to IMAGE_NT_HEADER and header itself
// before thatQ need to do basic validation on PE format
bool PeFile::InitBase(DWORD pid, PVOID pImage)
{
	bool result = FALSE;
	WORD tmp_word = 0;
	DWORD bRead = 0;
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;

	if(this->m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid))
	{
		// read IMAGE_DOS_SIGNATURE and compare it
		bool mem_was_read = ReadProcessMemory(this->m_hProcess, pImage, &tmp_word, sizeof(WORD), &bRead);
		if(!(mem_was_read && (tmp_word == IMAGE_DOS_SIGNATURE)))
			return FALSE;

		pImageDosHeader = (PIMAGE_DOS_HEADER)getmem(sizeof(IMAGE_DOS_HEADER));
		if(pImageDosHeader)
		{
			if(ReadProcessMemory(this->m_hProcess, pImage, pImageDosHeader, sizeof(IMAGE_DOS_HEADER), &bRead))
			{
				m_pImageNtHeader = (PIMAGE_NT_HEADERS)readAndAlloc(
					(PVOID)(pImageDosHeader->e_lfanew + (DWORD)pImage),
					sizeof(IMAGE_NT_HEADERS));

				m_e_lfanew = pImageDosHeader->e_lfanew;
				result = TRUE;
			}

			freemem(pImageDosHeader);
		}
	} else {
#ifdef _DEBUG
			__asm int 3;
#endif
		//printf("%d error access\n", pid);
	}
#ifdef _DEBUG
	if(result != true)
	{
		__asm int 3;
	}
#endif

	return result;
}

// Note(!): need improve validation of PExe file
PeFile* PeFile::Load(const char* szFile, unsigned char f)
{
	DWORD NeedSize = 0;
	PVOID pData = NULL;
	DWORD my = 0;

	// Validation();
	if((m_use_map = load_pe_file(szFile)) && InitBase(GetCurrentProcessId(), GetMapX()) && BasicValidation(GetMapX()))
	{
		m_szPeFile = (char*)getmem(strlen(szFile)+1);
		kstrcpy(m_szPeFile, szFile);
		m_base_x = (PVOID)m_pImageNtHeader->OptionalHeader.ImageBase;
		Initialize(f);	
	} else {
		SetError(CRASH_INIT);
	}

	return this;
}

// Note(!): need improve validation of PExe file
PeFile* PeFile::Load(PVOID pModule, DWORD pid, unsigned char f)
{
	DWORD NeedSize = 0;
	PVOID pData = NULL;
	WORD wtemp = 0;
	DWORD dwtemp = 0;

	if(pid == 1)
		pid = GetCurrentProcessId();

	if(pModule)
	{
		if(/*Validation() &&*/InitBase(pid, pModule))
		{
			m_dwPid = pid;
			this->m_base_x = pModule;
			m_szPeFile = (char*)getmem(MAX_PATH);
			if(!GetModuleFileNameExA(this->m_hProcess, (HMODULE)pModule, m_szPeFile, MAX_PATH))
			{
				print("get file name: error\n");
			}
			Initialize(f);
		} else
		{
			SetError(CRASH_INIT);
		}
	}

	return this;
}

void PeFile::Initialize(unsigned char f)
{
	if(!ReadNtHeadersByFile(m_szPeFile))
		SetError(HEADER_ERROR);

	if(!(f&IMPORT_ERROR) && !import_init())
		SetError(IMPORT_ERROR);

	if(!(f&EXPORT_ERROR) && !export_init())
		SetError(EXPORT_ERROR);

	if(!(f&SECTION_ERROR) && !section_init())
		SetError(SECTION_ERROR);
}

// Can't point right to the sections (because it may be a different process),
// need create private copies of the section headers after that create array of pointers and than
// refer the pointers to the own copies of the section's headers 
bool PeFile::section_init()
{
	DWORD sizeOptionHeader = m_pImageNtHeader->FileHeader.SizeOfOptionalHeader;
	DWORD offsetToSections = this->m_e_lfanew + sizeof(IMAGE_FILE_HEADER) + sizeOptionHeader + sizeof(DWORD);
	PVOID p = m_use_map? m_map_x: m_base_x;
	PVOID pSections = (PVOID)((DWORD)p + offsetToSections);
	m_countSections = m_pImageNtHeader->FileHeader.NumberOfSections;

	// create own array of pointers to the sections
	m_pSectionHeaders = (PIMAGE_SECTION_HEADER*)getmem(sizeof(PIMAGE_SECTION_HEADER)*m_countSections);

	if(!m_pSectionHeaders){
		return FALSE;
	} 

	// init the pointers by the sections
	for(int i=0; i<m_countSections; i++)
	{
		m_pSectionHeaders[i] = (PIMAGE_SECTION_HEADER)readAndAlloc((PVOID)((DWORD)pSections + sizeof(IMAGE_SECTION_HEADER)*i), 
			getmem(sizeof(IMAGE_SECTION_HEADER)), sizeof(IMAGE_SECTION_HEADER));
	}

	return TRUE;
}

PIMAGE_NT_HEADERS PeFile::GetImageNtHeaders(void) const
{
	return m_pImageNtHeader;
}

bool PeFile::load_pe_file(const char* szFile)
{
	HANDLE file = INVALID_HANDLE_VALUE, mapping = 0;
	PVOID pmap = NULL;
	DWORD base = 0, count=0, out_buf_size=0;

	if(!szFile)
		return FALSE;

	file = CreateFileA(szFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0,0);
	if (file == INVALID_HANDLE_VALUE)
		return FALSE;

	if(GetFileSize(file,0)<MIN_FILE_SIZE)
	{
		CloseHandle(file);
		return FALSE;
	}

	mapping = CreateFileMapping(file, 0, PAGE_READONLY|SEC_IMAGE, 0, 0, NULL);
	if (!mapping)
	{
		CloseHandle(file);
		return FALSE;
	}

	pmap = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
	if (!pmap)
	{
		CloseHandle(mapping);
		CloseHandle(file);
		return FALSE;
	}

	// everything is ok, have to save state
	m_map_x = pmap;
	m_hfile = file;
	m_hmap = mapping;
	return TRUE;
}

// Get info about functions which exported by names
bool PeFile::export_init(void)
{
	PIMAGE_EXPORT_DIRECTORY pExportTable = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;
	PDWORD AddressOfNames = NULL, AddressOfFunctions = NULL, pt4Bytes = NULL;
	PWORD AddressOfNameOrdinals = NULL;
	DWORD vaStartExport = 0, vaEndExport = 0, BaseAddress = (DWORD)(UseMap()?m_map_x:m_base_x);
	PEXPORT_FN ptrExportFn = NULL;
	DWORD t4b = 0;
	WORD t2b = 0;
	char* szstr = NULL;

	pOptionalHeader = &m_pImageNtHeader->OptionalHeader;

	// is this export table?
	if(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
	{
		// формируем адреса
		/*pExportTable = (PIMAGE_EXPORT_DIRECTORY)(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress																										+BaseAddress);*/ 
		PVOID pExportTable_original = (PVOID)(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress+BaseAddress);
		pExportTable = (PIMAGE_EXPORT_DIRECTORY)readAndAlloc(pExportTable_original, sizeof(IMAGE_EXPORT_DIRECTORY));
		if(!pExportTable)
			return FALSE;

		AddressOfNameOrdinals = (PWORD)(BaseAddress+pExportTable->AddressOfNameOrdinals);
		AddressOfFunctions = (PDWORD)(BaseAddress+pExportTable->AddressOfFunctions);
		AddressOfNames = (PDWORD)(BaseAddress+pExportTable->AddressOfNames);
		
		this->m_export_length = pExportTable->NumberOfNames;

		// get space size
		vaStartExport = (DWORD)pExportTable_original; 
		vaEndExport = (DWORD)pExportTable_original + (DWORD)pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

		// Alloc memory for structures with information about all exported functions
		ptrExportFn = (PEXPORT_FN)getmem(m_export_length*sizeof(EXPORT_FN));
		if(!ptrExportFn)
		{
			freemem(pExportTable);
			return FALSE;
		}

		// Save pointer to the array of exported functions
		m_export = ptrExportFn;

		//if(!m_export_vec.empty())
		//	m_export_vec.clear();

		// Reserve memory for pointers to the all exported functions
		//m_export_vec.reserve(m_export_length);

		for(WORD count=0; count < pExportTable->NumberOfNames; count++, ptrExportFn++)
		{
			// 1. get ordinal
			// pExportInfo->Ordinal = AddressOfNameOrdinals[count]+pExportTable->Base;
			// сделать ПРОВЕРКИ результатов readAndAlloc для полного счастья !!!!!
			readAndAlloc((AddressOfNameOrdinals + count), &ptrExportFn->Ordinal, sizeof(WORD));
			ptrExportFn->Ordinal += pExportTable->Base;

			// 2. get function address
			// pExportInfo->Api = (PVOID)((DWORD)BaseAddress+(AddressOfFunctions)[AddressOfNameOrdinals[count]]);
			readAndAlloc((AddressOfNameOrdinals + count), &t2b, sizeof(WORD));
			readAndAlloc((AddressOfFunctions + t2b), &t4b, sizeof(DWORD));
			ptrExportFn->Api = (PVOID)(BaseAddress + t4b);

			// 3. create ascii string with function name
			//ptrExportFn->Name = (char*)(PVOID)(BaseAddress+(AddressOfNames)[count]);
			if(pt4Bytes = (PDWORD)readAndAlloc((AddressOfNames + count), &t4b, sizeof(DWORD))){
				ptrExportFn->Name = CreateCopyAnsiString((char*)(BaseAddress + *pt4Bytes));
			}

			// Is It forwarding?
			if ((vaStartExport<=(DWORD)ptrExportFn->Api) && ((DWORD)ptrExportFn->Api<=vaEndExport))
			{
				ptrExportFn->forward_ = (PVOID)(DWORD)ptrExportFn->Api;
			}else
			{
				ptrExportFn->forward_ = 0;
			}

			// Save pointer to the information about exported function
			//this->m_expfn_container.push_back(pExportInfo);
		}

		// Don't forget it!
		freemem(pExportTable);

		// Sort vector by field - '.Name'
		//std::sort(m_expfn_container.begin(), m_expfn_container.end(), ExpFnLess_Name());

	} else 
	{
		m_export_length = 0;
		m_export = NULL;
	}

	return TRUE;
}

// condition - Is the import structure right?
bool imp_predicate(PDWORD pfnAddr, PDWORD pfnNames)
{
	BOOL result = TRUE;

	// the situations are not typical, skip it
	if((pfnAddr == NULL) || (pfnNames == NULL))
	{
		result = FALSE;
	} else if(pfnAddr == pfnNames)
	{
		result = FALSE;
		// result = true;
	}

	return result;
}

ulong PeFile::get_count_of_dependency_libs()
{
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = NULL,  pPrivateCopy_ImportTbl = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	DWORD BaseAddress = (DWORD)(UseMap()?m_map_x:m_base_x);
	ulong count_of_imported_libs = 0;

	pOptionHeader = &m_pImageNtHeader->OptionalHeader;
	pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (DWORD)BaseAddress);
	if(BaseAddress == (DWORD)pImportTable)
		return 0;

	// read first table
	pPrivateCopy_ImportTbl = (PIMAGE_IMPORT_DESCRIPTOR)readAndAlloc(pImportTable, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	if(!pPrivateCopy_ImportTbl)
		return 0;

	// enumerate dependency libraries
	while(pPrivateCopy_ImportTbl->Characteristics)
	{
		bool right_imp = imp_predicate( (PDWORD)(pPrivateCopy_ImportTbl->FirstThunk+BaseAddress),
			(PDWORD)(pPrivateCopy_ImportTbl->OriginalFirstThunk+BaseAddress));

		if(right_imp)
			count_of_imported_libs++;
		
		if(!readAndAlloc(++pImportTable, pPrivateCopy_ImportTbl, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
			break;
	}

	freemem(pPrivateCopy_ImportTbl);
	return count_of_imported_libs;
}

// !!! very dangerous, but it works. I'll fix it later..
// bug(!): should use common condition when I enumerate(count) imported libraries 
bool PeFile::import_init(ulong* pfunctionCount)
{
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = NULL,  pPrivateCopy_ImportTbl = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	DWORD impSize = 0, t4b = 0, BaseAddress = (DWORD)(UseMap()?m_map_x:m_base_x);
	PDWORD pfnImportAddr = NULL, pfnNames = NULL;
	ulong count_of_imported_libs = 0;
	PIMPORT_LIB pInfoImportAboutLibraries = NULL;
	PIMPORT_FN pfnInfo = NULL;
	BOOL right_imp = TRUE;
	
	// STEP 1: get count of import libs
	ulong dep_libs_n = get_count_of_dependency_libs();
	if(dep_libs_n == 0)
		return TRUE;

	m_import = (PIMPORT_LIB)Memory::getmem(dep_libs_n*sizeof(IMPORT_LIB));
	if(!m_import) 
		return FALSE;
	
	ZeroMemory(m_import, dep_libs_n*sizeof(IMPORT_LIB));
	
	pInfoImportAboutLibraries = m_import;
	m_import_length = dep_libs_n;

	pOptionHeader = &m_pImageNtHeader->OptionalHeader;
	pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress+
		(DWORD)BaseAddress);
	impSize = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

	// Read first table
	pPrivateCopy_ImportTbl = (PIMAGE_IMPORT_DESCRIPTOR)readAndAlloc(pImportTable, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	if(!pPrivateCopy_ImportTbl)
		return FALSE;

	// Enumerate libraries
	while(pPrivateCopy_ImportTbl->Characteristics)
	{
		// array of functions
		pfnImportAddr = (PDWORD)(pPrivateCopy_ImportTbl->FirstThunk+BaseAddress);

		// array of names
		pfnNames = (PDWORD)(pPrivateCopy_ImportTbl->OriginalFirstThunk+BaseAddress);
		
		// Condition.
		right_imp = imp_predicate(pfnImportAddr, pfnNames);

		// Enumerate functions and get information about them
		if(right_imp)
		{
			PDWORD pt4b = NULL;
			while((pt4b = (PDWORD)readAndAlloc(pfnImportAddr, &t4b, sizeof(t4b))) && *pt4b)
			{
				BOOL insert = false;
				if(pfnInfo = (PIMPORT_FN)getmem(sizeof(IMPORT_FN)))
				{
					//pApiInfo->Api = (PVOID)*pImportFunction;
					//pt4b = (PDWORD)readAndAlloc(pfnImportAddr, &t4b, sizeof(t4b));
					pfnInfo->Api = (PVOID)(*pt4b); // api_address
					pfnInfo->AddrFuncAddr = pfnImportAddr; // &api_address
					if(pt4b = (PDWORD)readAndAlloc(pfnNames, &t4b, sizeof(t4b)))
					{						
						if((*pt4b)&IMAGE_ORDINAL_FLAG32)
						{
							pfnInfo->ApiName = NULL;
							pfnInfo->Ordinal = *pt4b;
						} else
						{
							// ApiName field can be NULL, I skiped it
							pfnInfo->ApiName = CreateCopyAnsiString((char*)(*pt4b+BaseAddress+sizeof(WORD)));
							pfnInfo->Ordinal = 0;
						}

						insert = true;
					}

					if(insert)
					{ // everything is ok
						pInfoImportAboutLibraries->length++;
						pfnInfo->next = NULL;
						if(pInfoImportAboutLibraries->functions == NULL)
						{
							pInfoImportAboutLibraries->functions = pfnInfo;
						} else
						{
							pfnInfo->next = pInfoImportAboutLibraries->functions;
							pInfoImportAboutLibraries->functions = pfnInfo;
						}
					} else
					{
						freemem(pfnInfo);
					}
				}

				// next iteration
				pfnImportAddr++, pfnNames++, t4b = 0;
			}

			// get next memory block for IMPORT_LIB structure
			pInfoImportAboutLibraries->szLib = CreateCopyAnsiString((char*)(pPrivateCopy_ImportTbl->Name + BaseAddress));
			pInfoImportAboutLibraries++;
		}

		// go to next library and fill it
		if(!readAndAlloc(++pImportTable, pPrivateCopy_ImportTbl, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
			break;
	}

	freemem(pPrivateCopy_ImportTbl);
	return TRUE;
}

// Чтение региона памяти размером <= TEMP_STRING_SIZE, используется для
// сокращения вызовов системного api чтения памяти
BOOL PeFile::getInfAboutString(__inout pmregion pcstr) const
{
	MEMORY_BASIC_INFORMATION meminf;

	if(VirtualQueryEx(this->m_hProcess, pcstr->p, &meminf, sizeof(meminf)))
		if((meminf.State == MEM_COMMIT))
		{
			pcstr->rsize = (DWORD)meminf.RegionSize - ((DWORD)pcstr->p - (DWORD)meminf.BaseAddress);
			return TRUE;
		}

	return FALSE;
}

char* PeFile::CreateCopyAnsiString(char* pstr)
{///!!!!!!!!!!!!!!!!!!!!!!
	char* resultString = NULL;
	ulong i=0, region_size = 0;
	mregion smem = {0};
	smem.p = pstr;

	if(getInfAboutString(&smem))
	{
		region_size = smem.rsize<TEMP_STRING_SIZE?smem.rsize:TEMP_STRING_SIZE;

		// read full page
		if(readAndAlloc(pstr, m_StrTmpBuf, region_size))
		{
			// read only one string from page buffer
			for(i = 0; i<region_size && m_StrTmpBuf[i]; i++);

			if(!m_StrTmpBuf[i])
				if(resultString = (char*)getmem(i+1))
					strcpy(resultString, m_StrTmpBuf);
		}
	}

	return resultString;
}

void PeFile::SetError(unsigned char err_code)
{
	m_error_flag |= err_code;

	switch(err_code)
	{
	case SECTION_ERROR:
		print("\r\r pe_file::pe_file@section_init: error");
		break;
	case IMPORT_ERROR:
		print("\r\r pe_file::pe_file@import_info: error\n");
		break;
	case EXPORT_ERROR:
		print("\r\r pe_file::pe_file@export_info: error\n");
		break;
	case CRASH_INIT:
		print("\r\r crash!\n");
		break;
	}
}

bool PeFile::BasicValidation(PVOID pfile)
{
	WORD wSign = 0;
	DWORD dwSign = 0;

	if(pfile)
	{
		readAndAlloc(pfile, &wSign, sizeof(WORD));
		readAndAlloc(get_header_addr(0), &dwSign, sizeof(DWORD));
		return ((dwSign == IMAGE_NT_SIGNATURE) && (wSign == IMAGE_DOS_SIGNATURE));
	}

	return false;
}

PIMAGE_NT_HEADERS PeFile::GetImageNtHeadersByFile() const
{
	return m_pfImageNtHeader;
}

bool PeFile::ReadNtHeadersByFile(char* szFile)
{
	HANDLE file = INVALID_HANDLE_VALUE;
	DWORD dwReadSize = 0, dwOffset = 0;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)getmem(sizeof(IMAGE_DOS_HEADER));
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)getmem(sizeof(IMAGE_NT_HEADERS));
	BOOL result = FALSE;

	if(szFile)
	{
		file = CreateFileA(szFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0,0);
		if (file != INVALID_HANDLE_VALUE)
		{
			if(GetFileSize(file,0)>MIN_FILE_SIZE)
			{
				if(ReadFile(file, pDosHeader, sizeof(IMAGE_DOS_HEADER), &dwReadSize, NULL))
				{
					dwOffset = pDosHeader->e_lfanew;
					if(SetFilePointer(file,(LONG)dwOffset,NULL,0)!=INVALID_SET_FILE_POINTER)
					{
						if(ReadFile(file, pNtHeader, sizeof(IMAGE_NT_HEADERS), &dwReadSize, NULL))
						{
							m_pfImageNtHeader = pNtHeader;
							result = TRUE;
						}
					}
				}
			}

			CloseHandle(file);
		}
	}

	if(!result)
		freemem(pNtHeader);

	freemem(pDosHeader);
	return result;
}

const char* PeFile::GetFilePath() const
{
	return m_szPeFile;
}

PVOID PeFile::GetExportedFn(const char* szName) const
{
// 	ulong i = 0, count_api = 0;
// 	PEXPORT_FN p = GetExportApi(&count_api);
// 
// 	if(count_api){
// 		for(i=0; i<count_api; p++, i++){
// 			if(kstrcmp(szName, p->Name)==0)
// 				return p->Api;
// 		}
// 	}
// 
// 	return NULL;

	PEXPORT_FN ptrExpFn = std::find_if(m_export, (m_export+m_export_length), std::bind2nd(CmpExpByName(), szName));
	
	if(ptrExpFn != (m_export+m_export_length))
		return ptrExpFn->Api;
	else 
		return NULL;
}

PVOID PeFile::GetExportedFn(const WORD ordinal) const
{
// 	ulong i = 0, count_api = 0;
// 	PEXPORT_FN p = GetExportApi(&count_api);
// 
// 	if(count_api){
// 		for(i=0; i<count_api; p++, i++){
// 			if(p->Ordinal == ordinal){
// 				return p->Api;
// 			}
// 		}
// 	}
// 
// 	return NULL;

	PEXPORT_FN ptrExpFn = std::find_if(m_export, (m_export+m_export_length), std::bind2nd(CmpExpByOrdinal(), ordinal));

	if(ptrExpFn != (m_export+m_export_length))
		return ptrExpFn->Api;
	else 
		return NULL;
}

char* PeFile::GetExportedFn(const PVOID api) const
{
// 	ulong i = 0, count_api = 0;
// 	PEXPORT_FN p = GetExportApi(&count_api);
// 
// 	if(count_api){
// 		for(i=0; i<count_api; p++, i++){
// 			if(p->Api == api){
// 				return p->Name;
// 			}
// 		}
// 	}
// 
// 	return NULL;

	PEXPORT_FN ptrExpFn = std::find_if(m_export, (m_export+m_export_length), std::bind2nd(CmpExpByAddr(), api));

	if(ptrExpFn != (m_export+m_export_length))
		return ptrExpFn->Name;
	else 
		return NULL;
}

// PEXPORT_FN PeFile::GetExportedFnInfo(const char* szName) const
// {
// 	if(m_export_length)
// 	{
// 		EXPORT_FN srch;
// 		srch.Name = const_cast<char*>(szName);
// 
// 		std::pair<const PEXPORT_FN, const PEXPORT_FN> range = equal_range(m_export, (m_export+m_export_length),
// 			srch, ExpFnLess_Name());
// 		
// 		if(range.first != range.second)
// 		{
// 			return range.first;
// 		}
// 	}
// 
// 	return NULL;
// }

PEXPORT_FN PeFile::GetExportedFnInfo(const char* szName) const
{
// 	ulong i = 0, count_api = 0;
// 	PEXPORT_FN p = GetExportApi(&count_api);
// 
// 	if(count_api && p){
// 		for(i=0; i<count_api; p++, i++){
// 			if(kstrcmp(szName, p->Name)==0){
// 				return p;
// 			}
// 		}
// 	}
// 
// 	return NULL;

	PEXPORT_FN ptrExpFn = std::find_if(m_export, (m_export+m_export_length), std::bind2nd(CmpExpByName(), szName));

	if(ptrExpFn != (m_export+m_export_length))
		return ptrExpFn;
	else 
		return NULL;
}

PVOID PeFile::GetImportedFn(const char* szName) const
{
	PIMPORT_FN pfn = NULL;
	PIMPORT_LIB plib = this->m_import;

	if(plib) {
		for(ulong i = 0; i<m_import_length; i++, plib++){
			for(pfn=plib->functions; pfn != NULL;pfn=pfn->next){
				if(kstrcmp(pfn->ApiName, szName)==0) {
					return pfn->Api;
				}
			}
		}
	}

	return NULL;
}

char* PeFile::GetImportedFn(const PVOID api) const
{
	PIMPORT_FN pfn = NULL;
	PIMPORT_LIB plib = NULL;

	plib = this->m_import;

	for(ulong i = 0; i<m_import_length; i++, plib++){
		for(pfn=plib->functions; pfn != NULL;pfn=pfn->next){
			if(pfn->Api == api)
				return pfn->ApiName;
		}
	}

	return NULL;
}

PIMPORT_FN PeFile::GetImportedFnInfo(const char* szName) const
{
	PIMPORT_FN pfn = NULL;
	PIMPORT_LIB plib = NULL;

	plib = this->m_import;

	for(ulong i = 0; i<m_import_length; i++, plib++){
		for(pfn=plib->functions; pfn != NULL; pfn=pfn->next){
			if(kstrcmp(pfn->ApiName, szName) == 0) {
				return pfn;
			}
		}
	}

	return NULL;
}

PIMPORT_FN PeFile::GetImportedFnInfo(const char* szLib, const char* szName) const
{
	PIMPORT_FN pfn = NULL;
	PIMPORT_LIB plib = NULL;

	plib = this->m_import;

	for(ulong i = 0; i<m_import_length; i++, plib++)
	{
		if(kstrcmp(plib->szLib, szLib) == 0)
		{
			for(pfn=plib->functions; pfn != NULL;pfn=pfn->next)
			{
				if(kstrcmp(pfn->ApiName, szName)==0) {
					return pfn;
				}
			}
		}
	}

	return NULL;
}

PIMAGE_SECTION_HEADER* PeFile::GetSections(PWORD count) const
{
	if(count)
	{
		*count = m_countSections;
		return m_pSectionHeaders;
	} else
	{
		return NULL;
	}
}

PIMPORT_LIB PeFile::GetImport(ulong* pCount) const
{
	if (pCount)
	{
		*pCount = m_import_length;
		return this->m_import;
	} else
	{
		return NULL;
	}
}

PEXPORT_FN PeFile::GetExportApi(ulong* pCount) const
{
	if(pCount)
	{
		*pCount = m_export_length;
		return m_export;
	} else
	{
		return NULL;
	}
}

void PeFile::setValToNull()
{
	m_pImageNtHeader = NULL;
	m_pfImageNtHeader = NULL;
	m_export_length = 0;
	m_export = NULL;
	m_countSections = NULL;
	m_pSectionHeaders = NULL;
	m_base_x = NULL;
	m_use_map = false;
	m_map_x = NULL; //
	m_hfile = NULL; //
	m_hmap = NULL; // handle of map
	m_error_flag = 0; // 0x00 is success
	m_szPeFile = NULL;
	m_hProcess = NULL;
	m_import = NULL;
	m_import_length = NULL;
}

PVOID PeFile::readAndAlloc(PVOID readFrom, SIZE_T bufSize) const
{
	return readAndAlloc(readFrom, getmem(bufSize), bufSize);
}

PVOID PeFile::readAndAlloc(PVOID readFrom, PVOID pBuf, SIZE_T bufSize) const
{
	DWORD temp = 0;
	return ReadProcessMemory(this->m_hProcess, readFrom, pBuf, bufSize, &temp)?pBuf:NULL;
}

PeFile::PeFile()
{
	setValToNull();
}

PeFile::~PeFile(void)
{
	Destroy();
}

void PeFile::Destroy()
{
	PIMPORT_FN pfn = NULL, t = NULL;
	PIMPORT_LIB plib = NULL;

	// Delete info about sections
	for(int i=0; i<m_countSections; i++)
		freemem(m_pSectionHeaders[i]);

	freemem(m_pSectionHeaders);

	// Full path the file on the disk
	if(m_szPeFile)
		freemem(m_szPeFile);

	// array of export structures
	if(m_export_length)
	{
		for(int i=0; i<m_export_length; i++)
			freemem(m_export[i].Name);

		freemem(m_export);
	}

	// Array with import structures
	if(this->m_import_length)
	{
		plib = this->m_import;
		for(ulong i = 0; i<m_import_length; i++, plib++)
		{
			freemem(plib->szLib);
			for(pfn=plib->functions; pfn != NULL;)
			{
				freemem(pfn->ApiName);
				t = pfn;
				pfn = pfn->next;
				freemem(t);
			}
		}

		freemem(this->m_import);
	}

	// Header which was read from disk
	if(m_pfImageNtHeader) 
		freemem(m_pfImageNtHeader);

	// Header which was read from memory
	if(m_pImageNtHeader)
		freemem(m_pImageNtHeader);

	// free mem and close map
	if (m_use_map)
	{
		m_use_map = false;
		UnmapViewOfFile(m_map_x);
		CloseHandle(m_hmap);
		CloseHandle(m_hfile);
	}

	if(m_hProcess != INVALID_HANDLE_VALUE)
		CloseHandle(this->m_hProcess);
}

void PeFile::Make_ExpFunPtrs(__out ExportedFunsArray exp_fns) const
{
	if(!exp_fns.empty())
	{
		exp_fns.clear();
		//ExpFunPtrs().swap(exp_fns);
	}

	exp_fns.reserve(m_export_length);
	exp_fns.assign(m_export, m_export+m_export_length);
}

ExportedFunsArray PeFile::Make_ExpFunPtrs() const
{
	return ExportedFunsArray(m_export, (m_export + m_export_length));
}

// end