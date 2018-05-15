/**********************************************************************
 * (c) Vsoft Lab
 * e-mail: burluckij@gmail.com
 **********************************************************************/

#include "ntddk.h"
#include "stdio.h"
#include "stdlib.h"

#include "client0.h"
#include "w32.h"
#include "kstr.h"

//#define get_header_addr(hModule)		(void*)(hModule + (((PIMAGE_DOS_HEADER)hModule)->e_lfanew))
#define get_header_addr(x)				(m_pImageNtHeader)
#define lvar(x, y)						(readAndAlloc(x, y, sizeof(y)))


int InitBase(PEXE_FILE pexefile, PVOID pImage)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pImage;

	if (!pImage){
		return 0;
	}

	if (*((PWORD)pImage) != IMAGE_DOS_SIGNATURE)
		return 0;

	// (PVOID)(pImageDosHeader->e_lfanew + (DWORD)pImage)
	memset(pexefile, 0, sizeof(EXE_FILE));
	pexefile->m_base_x = pImage;
	pexefile->m_pImageNtHeader = (PIMAGE_NT_HEADERS)(pImageDosHeader->e_lfanew + (DWORD)pImage);
	pexefile->m_e_lfanew = pImageDosHeader->e_lfanew;

	return 1;
}


// Note(!): need improve validation of PExe file
EXE_FILE Load(PVOID pModule, unsigned char f)
{
	EXE_FILE exe_file;
	exe_file.m_error_flag = CRASH_INIT;


	if (pModule)
	{
		if (/*Validation() &&*/InitBase(&exe_file, pModule))
		{
			//exe_file.m_base_x = pModule;

			// init something ...
		}
	}

	return exe_file;
}

// Without allocating memory for private copies of sections
int InitSection(PEXE_FILE pexefile)
{
	DWORD sizeOptionHeader = pexefile->m_pImageNtHeader->FileHeader.SizeOfOptionalHeader;
	DWORD offsetToSections = pexefile->m_e_lfanew + sizeof(IMAGE_FILE_HEADER)+sizeOptionHeader + sizeof(DWORD);
	PVOID p = pexefile->m_base_x;
	PVOID pSections = (PVOID)((DWORD)p + offsetToSections);

	pexefile->m_countSections = pexefile->m_pImageNtHeader->FileHeader.NumberOfSections;

	// create own array of pointers to the sections
	pexefile->m_pSectionHeaders = (PIMAGE_SECTION_HEADER*)PAGE_MEM(sizeof(PIMAGE_SECTION_HEADER)* pexefile->m_countSections);

	if (!pexefile->m_pSectionHeaders){
		pexefile->m_countSections = 0;
		return FALSE;
	}

	// Init the pointers
	for (int i = 0; i < pexefile->m_countSections; i++)
	{
		pexefile->m_pSectionHeaders[i] = (PIMAGE_SECTION_HEADER)((PVOID)((DWORD)pSections + sizeof(IMAGE_SECTION_HEADER)*i));
	}

	return TRUE;
}

PIMAGE_SECTION_HEADER GetSectionByAddr(PEXE_FILE pexefile, PVOID p)
{
	for (ulong i = 0; i < pexefile->m_countSections; ++i)
	{
		PIMAGE_SECTION_HEADER section = pexefile->m_pSectionHeaders[i];

		ulong begin = (ulong)section->VirtualAddress + (ulong)pexefile->m_base_x;
		ulong end = begin + section->Misc.VirtualSize;

		if (((ULONG)p >= begin) && ((ULONG)p <= end))
		{
			return section;
		}
	}

	return NULL;
}

// Get info about functions which exported by names
int InitExport(PEXE_FILE pexefile)
{
	PIMAGE_EXPORT_DIRECTORY pExportTable = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;
	PDWORD AddressOfNames = NULL, AddressOfFunctions = NULL;
	PWORD AddressOfNameOrdinals = NULL;
	DWORD vaStartExport = 0, vaEndExport = 0, BaseAddress = (DWORD)pexefile->m_base_x;

	pOptionalHeader = &pexefile->m_pImageNtHeader->OptionalHeader;

	// is this export table?
	if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
	{
		pExportTable = (PIMAGE_EXPORT_DIRECTORY)(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (DWORD)BaseAddress);
		if (!pExportTable)
			return FALSE;

		AddressOfNameOrdinals = (PWORD)(BaseAddress + pExportTable->AddressOfNameOrdinals);
		AddressOfFunctions = (PDWORD)(BaseAddress + pExportTable->AddressOfFunctions);
		AddressOfNames = (PDWORD)(BaseAddress + pExportTable->AddressOfNames);

		pexefile->m_export_length = pExportTable->NumberOfNames;

		vaStartExport = (DWORD)pExportTable;
		vaEndExport = (DWORD)pExportTable + (DWORD)pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

		// Allocates memory for structures with information about all exported functions
		PEXPORT_FN ptrExportFn = (PEXPORT_FN)PAGE_MEM(pexefile->m_export_length * sizeof(EXPORT_FN));
		if (!ptrExportFn)
		{
			//ExFreePool(pExportTable);
			pexefile->m_export_length = 0;
			return FALSE;
		}

		pexefile->m_export = ptrExportFn;

		for (WORD count = 0; count < pExportTable->NumberOfNames; count++, ptrExportFn++)
		{
			// 1. get ordinal
			ptrExportFn->Ordinal = AddressOfNameOrdinals[count] + pExportTable->Base;
			// сделать ПРОВЕРКИ результатов readAndAlloc для полного счастья !!!!!
			// readAndAlloc((AddressOfNameOrdinals + count), &ptrExportFn->Ordinal, sizeof(WORD));
			// ptrExportFn->Ordinal += pExportTable->Base;

			// 2. get function address
			ptrExportFn->addr = (PVOID)((DWORD)BaseAddress + (AddressOfFunctions)[AddressOfNameOrdinals[count]]);
			// readAndAlloc((AddressOfNameOrdinals + count), &t2b, sizeof(WORD));
			// readAndAlloc((AddressOfFunctions + t2b), &t4b, sizeof(DWORD));
			// ptrExportFn->Api = (PVOID)(BaseAddress + t4b);

			// 3. create ascii string with function name
			ptrExportFn->Name = (char*)(PVOID)(BaseAddress+(AddressOfNames)[count]);
			// if (pt4Bytes = (PDWORD)readAndAlloc((AddressOfNames + count), &t4b, sizeof(DWORD)))
			// 	ptrExportFn->Name = CreateCopyAnsiString((char*)(BaseAddress + *pt4Bytes));

			// Is It forwarding?
			if ((vaStartExport <= (DWORD)ptrExportFn->addr) && ((DWORD)ptrExportFn->addr <= vaEndExport))
				ptrExportFn->forwarding = (PVOID)(DWORD)ptrExportFn->addr;
			else
				ptrExportFn->forwarding = 0;
		}

		//ExFreePool(pExportTable);
	}
	else
	{
		pexefile->m_export_length = 0;
		pexefile->m_export = NULL;
	}

	return TRUE;
}

// condition - Is the import structure right?
int imp_predicate(PDWORD pfnAddr, PDWORD pfnNames)
{
	int result = 1;

	// the situations are not typical, skip it
	if ((pfnAddr == NULL) || (pfnNames == NULL))
	{
		DbgPrint("client0: imp_predicate cond. =  pfnAddr == NULL || pfnNames == NULL");
		result = 0;
	}
	else if (pfnAddr == pfnNames)
	{
		DbgPrint("client0: imp_predicate cond. =  pfnAddr == pfnNames");
		result = 0;
		// result = true;
	}

	return result;
}

ULONG get_count_of_dependency_libs(PEXE_FILE pexefile)
{
	DWORD BaseAddress = (DWORD)pexefile->m_base_x;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = &pexefile->m_pImageNtHeader->OptionalHeader;
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (DWORD)BaseAddress);
	ulong countImportedLibs = 0;

	if (BaseAddress == (DWORD)pImportTable){
		DbgPrint("cl0: count_dep_libs module %x cond - BaseAddress == pImportTable",
			pexefile->m_base_x);
		return 0;
	}

	if (pImportTable->Characteristics == 0)
	{
		DbgPrint("client0: ImportTable->Characteristics == 0");
	}

	// enumerate dependency libraries
	while (pImportTable->Characteristics)
	{

		DbgPrint("client0: count_dep_libs module %x for cicle", pexefile->m_base_x);

		int right_imp = imp_predicate((PDWORD)(pImportTable->FirstThunk + BaseAddress),
			(PDWORD)(pImportTable->OriginalFirstThunk + BaseAddress));

		if (right_imp != 0)
		{
			countImportedLibs++;
			DbgPrint("client0: count_dep_libs module %x countImportedLibs++ == %d",
				pexefile->m_base_x,
				countImportedLibs);
		}
		else{
			DbgPrint("client0: count_dep_libs module %x right_imp == false",
				pexefile->m_base_x);
		}

		//pImportTable++;
		++pImportTable;
	}

	return countImportedLibs;
}

// !!! very dangerous, but it works. I'll fix it later..
// bug(!): should use common condition when enumerate(count) imported libraries 
int InitImport(PEXE_FILE pexefile)
{
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	DWORD impSize = 0, BaseAddress = (DWORD)(pexefile->m_base_x);
	PDWORD pfnImportAddr = NULL, pfnNames = NULL;
	ulong count_of_imported_libs = 0;
	PIMPORT_LIB pInfoImp = NULL;
	PIMPORT_FN pfnInfo = NULL;
	int right_imp = 1;

	// STEP 1: get count of import libs
	ULONG depLibs = get_count_of_dependency_libs(pexefile);
	if (depLibs == 0){
		DbgPrint("client0: dep_libs_n == 0");
		return TRUE;
	}

	pexefile->m_import = (PIMPORT_LIB)PAGE_MEM(depLibs*sizeof(IMPORT_LIB));
	if (!pexefile->m_import)
	{
		DbgPrint("client0: !pexefile->m_import");
		return FALSE;
	}

	memset(pexefile->m_import, 0, depLibs*sizeof(IMPORT_LIB));

	pInfoImp = pexefile->m_import;
	pexefile->m_import_length = depLibs;

	pOptionHeader = &pexefile->m_pImageNtHeader->OptionalHeader;
	pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (DWORD)BaseAddress);
	impSize = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

	// Enumerate libraries
	while (pImportTable->Characteristics)
	{
		// array of functions
		pfnImportAddr = (PDWORD)(pImportTable->FirstThunk + BaseAddress);

		// array of names
		pfnNames = (PDWORD)(pImportTable->OriginalFirstThunk + BaseAddress);

		// Condition.
		// Enumerate functions and get information about them
		if (right_imp = imp_predicate(pfnImportAddr, pfnNames))
		{
			while (pfnImportAddr && (*((PDWORD)pfnImportAddr)))
			{
				int insertOnlyImportedByNames = 0;

				if (pfnInfo = (PIMPORT_FN)PAGE_MEM(sizeof(IMPORT_FN)))
				{
					//pApiInfo->Api = (PVOID)*pImportFunction;
					//pt4b = (PDWORD)readAndAlloc(pfnImportAddr, &t4b, sizeof(t4b));

					pfnInfo->Api = (PVOID) *pfnImportAddr; // api_address
					pfnInfo->AddrFuncAddr = pfnImportAddr; // &api_address

					if (pfnNames)
					{
						if ((*pfnNames) & IMAGE_ORDINAL_FLAG32)
						{
							pfnInfo->ApiName = NULL;
							pfnInfo->Ordinal = *pfnNames;
						}
						else
						{
							// .ApiName field can be NULL, I'll skip it
							pfnInfo->ApiName = (char*)(*pfnNames + BaseAddress + sizeof(WORD));
							pfnInfo->Ordinal = 0;
						}

						insertOnlyImportedByNames = 1;
					}

					if (insertOnlyImportedByNames)
					{
						pInfoImp->length++;
						pfnInfo->next = NULL;

						if (pInfoImp->functions == NULL)
							pInfoImp->functions = pfnInfo;
						else
						{
							pfnInfo->next = pInfoImp->functions;
							pInfoImp->functions = pfnInfo;
						}
					} else
					{
						ExFreePool(pfnInfo);
					}
				}

				// next iteration
				pfnImportAddr++, pfnNames++;
			}

			// get next memory block for IMPORT_LIB structure
			pInfoImp->szLib = (char*)(pImportTable->Name + BaseAddress);
			pInfoImp++;
		}

		++pImportTable;
	}

	return TRUE;
}

int ExeVerifier(PVOID pfile)
{
	WORD wSign = 0;
	DWORD dwSign = 0;

	if (pfile)
	{
		//readAndAlloc(pfile, &wSign, sizeof(WORD));
		//readAndAlloc(get_header_addr(0), &dwSign, sizeof(DWORD));
		return ((dwSign == IMAGE_NT_SIGNATURE) && (wSign == IMAGE_DOS_SIGNATURE));
	}

	return 0;
}

PVOID GetExportedFn(PEXE_FILE pexefile, PCHAR szName)
{
	ULONG i = 0, count_api = pexefile->m_export_length;
	PEXPORT_FN p = pexefile->m_export;

	if (count_api){
		for (i = 0; i < count_api; p++, i++){
			if (kstrcmp(szName, p->Name) == 0){
				return p->addr;
			}
		}
	}

	return NULL;
}

PVOID GetExportedFnByOrd(PEXE_FILE pexefile, WORD ordinal)
{
	ulong i = 0, count_api = pexefile->m_export_length;
	PEXPORT_FN p = pexefile->m_export;

	if (count_api){
		for (i = 0; i < count_api; p++, i++){
			if (p->Ordinal == ordinal){
				return p->addr;
			}
		}
	}

	return NULL;
}

const PCHAR GetExportedFnByAddr(PEXE_FILE pexefile, PVOID api)
{
	ulong i = 0, count_api = pexefile->m_export_length;
	PEXPORT_FN p = pexefile->m_export;

	if (count_api){
		for (i = 0; i < count_api; p++, i++){
			if (p->addr == api){
				return p->Name;
			}
		}
	}

	return NULL;
}

PEXPORT_FN GetExportedFnInfo(PEXE_FILE pexefile, PCHAR szName)
{
	ulong i = 0, count_api = pexefile->m_export_length;
	PEXPORT_FN p = pexefile->m_export;

	if (count_api && p)
	for (i = 0; i < count_api; p++, i++)
	if (kstrcmp(szName, p->Name) == 0)
		return p;

	return NULL;
}

PVOID GetImportedFn(PEXE_FILE pexefile, PCHAR szName)
{
	PIMPORT_FN pfn = NULL;
	PIMPORT_LIB plib = pexefile->m_import;

	if (plib){
		for (ulong i = 0; i < pexefile->m_import_length; i++, plib++){
			for (pfn = plib->functions; pfn != NULL; pfn = pfn->next){
				if (kstrcmp(pfn->ApiName, szName) == 0){
					return pfn->Api;
				}
			}
		}
	}

	return NULL;
}

const PCHAR GetImportedFnByAddr(PEXE_FILE pexefile, PVOID api)
{
	PIMPORT_FN pfn = NULL;
	PIMPORT_LIB plib = NULL;

	plib = pexefile->m_import;

	for (ulong i = 0; i < pexefile->m_import_length; i++, plib++){
		for (pfn = plib->functions; pfn != NULL; pfn = pfn->next){
			if (pfn->Api == api)
				return pfn->ApiName;
		}
	}

	return NULL;
}

PIMPORT_FN GetImportedFnInfo(PEXE_FILE pexefile, PCHAR szName)
{
	PIMPORT_FN pfn = NULL;
	PIMPORT_LIB plib = NULL;

	plib = pexefile->m_import;

	for (ulong i = 0; i < pexefile->m_import_length; i++, plib++)
	for (pfn = plib->functions; pfn != NULL; pfn = pfn->next)
	if (kstrcmp(pfn->ApiName, szName) == 0)
		return pfn;

	return NULL;
}

PIMPORT_FN GetImportedFnInfoByLibAndName(PEXE_FILE pexefile, PCHAR szLib, PCHAR szName)
{
	PIMPORT_FN pfn = NULL;
	PIMPORT_LIB plib = NULL;

	plib = pexefile->m_import;

	for (ulong i = 0; i < pexefile->m_import_length; i++, plib++){
		if (kstrcmp(plib->szLib, szLib) == 0){
			for (pfn = plib->functions; pfn != NULL; pfn = pfn->next){
				if (kstrcmp(pfn->ApiName, szName) == 0){
					return pfn;
				}
			}
		}
	}

	return NULL;
}

void ExeFileFree(PEXE_FILE pexefile)
{
	PIMPORT_FN pfn = NULL, t = NULL;
	PIMPORT_LIB plib = NULL;

	// 1. Sections pointer
	if (pexefile->m_countSections)
	{
		ExFreePool(pexefile->m_pSectionHeaders);
	}
	
	// 2. Export data
	if (pexefile->m_export_length)
	{
		// 		for (int i = 0; i < m_export_length; i++)
		// 			freemem(m_export[i].Name);

		ExFreePool(pexefile->m_export);
	}

	// 3. Import data
	if (pexefile->m_import_length)
	{
		plib = pexefile->m_import;

		for (ulong i = 0; i < pexefile->m_import_length; i++, plib++)
		{
			//ExFreePool(plib->szLib);
			for (pfn = plib->functions; pfn != NULL;)
			{
				//ExFreePool(pfn->ApiName);
				t = pfn;
				pfn = pfn->next;
				ExFreePool(t);
			}
		}

		ExFreePool(pexefile->m_import);
	}
}

