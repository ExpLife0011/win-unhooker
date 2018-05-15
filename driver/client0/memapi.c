
#include "Ntifs.h"
#include "ntddk.h"
#include "ntdef.h"

#include "client0.h"
#include "w32.h"
#include "ntt.h"
#include "kstr.h"
#include "list_t.h"
#include "algo_t.h"

extern ULONG off_EPROCESS_ActiveProcessLink;
extern ULONG off_EPROCESS_ProcessName;
extern ULONG off_EPROCESS_PID;
extern ULONG off_EPROCESS_RootVad;

typedef struct _VAD_INFO
{
	LONG level;
	ULONG pAddress;
	PCONTROL_AREA pControlArea;
	PFILE_OBJECT pFileObject;
	PUNICODE_STRING Name;
}VAD_INFO, *PVAD_INFO;


PEPROCESS GetEprocess(PUCHAR szProcessName);
PMMVAD GetVAD(PUCHAR szProcessName);
VOID SetVadInfo(PMMVAD pVad, PVAD_INFO pVadInfo);
VOID DisplayVadInfo(PVAD_INFO pVadInfo);
PCONTROL_AREA GetControlArea(PMMVAD pVad);
PFILE_OBJECT GetFileObject(PMMVAD pVad);
PUNICODE_STRING GetVADName(PMMVAD pVad);
VOID ListVAD(PMMVAD pParentVad, LONG level);

PEPROCESS GetEprocess(PUCHAR szProcessName)
{
	PEPROCESS pBaseEprocess = NULL;
	PEPROCESS pCurrentEprocess = NULL;
	PLIST_ENTRY pCurrentList = NULL;

	pCurrentEprocess = (PEPROCESS)IoGetCurrentProcess();
	pBaseEprocess = pCurrentEprocess;

	do
	{
		//DbgPrint("\nProcess : %s", ((PUCHAR)pCurrentEprocess+0x174));
		pCurrentList = (PLIST_ENTRY)((PUCHAR)pCurrentEprocess + off_EPROCESS_ActiveProcessLink);

		if (pCurrentList->Flink == NULL)
			return NULL;

		pCurrentEprocess = (PEPROCESS)((PUCHAR)pCurrentList->Flink - off_EPROCESS_ActiveProcessLink);

		if (pBaseEprocess == pCurrentEprocess)
			return NULL;

	} while (strcmp(szProcessName, (PUCHAR)pCurrentEprocess + off_EPROCESS_ProcessName));

	return pCurrentEprocess;
}

PMMVAD GetVAD(PUCHAR szProcessName)
{
	PMMVAD pVadRoot = NULL;
	PEPROCESS pEprocess = NULL;
	pEprocess = GetEprocess(szProcessName);

	DbgPrint("\n\nEPROCESS : 0x%x \n\n", pEprocess);

	if (pEprocess == NULL)
	{
		DbgPrint("\nProcess not found\n");
		return NULL;
	}

	pVadRoot = (PMMVAD)*(PULONG)((PUCHAR)pEprocess + off_EPROCESS_RootVad);
	DbgPrint("\n\nVADRoot : 0x%x\n\n", pVadRoot);
	return pVadRoot;
}

VOID SetVadInfo(PMMVAD pVad, PVAD_INFO pVadInfo)
{
	pVadInfo->pAddress = (ULONG)pVad;
	pVadInfo->pControlArea = (PCONTROL_AREA)GetControlArea(pVad);
	pVadInfo->pFileObject = (PFILE_OBJECT)GetFileObject(pVad);
	pVadInfo->Name = (PUNICODE_STRING)GetVADName(pVad);
	return;
}

VOID DisplayVadInfo(PVAD_INFO pVadInfo)
{
	DbgPrint("\n[+]0x%x", pVadInfo->pAddress);
	DbgPrint("      Level : %ld", pVadInfo->level);
	DbgPrint("      Control Area : 0x%x", pVadInfo->pControlArea);
	DbgPrint("      File Object : 0x%x", pVadInfo->pFileObject);
	DbgPrint("      Name : %wZ", pVadInfo->Name);
	return;
}

PCONTROL_AREA GetControlArea(PMMVAD pVad)
{
	if (MmIsAddressValid(pVad) == FALSE || pVad == NULL)
		return NULL;

	return (PCONTROL_AREA)pVad->ControlArea;
}

PFILE_OBJECT GetFileObject(PMMVAD pVad)
{
	PCONTROL_AREA pControlArea = NULL;
	pControlArea = GetControlArea(pVad);

	if (MmIsAddressValid((PULONG)pControlArea) == FALSE)
		return NULL;

	return (PFILE_OBJECT)pControlArea->FilePointer;
}

PUNICODE_STRING GetVADName(PMMVAD pVad)
{
	PFILE_OBJECT pFileObject = NULL;
	pFileObject = GetFileObject(pVad);

	if (MmIsAddressValid((PULONG)pFileObject) == FALSE)
		return NULL;

	if (MmIsAddressValid((PULONG)((PUCHAR)&pFileObject->FileName)) == FALSE)
		return NULL;

	/* IoQueryFileDosDeviceName */
	return &pFileObject->FileName;
}

VOID ListVAD(PMMVAD pParentVad, LONG level)
{
	PMMVAD pVadLeft = NULL;
	PMMVAD pVadRight = NULL;
	VAD_INFO VadInfo;

	if (pParentVad == NULL)
		return;

	VadInfo.level = level;
	SetVadInfo(pParentVad, &VadInfo);
	DisplayVadInfo(&VadInfo);

	pVadLeft = (PMMVAD)pParentVad->LeftChild;
	pVadRight = (PMMVAD)pParentVad->RightChild;

	if (pVadLeft != NULL)
	{
		ListVAD(pVadLeft, level + 1);
	}
	if (pVadRight != NULL)
	{
		ListVAD(pVadRight, level + 1);
	}

	return;
}

void List_Vad()
{
	DbgPrint("cl0: list VAD for explorer.exe\n");

	PMMVAD pVadRoot = GetVAD("explorer.exe");

	ListVAD(pVadRoot, 0);
}

