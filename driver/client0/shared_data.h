/************************************************************************/
/* Type Definitions                                                     */
/************************************************************************/

#ifndef SHARED_DATA
#define SHARED_DATA

#define DEVICE_LINK			L"\\DosDevices\\client0"
#define DEVICE_NAME			L"\\Device\\client0"
#define DEV_NAME			"\\\\.\\client0"
#define CLIENT0_SERVICE_NAME "client0"

#define KERNEL_MODULE_NAME_SRCH		"krnl"

#define EXPORT			EXTERN_C __declspec(dllexport)
#define CL0_BUFFER_TOO_SMALL		0x01
#define CL0_KRNL_NOT_CONNECTED		0x02
#define CL0_UNPREPARED				0x03
#define CL0_NO_MEMORY				0x04
#define CL0_UNKNOWN_ERROR			0x05
#define CL0_SUCCESS					0


//#define DO_DEVICE_HAS_NAME                  0x00000040 
#define DDK_DO_DEVICE_HAS_NAME                0x00000040 

#define FILE_PATH_LEN		256
#define CLIENT0_DEVICE		0x00002a7b

#define IOCTL_KERNELBASE			CTL_CODE(CLIENT0_DEVICE, 0x0778, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_SSERV_OFFSETS			CTL_CODE(CLIENT0_DEVICE, 0x0578, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESSES			CTL_CODE(CLIENT0_DEVICE, 0x0700, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GET_PROC_MODULES		CTL_CODE(CLIENT0_DEVICE, 0x0701, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GET_KRNL_MODULES		CTL_CODE(CLIENT0_DEVICE, 0x0702, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_SSDT_SCAN				CTL_CODE(CLIENT0_DEVICE, 0x0703, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_SSDT_RESET			CTL_CODE(CLIENT0_DEVICE, 0x0705, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_SYSENTER_CHECK		CTL_CODE(CLIENT0_DEVICE, 0x0704, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_SYSENTER_RESET		CTL_CODE(CLIENT0_DEVICE, 0x0707, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_CL0_VERSION			CTL_CODE(CLIENT0_DEVICE, 0x0706, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_IRP_HANDLERS			CTL_CODE(CLIENT0_DEVICE, 0x0708, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
//#define IOCTL_IRP_RESET				CTL_CODE(CLIENT0_DEVICE, 0x0709, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_DRIVERS				CTL_CODE(CLIENT0_DEVICE, 0x0710, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_DEVICES				CTL_CODE(CLIENT0_DEVICE, 0x0711, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_ATTACHED_DEVICES		CTL_CODE(CLIENT0_DEVICE, 0x0712, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
//#define IOCTL_INIT_AUTO				CTL_CODE(CLIENT0_DEVICE, 0x0713, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_SYSAPI_CHECK_CODE		CTL_CODE(CLIENT0_DEVICE, 0x0714, /*METHOD_BUFFERED*/ METHOD_NEITHER, FILE_ANY_ACCESS)


typedef NTSTATUS(NTAPI *NTPROC) ();
typedef NTPROC			*PNTPROC;


#ifndef KERNEL_USAGE

typedef unsigned long	DWORD, *PDWORD;
typedef unsigned long	ULONG;
typedef unsigned short	WORD, *PWORD;
typedef unsigned char	BYTE, *PBYTE;
typedef BOOLEAN			BOOL;
typedef DWORD			*PDWORD;
typedef CHAR			*PCHAR;
typedef ULONG			ulong;
// typedef NTSTATUS(NTAPI *NTPROC) ();
// typedef NTPROC			*PNTPROC;

#endif

#pragma pack(1)

typedef struct _SYSTEM_SERVICE_TABLE
{
	PNTPROC	ServiceTable; // array of pointers to the sys api
	PDWORD	CounterTable; // counter usage
	DWORD	ServiceLimit; // size of array
	PBYTE	ArgumentTable;
}SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
	SYSTEM_SERVICE_TABLE ntoskrnl; // system interface
	SYSTEM_SERVICE_TABLE win32k; // graphic interface
	SYSTEM_SERVICE_TABLE Table3;
	SYSTEM_SERVICE_TABLE Table4;

} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

#define GET_BODY(p)			((PCHAR)p + sizeof(CL0_REQUEST))
#define REQUEST_BODY(p)		((PCHAR)p + sizeof(CL0_REQUEST))

typedef struct CL0_REQUEST_
{
	DWORD error; // ERROR if it is not zero
	union {
		DWORD result; // result of request operation by user app
		DWORD arg;
	};
	
	union {
		DWORD bodysize; // size of written data in body of request
		DWORD data;
	};
	
	// BYTE data[0];
	// after this structure is a output/input buffer
	// ....
}CL0_REQUEST, *PCL0_REQUEST;

typedef struct CL0_KRNL_MODULE_
{
	DWORD imageBase;
	DWORD size;
	CHAR fileName[FILE_PATH_LEN];
}CL0_KRNL_MODULE, *PCL0_KRNL_MODULE;

typedef struct CL0_PROC_INFO_
{
	//DWORD imageBase;
	//DWORD size;
	DWORD pid;
	CHAR fileName[FILE_PATH_LEN];
}CL0_PROC_INFO, *PCL0_PROC_INFO;

typedef struct ssdt_hook_
{
	DWORD index;
	PVOID hookproc;
	PVOID rtkimage;
	CHAR rtkfile[FILE_PATH_LEN];
}SSDT_HK, *PSSDT_HK;

typedef struct sysenter_handler
{
	BOOL	hooked; // TRUE if it's hooked
	PVOID	handler; // fake handler
	PVOID	imagebase; // base address of module
	CHAR	module[FILE_PATH_LEN]; // address to file on disk
}SYSENTER_HANDLER, *PSYSENTER_HANDLER;

typedef struct FAKE_HANDLER_
{
	//
	PVOID handler;
	PVOID imagebase;
	PVOID original_handler;
	// NAME field
} FAKE_HANDLER, *PFAKE_HANDLER;

typedef struct IRP_HANDLER_
{
	LONG	major_code;
	PVOID	handler;
	PVOID	imagebase;
	CHAR	module[FILE_PATH_LEN];
}IRP_HANDLER, *PIRP_HANDLER;

typedef struct DRIVER_FILE_
{
	PVOID	pImageBase;
	PVOID	pEntryPoint;
	ULONG	ImageSize;
	WCHAR	filePath[FILE_PATH_LEN];
	WCHAR	fileName[FILE_PATH_LEN];
}DRIVER_MODULE, *PDRIVER_MODULE;

typedef struct DRIVER_OBJECT_INFO_
{
	WCHAR driver_name[FILE_PATH_LEN];
	DRIVER_MODULE driver_module;
}DRIVER_OBJECT_INFO, *PDRIVER_OBJECT_INFO;

typedef struct DEVICE_INFO_
{
	ULONG	reserved;
	WCHAR	device_name[FILE_PATH_LEN];
	DRIVER_OBJECT_INFO driver_info;
}DEVICE_INFO, *PDEVICE_INFO;

typedef struct CODE_INJECTION_
{
	PVOID pBegin; /* Address of changed code region. */
	ULONG SizeOfNewCode; /* Size of modified code. */
	PVOID pFunction; /* Function addr which code was modified. */
	PVOID HookFn; /* */
	PVOID HookModuleImage;
}CODE_INJECTION, *PCODE_INJECTION;

#pragma pack()

#endif


/***********
#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_QUERY_EA                 0x07
#define IRP_MJ_SET_EA                   0x08
#define IRP_MJ_FLUSH_BUFFERS            0x09
#define IRP_MJ_QUERY_VOLUME_INFORMATION 0x0a
#define IRP_MJ_SET_VOLUME_INFORMATION   0x0b
#define IRP_MJ_DIRECTORY_CONTROL        0x0c
#define IRP_MJ_FILE_SYSTEM_CONTROL      0x0d
#define IRP_MJ_DEVICE_CONTROL           0x0e
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0f
#define IRP_MJ_SHUTDOWN                 0x10
#define IRP_MJ_LOCK_CONTROL             0x11
#define IRP_MJ_CLEANUP                  0x12
#define IRP_MJ_CREATE_MAILSLOT          0x13
#define IRP_MJ_QUERY_SECURITY           0x14
#define IRP_MJ_SET_SECURITY             0x15
#define IRP_MJ_POWER                    0x16
#define IRP_MJ_SYSTEM_CONTROL           0x17
#define IRP_MJ_DEVICE_CHANGE            0x18
#define IRP_MJ_QUERY_QUOTA              0x19
#define IRP_MJ_SET_QUOTA                0x1a
#define IRP_MJ_PNP                      0x1b
#define IRP_MJ_PNP_POWER                IRP_MJ_PNP      // Obsolete....
#define IRP_MJ_MAXIMUM_FUNCTION         0x1b

*/