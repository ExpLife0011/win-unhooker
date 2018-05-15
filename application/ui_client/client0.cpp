
//      (c)VsoftLab 2006 - 2014
//		Author: burluckij@gmail.com	

#include "client0.h"

bool client0::InstallAndLoad()
{
	return client0::InstallAndLoad((client0&)*this);
}

bool client0::InstallAndLoad(__in client0& client)
{
	bool state = client.InstallDriver();

	// Handles if has occurred ERROR_SERVICE_EXISTS
	if ((state == FALSE) && (GetLastError() == ERROR_SERVICE_EXISTS))
	{
		// Another way to continue - delete earlier created service and create new
		state = TRUE;
	}

	state = client.LoadDriver();

	if((state == FALSE) && (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING))
	{
		// If the service was loaded earlier assume that that's OK
		state = TRUE;
	}
	
	return state;
}

bool client0::UnloadAndRemove()
{
	if(UnloadDriver())
		if(DeleteService())
			return true;

	return false;
}

bool client0::InstallDriver(DWORD dwStartType)
{
	return System::CreateDriverService(dwStartType, m_serviceName.toAscii().constData(), m_drvFilePath.toAscii().constData());
}

bool client0::LoadDriver()
{
	BOOL loaded = System::LoadDriver(m_serviceName.toAscii().constData());

	// If client0 was early loaded than return TRUE
// 	if((loaded==FALSE) && (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)){
// 		return TRUE;
// 	}

	return loaded;
}

bool client0::UnloadDriver()
{
	return System::UnloadDriver(m_serviceName.toAscii().constData());
}

bool client0::DeleteService()
{
	BOOL deleted = FALSE;
	SC_HANDLE hOpenSM;
	SC_HANDLE hDrvService;

	hOpenSM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hOpenSM) {
		return FALSE;
	}

	hDrvService = OpenService(hOpenSM, m_serviceName.toAscii().constData(), SERVICE_ALL_ACCESS);
	if (hDrvService)
	{
		deleted = ::DeleteService(hDrvService);
		CloseServiceHandle(hDrvService);
	}

	CloseServiceHandle(hOpenSM);
	return deleted;
}

bool client0::InitDriver(__in const char* ntoskernel, bool exact_match)
{
	char* pFilePath;
	PeFile* pe_kernel = NULL;
	CL0_REQUEST request;
	DWORD reqired_size = 0;
	PVOID pNtoskrnl = m_sysapi.GetDriverImageBaseAddress(ntoskernel, exact_match);

	if (!connectToDevice()){
		return false;
	}
	
	if(!pNtoskrnl)
		return false;

	// Load SSDT from file
	m_sysapi.GetDriverFilePath(pNtoskrnl, NULL, &reqired_size);
	pFilePath = (char*)Memory::getmem(reqired_size);
	if(!m_sysapi.GetDriverFilePath(pNtoskrnl, pFilePath, &reqired_size)){
		Memory::freemem(pFilePath);
		return false;
	}

	pe_kernel = new (std::nothrow)PeFile("c:\\windows\\system32\\ntkrnlpa.exe"/*pFilePath*/);
	if (pe_kernel->GetError() == CRASH_INIT){
		delete pe_kernel;
		Memory::freemem(pFilePath);
		return false;//0x00a225e0 "c:\\windows\\system32\\ntkrnlpa.exe"
	}

	DWORD krnl_base = (DWORD)pe_kernel->GetBaseX();
	PSERVICE_DESCRIPTOR_TABLE psdt = (PSERVICE_DESCRIPTOR_TABLE)pe_kernel->GetExportedFn("KeServiceDescriptorTable");

	// get offset to KeServiceDescriptorTable
	request.result = (DWORD)psdt - (DWORD)pe_kernel->GetMapX();
	request.data = (DWORD)pNtoskrnl;

	// response on the request
	request = sendRequest(IOCTL_KERNELBASE, &request, &request, sizeof(CL0_REQUEST));
	m_configured = request.error == CL0_SUCCESS;
	return (m_configured);
}

bool client0::GetDriverSate()
{
	return false;
}

bool client0::connectToDevice()
{
	m_hDevice = CreateFileA(m_deviceName.toAscii().constData(),
		FILE_WRITE_ACCESS | FILE_READ_ACCESS,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	return m_hDevice != INVALID_HANDLE_VALUE;
}

CL0_REQUEST client0::sendRequest(__in DWORD requestCode, __in PCL0_REQUEST pRequest, __out PVOID outData, __in DWORD outDataSize)
{
	DWORD returned = 0;
	CL0_REQUEST response;

	BOOL result = DeviceIoControl(m_hDevice,
		requestCode,
		pRequest,
		sizeof(CL0_REQUEST),
		outData,
		outDataSize,
		&returned,
		NULL);

	if(!result)
	{
		// If it's an error then all fields are set default values
		response.error = 0;
		response.result = returned;
		response.bodysize = 0;
	}
	else
	{
		memcpy(&response, outData, sizeof(CL0_REQUEST));
	}

	return response;
}

bool client0::GetSsdtHooks(__out THooksSsdt& hooks)
{
	return GetDataBlock<THooksSsdt, SSDT_HK>(IOCTL_SSDT_SCAN, hooks);
}

bool client0::GetKernelModules(__out TKernelModules& modules)
{
	return GetDataBlock<TKernelModules, CL0_KRNL_MODULE>(IOCTL_GET_KRNL_MODULES, modules);
}

bool client0::GetRunningProcesses(__out TSysProcesses& processes)
{
	return GetDataBlock<TSysProcesses, CL0_PROC_INFO>(IOCTL_GET_PROCESSES, processes);
}
