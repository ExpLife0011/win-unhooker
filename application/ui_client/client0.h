
//      (c)Burluckij Stas 2006 - 2014
//		Author: burluckij@gmail.com	

#ifndef CLIENT0_H
#define CLIENT0_H

#include <QList>
#include <QVector>
#include <QString>
#include "System.h"
#include "PE.h"

#define KERNEL_USAGE
#include "..\..\..\driver\client0\shared_data.h"

typedef QList< CL0_PROC_INFO >		TSysProcesses;
typedef QList< CL0_KRNL_MODULE >	TKernelModules;
typedef QList< SSDT_HK >			THooksSsdt;


class client0: protected CBase
{
private:
	QString m_deviceName;
	QString m_drvFilePath;
	QString m_serviceName;

	BOOL m_configured;
	System m_sysapi;

	HANDLE m_hDevice;

	bool connectToDevice();
	CL0_REQUEST sendRequest(__in DWORD requestCode, __in PCL0_REQUEST pRequest, __out PVOID outData, __in DWORD outDataSize);

public:

	static bool InstallAndLoad(__in client0&);

	bool UnloadAndRemove();
	bool InstallAndLoad();

	bool InstallDriver(DWORD dwStartType = SERVICE_DEMAND_START);
	bool LoadDriver();
	bool UnloadDriver();
	bool DeleteService();
	bool GetDriverSate();

	bool InitDriver(__in const char* ntoskernel = "krnl", bool exact_match = FALSE);
	bool GetSsdtHooks(__out THooksSsdt& hooks);
	bool GetRunningProcesses(__out TSysProcesses& processes);
	bool GetKernelModules(__out TKernelModules& modules);

protected:
	client0(QString drvFilePath, QString serviceName = CLIENT0_SERVICE_NAME, QString devName = DEV_NAME):
		 m_deviceName(devName), m_serviceName(serviceName), m_hDevice(INVALID_HANDLE_VALUE),
			 m_drvFilePath(drvFilePath), m_configured(FALSE)
		 {

		 }
public:

	static client0& GetClient(QString drvFilePath = "client0.sys", QString serviceName = CLIENT0_SERVICE_NAME, QString devName = DEV_NAME)
	{
		static client0 m_client(drvFilePath, serviceName, devName);
		return m_client;
	}

	// Gets data from module and saves them in container
	template<class T_container, class T_received>
	bool GetDataBlock(__in DWORD requestCode, __out T_container & container)
	{
		bool request_result = false;
		CL0_REQUEST request;
		request.bodysize = 0;

		CL0_REQUEST response = sendRequest(requestCode, &request, &request, sizeof(CL0_REQUEST));

		if((response.error == CL0_SUCCESS) && (response.result == 0)){
			return true;
		} else if (response.error != CL0_BUFFER_TOO_SMALL){
			return false;
		}

		DWORD respSize = sizeof(CL0_REQUEST) + response.result;
		PVOID pCl0Response = Memory::getmem(respSize + 32);
		request.bodysize = response.result;
		response = sendRequest(requestCode, &request, pCl0Response, respSize);
		request_result = (response.error == CL0_SUCCESS);

		// Saves information about received modules in container if everything is ok
		if(request_result)
		{
			T_received* pEntry = (T_received*) ((PCHAR)pCl0Response + sizeof(CL0_REQUEST));
			ulong count = response.result / sizeof(T_received);

			for(int i=0; i<count; ++i, ++pEntry)
			{
				container.push_back(*pEntry);
			}
		}

		Memory::freemem(pCl0Response);
		return request_result;
	}

	BOOL Configured(){
		return m_configured;
	}
private:
	//static client0 m_driver;
};
#endif
