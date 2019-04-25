#pragma once
#include <iostream>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include "KernelHelpers.h"
#include "Structs.h"
#include <stdio.h>
#include <aclapi.h>


// for Security descriptor
DWORD dwRes;
SECURITY_ATTRIBUTES sa;
PSECURITY_DESCRIPTOR pSD = NULL;
SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
PACL pAcl = NULL;
PSID pEveryoneSID = NULL;
EXPLICIT_ACCESS ea[1];




// interface for our driver
class Kernelrequests
{
public:
	

	DWORD_PTR FindProcessId(const std::string& processName)
	{
		PROCESSENTRY32 processInfo;
		processInfo.dwSize = sizeof(processInfo);

		HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (processesSnapshot == INVALID_HANDLE_VALUE)
			return 0;

		Process32First(processesSnapshot, &processInfo);
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}

		while (Process32Next(processesSnapshot, &processInfo))
		{
			if (!processName.compare(processInfo.szExeFile))
			{
				CloseHandle(processesSnapshot);
				return processInfo.th32ProcessID;
			}
		}

		CloseHandle(processesSnapshot);
		return 0;
	}


	// add functions here kernel functions

	
	template<typename T>
	bool Write(UINT_PTR WriteAddress, const T& value)
	{
		return WriteVirtualMemoryRaw(WriteAddress, (UINT_PTR)&value, sizeof(T));
	}
	bool WriteVirtualMemoryRaw(UINT_PTR WriteAddress, UINT_PTR SourceAddress, SIZE_T WriteSize)
	{
		auto Write_memoryst = (char*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, 4096);
		char str[8];
		strcpy_s(str, "Write");
		RtlCopyMemory(Write_memoryst, str, strlen(str) + 1);
#ifdef DBG_PRINT
		printf("message has been sent to kernel [Write]! \n");
#endif // DBG_PRINT
		UnmapViewOfFile(Write_memoryst);

		WaitForSingleObject(SharedEvent_dataarv, INFINITE);


		KM_WRITE_REQUEST* Sent_struct = (KM_WRITE_REQUEST*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, sizeof(KM_WRITE_REQUEST));

		if (!Sent_struct) {
#ifdef DBG_PRINT
			printf("Error MapViewOfFile(Sent_struct)\n");
#endif // DBG_PRINT
			return false;
		}

		KM_WRITE_REQUEST  WriteRequest;
		WriteRequest.ProcessId = PID;
		WriteRequest.ProcessidOfSource = GetCurrentProcessId(); // gets our program PID.
		WriteRequest.TargetAddress = WriteAddress;
		WriteRequest.SourceAddress = SourceAddress;
		WriteRequest.Size = WriteSize;

#ifdef DBG_PRINT
		printf("PID :%u ProcessidOfSource : %u Source Address : %p Target Address : %p  Size : %x \n", WriteRequest.ProcessId, WriteRequest.ProcessidOfSource,WriteRequest.SourceAddress, WriteRequest.TargetAddress, WriteRequest.Size);
#endif // DBG_PRINT

		KM_WRITE_REQUEST* test_ptr = &WriteRequest;
		if (0 == memcpy(Sent_struct, test_ptr, sizeof(KM_WRITE_REQUEST))) {
#ifdef DBG_PRINT
			printf("Error copying memory with (memcpy) to struct\n");
#endif // DBG_PRINT
			return false;
		}
#ifdef DBG_PRINT
		printf("%p\n", Sent_struct);
#endif // DBG_PRINT
		UnmapViewOfFile(Sent_struct);

		WaitForSingleObject(SharedEvent_trigger, INFINITE); // wait for a signal from kernel to exit this function adn execute again.
		ResetEvent(SharedEvent_trigger);
		return true;
	}




	template <typename type>
	type Read(UINT_PTR ReadAddress)
	{
		auto Read_memoryst = (char*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, 4096);
		char str[8];
		strcpy_s(str, "Read");
		RtlCopyMemory(Read_memoryst, str, strlen(str) + 1);
#ifdef DBG_PRINT
		printf("message has been sent to kernel [Read]! \n");
#endif // DBG_PRINT
		UnmapViewOfFile(Read_memoryst);

		WaitForSingleObject(SharedEvent_dataarv, INFINITE);


		KM_READ_REQUEST* Sent_struct = (KM_READ_REQUEST*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, sizeof(KM_READ_REQUEST));

		if (!Sent_struct) {
#ifdef DBG_PRINT
			printf("Error MapViewOfFile(Sent_struct)\n");
#endif // DBG_PRINT
			return false;
		}

		KM_READ_REQUEST ReadRequest{};

		// just to clairfy this is like doing for ex : int response; its an empty var
		type response{};

		ReadRequest.ProcessId = PID;
		ReadRequest.SourceAddress = ReadAddress;
		ReadRequest.Size = sizeof(type);
		ReadRequest.Output = &response;


		KM_READ_REQUEST* test_ptr = &ReadRequest;
		if (0 == memcpy(Sent_struct, test_ptr, sizeof(KM_READ_REQUEST))) {
#ifdef DBG_PRINT
			printf("Error copying memory with (memcpy) to struct\n");
#endif // DBG_PRINT
			return 1;
		}
#ifdef DBG_PRINT
		printf(" Struct pointer : %p PID : %u ReadAddress : %p Output : %p Size : %x \n", Sent_struct, ReadRequest.ProcessId, ReadRequest.SourceAddress, ReadRequest.Output, ReadRequest.Size);
#endif // DBG_PRINT
		UnmapViewOfFile(Sent_struct);
		

		
		WaitForSingleObject(SharedEvent_ready2read, INFINITE);
	
		KM_READ_REQUEST* Read_struct = (KM_READ_REQUEST*)MapViewOfFile(hMapFileR, FILE_MAP_READ, 0, 0, sizeof(KM_READ_REQUEST));
		if (!Read_struct)
		{
#ifdef DBG_PRINT
			printf("OpenFileMappingA(Read_struct) fail! Error: %u\n", GetLastError());
#endif // DBG_PRINT
			return 0;
		}

	
#ifdef DBG_PRINT
		printf("Data Read_struct : %p\n", Read_struct);
		printf("Data Read_struct->Output : %p\n", Read_struct->Output);
		printf("Data value : %u \n", Read_struct->Output);
#endif // DBG_PRINT

		type Returnval = ((type)Read_struct->Output);

		UnmapViewOfFile(Read_struct);
		WaitForSingleObject(SharedEvent_trigger, INFINITE);
		ResetEvent(SharedEvent_trigger);
		return Returnval;
	}


	bool ClearMmunloadedDrivers() {

		auto Clearmm_memoryst = (char*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, 4096);
		if (!hMapFileW || hMapFileW == INVALID_HANDLE_VALUE) {
			printf("MapViewOfFile(Clearmm_memoryst) fail! Error: %u\n", GetLastError());
			return false;
		}
		char str[10];
		strcpy_s(str, "Clearmm");
		if (0 == RtlCopyMemory(Clearmm_memoryst, str, strlen(str) + 1)) {
			printf("RtlCopyMemory(Clearmm_memoryst) fail! Error: %u\n", GetLastError());
			return false;
		}
		printf("message has been sent to kernel [Clearmm]! \n");
		UnmapViewOfFile(Clearmm_memoryst);


		WaitForSingleObject(SharedEvent_ready2read, INFINITE);

		auto pBuf = (char*)MapViewOfFile(hMapFileR, FILE_MAP_READ, 0, 0, 4096);
		if (!pBuf)
		{
			printf("OpenFileMappingA(read) fail! Error: %u\n", GetLastError());
			return 0;
		}


		printf("Data: %s\n", pBuf);
		UnmapViewOfFile(pBuf);
		return true;
	}

	bool ClearPIDCache() {
		auto ClearPIDCache_mem = (char*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, 4096);
		if (!hMapFileW || hMapFileW == INVALID_HANDLE_VALUE) {
			printf("MapViewOfFile(ClearPIDCache_mem) fail! Error: %u\n", GetLastError());
			return false;
		}
		char str1[11];
		strcpy_s(str1, "Clearpid");
		if (0 == RtlCopyMemory(ClearPIDCache_mem, str1, strlen(str1) + 1)) {
			printf("RtlCopyMemory(ClearPIDCache_mem) fail! Error: %u\n", GetLastError());
			return false;
		}
		printf("message has been sent to kernel [ClearPIDCache_mem]! \n");
		UnmapViewOfFile(ClearPIDCache_mem);


		WaitForSingleObject(SharedEvent_ready2read, INFINITE);

		auto pBuf = (char*)MapViewOfFile(hMapFileR, FILE_MAP_READ, 0, 0, 4096);
		if (!pBuf)
		{
			printf("OpenFileMappingA(read) fail! Error: %u\n", GetLastError());
			return 0;
		}

		printf("Data: %s\n", pBuf);
		UnmapViewOfFile(pBuf);
		return true;
	}


	// change to UINT_PTR OR DWORD_PTR
	ULONG64 GetModuleBase(ULONG pid) {
		
		auto GetModuleBase_msg = (char*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, 4096);
		if (!hMapFileW || hMapFileW == INVALID_HANDLE_VALUE) {
#ifdef DBG_PRINT
			printf("MapViewOfFile(Clearmm_memoryst) fail! Error: %u\n", GetLastError());
#endif // DBG_PRINT
			return 0;
		}
		char str[10];
		strcpy_s(str, "getBase");
		if (0 == RtlCopyMemory(GetModuleBase_msg, str, strlen(str) + 1)) {
#ifdef DBG_PRINT
			printf("RtlCopyMemory(GetModuleBase_msg) fail! Error: %u\n", GetLastError());
#endif // DBG_PRINT
			return 0;
		}
#ifdef DBG_PRINT
		printf("message has been sent to kernel [getBase]! \n");
#endif // DBG_PRINT
		UnmapViewOfFile(GetModuleBase_msg);

		WaitForSingleObject(SharedEvent_dataarv, INFINITE);

		GET_USERMODULE_IN_PROCESS* Sent_struct = (GET_USERMODULE_IN_PROCESS*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, sizeof(GET_USERMODULE_IN_PROCESS));

		if (!Sent_struct) {
#ifdef DBG_PRINT
			printf("Error MapViewOfFile(Sent_struct)\n");
#endif // DBG_PRINT
			return 0;
		}

		GET_USERMODULE_IN_PROCESS requestbase;

		requestbase.pid = pid;

		GET_USERMODULE_IN_PROCESS* test_ptr = &requestbase;
		if (0 == memcpy(Sent_struct, test_ptr, sizeof(GET_USERMODULE_IN_PROCESS))) {
#ifdef DBG_PRINT
			printf("Error copying memory with (memcpy) to struct\n");
#endif // DBG_PRINT
			return 0;
		}
#ifdef DBG_PRINT
		printf("PID : %u \n",requestbase.pid);
#endif // DBG_PRINT
		UnmapViewOfFile(Sent_struct);


		WaitForSingleObject(SharedEvent_ready2read, INFINITE);

		GET_USERMODULE_IN_PROCESS* getbase_struct = (GET_USERMODULE_IN_PROCESS*)MapViewOfFile(hMapFileR, FILE_MAP_READ, 0, 0, sizeof(GET_USERMODULE_IN_PROCESS));
		if (!getbase_struct)
		{
#ifdef DBG_PRINT
			printf("OpenFileMappingA(getbase_struct) fail! Error: %u\n", GetLastError());
#endif // DBG_PRINT
			return 0;
		}

		
		ULONG64 base = NULL;

		base = getbase_struct->BaseAddress;
#ifdef DBG_PRINT
			printf("Base address of dummy program : %p \n", getbase_struct->BaseAddress);
			printf("Base  : %p \n", base);
#endif // DBG_PRINT

		UnmapViewOfFile(getbase_struct);

		return base;
	}




	void createSecuritydesc() {
		// FFS see https://docs.microsoft.com/en-us/windows/desktop/SecAuthZ/creating-a-security-descriptor-for-a-new-object-in-c--
		// https://www.codeproject.com/Questions/536143/C-b-b-aplusGlobalpluseventplusopeningplusproble
		// https://docs.microsoft.com/en-us/windows/desktop/api/accctrl/ns-accctrl-_explicit_access_a

		//Creation of SID for the Everyone group
		if (!AllocateAndInitializeSid(
			&SIDAuthWorld,   //PSID_IDENTIFIER_AUTHORITY
			1,               //nSubAuthorityCount
			SECURITY_WORLD_RID,     //nSubAuthority0
			0, 0, 0, 0, 0, 0, 0,    //Not used subAuthorities.
			&pEveryoneSID))         //Callback argument that recieves pointer to the allocated and initialized SID structure
		{
#ifdef DBG_PRINT
			printf("AllocateAndInitializeSid() Error.\n", GetLastError());
			system("pause");
#endif // DBG_PRINT
		}

		//Filling in EXPLICIT_ACCESS structure. Everyone's group members will have all the permissions on event.
		ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
		ea[0].grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
		ea[0].grfAccessMode = SET_ACCESS;
		ea[0].grfInheritance = NO_INHERITANCE;
		ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		//ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
		ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
		ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

		//Creation of new ACL that contains the new ACE.
		dwRes = SetEntriesInAcl(1, ea, NULL, &pAcl);
		if (dwRes != ERROR_SUCCESS)
		{
#ifdef DBG_PRINT
			printf("SetEntriesInAcl() Error.\n", GetLastError());
			system("pause");
#endif // DBG_PRINT
		}

		//Security Descriptor initialization
		pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
		if (pSD == NULL)
		{
#ifdef DBG_PRINT
			printf("LocalAlloc() Error.\n", GetLastError());
			system("pause");
#endif // DBG_PRINT
		}

		if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
		{
#ifdef DBG_PRINT
			printf("InitializeSecurityDescriptor() Error.\n", GetLastError());
			system("pause");
#endif // DBG_PRINT
		}

		//Adding ACL to Security Descriptor.
		if (!SetSecurityDescriptorDacl(pSD, TRUE, pAcl, FALSE))
		{
#ifdef DBG_PRINT
			printf("SetSecurityDescriptorDacl() Error.\n", GetLastError());
			system("pause");
#endif // DBG_PRINT
		}

		//Initialize Security Attributes structure.
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.lpSecurityDescriptor = pSD;
		sa.bInheritHandle = FALSE;
	}


	void createConsMenu() {
		static const char* ConHdr = "==================================================\n"
			"|             Shmem driver by Frankoo            |\n"
			"| Press F8 to open shared memory.                |\n"
			"| Press F6 to write Memory!.         |\n"
			"| Press F9 to Trigger kernel loop!.         |\n"
			"==================================================\n\n";
		SetConsoleTitleA("Shmem driver by frankoo");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0xD);
		printf(ConHdr);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x5);
	}



	void CreateSharedEvents() {
		SharedEvent_dataarv = CreateEventA(&sa, TRUE, FALSE, "Global\\DataArrived");
		if (!SharedEvent_dataarv)
		{
#ifdef DBG_PRINT
			printf("CreateEventA fail! Error: %u\n", GetLastError());
			system("pause");
#endif // DBG_PRINT
		}
#ifdef DBG_PRINT
		printf("CreateEventA SUCESS (SharedEvent->(DataArrived)) ! \n");
#endif // DBG_PRINT

		SharedEvent_trigger = CreateEventA(&sa, TRUE, FALSE, "Global\\trigger");
		if (!SharedEvent_trigger)
		{
#ifdef DBG_PRINT
			printf("CreateEventA fail! Error: %u\n", GetLastError());
			system("pause");
#endif // DBG_PRINT
		}
#ifdef DBG_PRINT
		printf("CreateEventA SUCESS (SharedEvent->(trigger)) ! \n");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0xD);
#endif // DBG_PRINT


		SharedEvent_ready2read = CreateEventA(&sa, TRUE, FALSE, "Global\\ReadyRead");
		if (!SharedEvent_ready2read)
		{
#ifdef DBG_PRINT
			printf("CreateEventA fail! Error: %u\n", GetLastError());
			system("pause");
#endif // DBG_PRINT
		}
#ifdef DBG_PRINT
		printf("CreateEventA SUCESS (SharedEvent->(ready2read)) ! \n");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0xD);
#endif // DBG_PRINT
	}


	bool OpenSharedMemory() {
		hMapFileW = OpenFileMappingA(FILE_MAP_WRITE, FALSE, "Global\\SharedMem");
		if (!hMapFileW || hMapFileW == INVALID_HANDLE_VALUE)
		{
#ifdef DBG_PRINT
			printf("OpenFileMappingA(write) fail! Error: %u\n", GetLastError());
#endif // DBG_PRINT
			return false;
		}

		hMapFileR = OpenFileMappingA(FILE_MAP_READ, FALSE, "Global\\SharedMem");
		if (!hMapFileR || hMapFileR == INVALID_HANDLE_VALUE)
		{
#ifdef DBG_PRINT
			printf("OpenFileMappingA(read) fail! Error: %u\n", GetLastError());
#endif // DBG_PRINT
			return false;
		}
		printf("[Completed] SHared MEmory is available to use !.\n");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0xA);
		return true;
	}


	void GetPidNBaseAddr() {

		// Get PID

		PID = FindProcessId("dummy.exe");
		std::cout << "PID IS : " << PID << std::endl;

		// get base address
		baseaddr = GetModuleBase(PID);
		std::cout << "base address is : " << std::hex << baseaddr << std::endl;
	}

};

	

