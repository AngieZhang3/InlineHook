// InlineHook.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>

BYTE g_oldCode[7] = { 0 }; // save old code for readFile
DWORD g_pushVal1;
DWORD g_pushVal2;
PBYTE g_pReadFileFunc; // entry point of the ReadFile function
PBYTE g_jmpBackAddrReadFile;  // jmp address for readFile
BOOL g_bIsPush = FALSE;

PBYTE g_pCreateFileAFunc; // entry point of the CreateFile function
PBYTE g_jmpBackAddrCreateFileA;  // jmp back address for createFile
BYTE g_savedCode[5] = { 0 }; // save old code for CreateFile

//Check if the module name matches the target program
BOOL IsTargetModule() {
	HMODULE hModule;
	char moduleName[MAX_PATH];
	hModule = GetModuleHandle(NULL);
	if (hModule == NULL) {
		return FALSE;
	}

	if (GetModuleFileNameA(hModule, moduleName, MAX_PATH)) {
		//Check if the module name matches the target program
		if (strstr(moduleName, "InlineHook.exe")) {
			return TRUE;
		}
	}

	return FALSE;
}

// write the content to a txt file
int saveBufferToFile(const char* fileName, LPVOID lpBuffer, DWORD dwSize) {

	FILE* file = fopen(fileName, "ab");
	if (file == NULL) {
		printf("Failed to open file. errno: %d\n", errno);
		return -1;
	}

	size_t nWritten = fwrite(lpBuffer, 1, dwSize, file);
	fflush(file);
	fclose(file);

	return (nWritten == dwSize) ? 0 : -1;
}

/*=======================Hook CreateFileA ====================*/

// trampoline function for CreateFileA
__declspec(naked) HANDLE WINAPI TrampolineCreateFileA(LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile) {
	__asm {
		mov edi, edi
		push ebp
		mov ebp, esp
		jmp g_jmpBackAddrCreateFileA;
	}
}

// HookedCreateFileA function
HANDLE HookedCreateFileA(
	LPCSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
) {
	HANDLE handle = TrampolineCreateFileA(lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile);
	if (handle && lpFileName && IsTargetModule()) {
		// save file name to result.txt
		printf("printing file name: %s\n", lpFileName);
		//Calculate the length of the new string(prefix + file name + '\n')
		int prefixLen = strlen("File name: ");
		int fileNameLen = strlen(lpFileName);
		int totalLen = prefixLen + fileNameLen + 1; // add \n

		char* szFileName = new char[totalLen + 1]; // add '\0'
		strcpy(szFileName, "File name: ");
		strcat(szFileName, lpFileName);
		szFileName[totalLen - 1] = '\n';
		szFileName[totalLen] = '\0';
		saveBufferToFile("result.txt", szFileName, totalLen);
		delete[] szFileName;
	}
	return handle;
}

// install hook
int InstallHookCreateFileA() {
	//get module name
	HMODULE hModule = GetModuleHandle("kernel32.dll");
	if (!hModule) {
		printf("failed to get hModule");
		return -1;
	}
	// get the original address of the CreateFileA function
	PBYTE originalCreateFileA = (PBYTE)GetProcAddress(hModule, "CreateFileA");

	if (!originalCreateFileA) {
		printf("failed to get orginal CreateFileA Address");
		return -1;
	}

	// get the first two bytes of CreateFile to check if it starts with a jmp
	if (*(WORD*)originalCreateFileA == 0x25FF) {
		// JMP + pointer to another memory location that contains the actual address of the function
		DWORD indirectPointer = *(DWORD*)(originalCreateFileA + 2);
		// dereference the pointer to get the real address of the function
		DWORD realAddress = *(DWORD*)indirectPointer;
		g_pCreateFileAFunc = (PBYTE)realAddress;
	}
	else {
		// if not start with JMP, the original address get from GetProcAddress  is the entry point of the CreateFile function
		g_pCreateFileAFunc = originalCreateFileA;
	}

	// prepare the jmp instruction: jmp + 4-byte relative offset
	BYTE newEntry[5] = { 0 };
	newEntry[0] = 0xE9;  //jmp
	// calculate the offset between next instrution right after jmp and the hook function
	//offset = HookedFunAddr - SystemFunc - CodeLength
	DWORD dwOffset;
	dwOffset = (DWORD)HookedCreateFileA - (DWORD)g_pCreateFileAFunc - 5;
	*(DWORD*)(newEntry + 1) = dwOffset;

	//change the memory protection constant
	DWORD dwOldProtect;
	MEMORY_BASIC_INFORMATION MBI = { 0 };
	VirtualQuery(g_pCreateFileAFunc, &MBI, sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(MBI.BaseAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	// save the old code
	memcpy(g_savedCode, g_pCreateFileAFunc, 5);
	g_jmpBackAddrCreateFileA = g_pCreateFileAFunc + 5;

	// change the firt 5 bytes of the entry point to jmp offset
	memcpy(g_pCreateFileAFunc, newEntry, 5);
	// change back the memory protection constant
	VirtualProtect(MBI.BaseAddress, 5, dwOldProtect, &dwOldProtect);
	return 0;
}
// Uninstall Hook
int UninstallHookCreateFileA() {
	//get module name
	HMODULE hModule = GetModuleHandle("kernel32.dll");
	if (!hModule) {
		printf("failed to get hModule");
		return -1;
	}
	// get the original address of the CreateFileA function
	PBYTE originalCreateFileA = (PBYTE)GetProcAddress(hModule, "CreateFileA");

	if (!originalCreateFileA) {
		printf("failed to get orginal CreateFileA Address");
		return -1;
	}

	// change the memory protection 
		//change the memory protection constant
	DWORD dwOldProtect;
	MEMORY_BASIC_INFORMATION MBI = { 0 };
	VirtualQuery(g_pCreateFileAFunc, &MBI, sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(MBI.BaseAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//restore the old code
	memcpy(g_pCreateFileAFunc, g_savedCode, 5);
	// change back the memory protection constant
	VirtualProtect(MBI.BaseAddress, 5, dwOldProtect, &dwOldProtect);
	printf("uninstall CreateFileA");
	return 0;

}
/*=========================Hook ReadFile=============================*/
// create the Trampoline function 
// if function starts with push xx, push xxxx, call :
__declspec(naked) BOOL WINAPI TrampolineReadFileLong(HANDLE hFile,
	LPVOID lpBuffer,
	DWORD nNumberOfBytesToRead,
	LPDWORD lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped) {

	__asm {
		push g_pushVal1
		push g_pushVal2
		jmp g_jmpBackAddrReadFile
	}

}

// if the function start with mov edi, edi
__declspec(naked) BOOL WINAPI TrampolineReadFileShort(HANDLE hFile,
	LPVOID lpBuffer,
	DWORD nNumberOfBytesToRead,
	LPDWORD lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped) {
	__asm {
		mov edi, edi
		push ebp
		mov ebp, esp
		jmp g_jmpBackAddrReadFile;
	}
}


BOOL WINAPI HookedReadFile(HANDLE hFile,
	LPVOID lpBuffer,
	DWORD nNumberOfBytesToRead,
	LPDWORD lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped) {
	BOOL result;
	if (g_bIsPush) {
		result = TrampolineReadFileLong(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	}
	else {
		result = TrampolineReadFileShort(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	}

	if (IsTargetModule() && result && *lpNumberOfBytesRead > 0) {
		saveBufferToFile("result.txt", lpBuffer, *lpNumberOfBytesRead);
		printf("printing lpBuffer: %s\n numberRead: %d\n", lpBuffer, *lpNumberOfBytesRead);
	}
#ifdef _DEBUG
	TCHAR path[MAX_PATH];
	DWORD dwRet;
	dwRet = GetFinalPathNameByHandle(hFile, path, MAX_PATH,
		FILE_NAME_NORMALIZED);
	printf("file path is: %s\n", path);

#endif

	return result;
}

//Install Hook
int InstallHookReadFile() {
	//get module name
	HMODULE hModule = GetModuleHandle("kernel32.dll");
	if (!hModule) {
		printf("failed to get hModule");
		return -1;
	}
	// get the original address of the ReadFile function
	PBYTE originalReadFile = (PBYTE)GetProcAddress(hModule, "ReadFile");

	if (!originalReadFile) {
		printf("failed to get orginal ReadFile Address");
		return -1;
	}
	// get the first two bytes of readfile to check if it starts with a jmp
	if (*(WORD*)originalReadFile == 0x25FF) {
		// JMP + pointer to another memory location that contains the actual address of the function
		DWORD indirectPointer = *(DWORD*)(originalReadFile + 2);
		// dereference the pointer to get the real address of the function
		DWORD realAddress = *(DWORD*)indirectPointer;
		g_pReadFileFunc = (PBYTE)realAddress;
	}
	else {
		// if not start with JMP, the original address get from GetProcAddress  is the entry point of the ReadFile function
		g_pReadFileFunc = originalReadFile;
	}

	// prepare the jmp instruction: jmp + 4-byte relative offset
	BYTE newEntry[5] = { 0 };
	newEntry[0] = 0xE9;  //jmp
	// calculate the offset between next instrution right after jmp and the hook function
	//offset = HookedFunAddr - SystemFunc - CodeLength
	DWORD dwOffset;
	dwOffset = (DWORD)HookedReadFile - (DWORD)g_pReadFileFunc - 5;
	*(DWORD*)(newEntry + 1) = dwOffset;

	//change the memory protection constant
	DWORD dwOldProtect;
	MEMORY_BASIC_INFORMATION MBI = { 0 };
	VirtualQuery(g_pReadFileFunc, &MBI, sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(MBI.BaseAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	if (*(BYTE*)g_pReadFileFunc == 0x8B) {
		//start with mov edi, edi
		g_jmpBackAddrReadFile = g_pReadFileFunc + 5;
	}
	else if (*(BYTE*)g_pReadFileFunc == 0x6A) {
		// start with push 
			// save the first 7 bytes from the entry point of readFile
		memcpy(g_oldCode, g_pReadFileFunc, 7);
		g_pushVal1 = (DWORD) * (BYTE*)(g_oldCode + 1);
		g_pushVal2 = *(DWORD*)(g_oldCode + 3);
		g_jmpBackAddrReadFile = g_pReadFileFunc + 7;
		g_bIsPush = TRUE;
	}
	else {
		printf(" special instruction");
		return -1;
	}

	// change the firt 5 bytes of the entry point to jmp offset
	memcpy(g_pReadFileFunc, newEntry, 5);
	// change back the memory protection constant
	VirtualProtect(MBI.BaseAddress, 5, dwOldProtect, &dwOldProtect);
	return 0;
}

// Uninstall Hook
int UninstallHookReadFile() {
	//get module name
	HMODULE hModule = GetModuleHandle("kernel32.dll");
	if (!hModule) {
		printf("failed to get hModule");
		return -1;
	}
	// get the original address of the ReadFile function
	PBYTE originalReadFile = (PBYTE)GetProcAddress(hModule, "ReadFile");

	if (!originalReadFile) {
		printf("failed to get orginal ReadFile Address");
		return -1;
	}

	// change the memory protection 
		//change the memory protection constant
	DWORD dwOldProtect;
	MEMORY_BASIC_INFORMATION MBI = { 0 };
	VirtualQuery(g_pReadFileFunc, &MBI, sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(MBI.BaseAddress, 7, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// copy the old code back
	if (g_bIsPush) {
		memcpy(g_pReadFileFunc, g_oldCode, 7);
	}
	else {
		memcpy(g_pReadFileFunc, g_oldCode, 5);
	}

	// change back the memory protection constant
	VirtualProtect(MBI.BaseAddress, 7, dwOldProtect, &dwOldProtect);
	return 0;

}


int main()
{
	InstallHookCreateFileA();
	HANDLE hFile = CreateFile("test.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Failed to open file. Error: %lu\n", GetLastError());
		system("pause");
		return 1;
	}

	char buffer[128] = { 0 };
	DWORD bytesRead;
	if (ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
		buffer[bytesRead] = '\0'; // Null-terminate the string
		printf("File content:\n%s\n", buffer);
	}
	else {
		printf("Failed to read file. Error: %lu\n", GetLastError());
	}

	//Install hook
	if (InstallHookReadFile() != 0) {
		printf("Failed to install hook\n");
		return 1;
	}


	// reset file pointer to beginning of file
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

	printf("\nReading file after hook:\n");
	if (ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
		buffer[bytesRead] = '\0';
		printf("File content:\n%s\n", buffer);
	}
	else {
		printf("Failed to read file. Error: %lu\n", GetLastError());
	}

	CloseHandle(hFile);

	return 0;
}


