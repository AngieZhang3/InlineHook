# Inline Hook
## Intro 
Inline hooking is a technique that modifies a program's execution flow by intercepting function calls. 
The process works by overwriting the first few bytes of a target function with a jump instruction (such as jmp, call, or retn),
which redirects execution to a custom hook function. 
When the program calls the target function, it first jumps to the hook function, executes the custom code, and then returns to continue the original function's execution. 
This method effectively creates a detour in the program's normal execution path, allowing for runtime modification of program behavior without changing the original source code.
## Implementation 
This project demonstrates the use of Inline Hooks to intercept two Windows APIs: CreateFileA and ReadFile. Below, we use ReadFile as an example to explain the hook implementation process.
### Steps to Implement the Hook
### 1. Locate the Target Function
The first step is identifying the memory address of the function to be intercepted, referred to as the "Target Function." <br>
In this project, the target functions are CreateFileA and ReadFile. To correctly locate their addresses, we analyzed them using x32dbg on Windows 7, 10, and 11.
For ReadFile, the disassembly varies across these operating systems:
- Windows 7:<br>
  The function call directly points to the entry of ReadFile.
  ![image](https://github.com/user-attachments/assets/f719a167-230f-4b54-95fd-9ae96fba277e)
- Windows 10 and 11:<br>
  The function call first jumps to a jmp instruction, which then redirects to the actual entry point of ReadFile.
  - Windows 10:
    ![image](https://github.com/user-attachments/assets/9377ea82-8792-45c0-b3d4-e9af864334cc)
    ![image](https://github.com/user-attachments/assets/e7259299-fc17-4b8b-93b4-4c8925b419ff)
  - Windows 11:
    ![image](https://github.com/user-attachments/assets/b532ba18-5043-447d-9475-79656c088c78)
    ![image](https://github.com/user-attachments/assets/b17e3082-3595-49a2-a0d4-908053a31992)
    
From this analysis, we observe two cases:
- On Windows 7, we can directly retrieve the address of ReadFile using GetProcAddress().
- On Windows 10 and 11, we must resolve the jump instruction to find the actual entry point of ReadFile. For example, in Windows 11, after inspecting the jump address (e.g., 777C11EC), we find it points to the start address of ReadFile.
  ![image](https://github.com/user-attachments/assets/a0414338-20a9-432f-97f5-86a884c1abbe)
  ![image](https://github.com/user-attachments/assets/08ec42db-1df0-4738-8945-e38a5e4df341)

The following code demonstrates how to locate the address of ReadFile across these cases:
```
    //get module name
	HMODULE hModule = GetModuleHandle("kernel32.dll");
	if (!hModule) {
		printf("failed to get hModule");
		return -1;
	}
	// Retrieve the original address of the ReadFile function
	PBYTE originalReadFile = (PBYTE)GetProcAddress(hModule, "ReadFile");

	if (!originalReadFile) {
		printf("failed to get orginal ReadFile Address");
		return -1;
	}
	// Check if ReadFile starts with a JMP instruction
	if (*(WORD*)originalReadFile == 0x25FF) {
		// JMP + pointer to another memory location containing the actual function address
		DWORD indirectPointer = *(DWORD*)(originalReadFile + 2);
		// dereference the pointer to get the real address of the function
		DWORD realAddress = *(DWORD*)indirectPointer;
		g_pReadFileFunc = (PBYTE)realAddress;
	}
	else {
		//  If no JMP, use original address as entry point
		g_pReadFileFunc = originalReadFile;
	}
```
### 2. Backup Original Instructions
Save the first few bytes of the target function's instructions, which will be overwritten. These saved instructions are used later in the trampoline function to ensure proper execution. 
From the analysis of the ReadFile function, there are two possible cases for its starting instructions:
- Case 1: The function starts with two push instructions followed by a call. These two push instructions take up 7 bytes.
- Case 2: The function starts with mov edi, edi, followed by push ebp, and then mov ebp, esp. These instructions take up 5 bytes. <br>

To implement the hook, we replace the first 5 bytes of the target function with a jmp instruction (1 byte) and a 4-byte offset. However, to ensure proper execution of the trampoline function, we back up:
   - The first 7 bytes for Case 1.
   - The first 5 bytes for Case 2.
     
The following code demonstrates how to handle these two cases:
```
	if (*(BYTE*)g_pReadFileFunc == 0x8B) {
		//case 2: start with mov edi, edi
		g_jmpBackAddrReadFile = g_pReadFileFunc + 5;
		memcpy(g_oldCode, g_pReadFileFunc, 5);
	}
	else if (*(BYTE*)g_pReadFileFunc == 0x6A) {
		// case 1: start with push
		// save the first 7 bytes from the entry point of readFile
		memcpy(g_oldCode, g_pReadFileFunc, 7);
		g_pushVal1 = (DWORD) * (BYTE*)(g_oldCode + 1); // Extract value from first push
		g_pushVal2 = *(DWORD*)(g_oldCode + 3); 		// Extract value from second push
		g_jmpBackAddrReadFile = g_pReadFileFunc + 7;
		g_bIsPush = TRUE;
	}
	else {
		printf(" special instruction");
		return -1;
	}
```
### 3. Insert a Detour (Hook) Function
To intercept the target function, we overwrite its initial instructions with a jmp or call instruction that redirects execution to a custom "Detour Function." In this project, we created the HookedReadFile() function as the detour function.

The detour function must match the target function in terms of return value, calling convention, and arguments to ensure compatibility. Within HookedReadFile(), we call the original ReadFile function using a trampoline function and capture the content read by ReadFile (stored in lpBuffer). This content is then saved to a text file (result.txt) for logging purposes.

Below is the implementation of the detour function:
```
BOOL WINAPI HookedReadFile(HANDLE hFile,
	LPVOID lpBuffer,
	DWORD nNumberOfBytesToRead,
	LPDWORD lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped) {
	BOOL result;
    	// Call the original ReadFile via the appropriate trampoline function
	if (g_bIsPush) {
		result = TrampolineReadFileLong(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	}
	else {
		result = TrampolineReadFileShort(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	}
  	// If the target module is detected and data is successfully read, save it to a file
	if (IsTargetModule() && result && *lpNumberOfBytesRead > 0) {
		saveBufferToFile("result.txt", lpBuffer, *lpNumberOfBytesRead);
		printf("printing lpBuffer: %s\n numberRead: %d\n", lpBuffer, *lpNumberOfBytesRead);
	}
#ifdef _DEBUG
    	// Debugging: Print the file path being accessed
	TCHAR path[MAX_PATH];
	DWORD dwRet;
	dwRet = GetFinalPathNameByHandle(hFile, path, MAX_PATH,
		FILE_NAME_NORMALIZED);
	printf("file path is: %s\n", path);

#endif

	return result;
}
```
