# Inline Hook
## Intro 
Inline hooking is a technique that modifies a program's execution flow by intercepting function calls. 
The process works by overwriting the first few bytes of a target function with a jump instruction (such as jmp, call, or retn),
which redirects execution to a custom hook function. 
When the program calls the target function, it first jumps to the hook function, executes the custom code, and then returns to continue the original function's execution. 
This method effectively creates a detour in the program's normal execution path, allowing for runtime modification of program behavior without changing the original source code.
## Implementation 
This project demonstrates the use of Inline Hooks to intercept two Windows APIs: CreateFileA and ReadFile. Below, I use ReadFile as an example to explain the hook implementation process.
### Steps to Implement the Hook
### 1. Locate the Target Function
The first step is identifying the memory address of the function to be intercepted, referred to as the "Target Function." In this project, the target functions are CreateFileA and ReadFile. To correctly locate their addresses, I analyzed them using x32dbg on Windows 7, 10, and 11.
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


