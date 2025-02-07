## Concept
Inline hooking is a technique that modifies a program's execution flow by intercepting function calls. 
The process works by overwriting the first few bytes of a target function with a jump instruction (such as jmp, call, or retn),
which redirects execution to a custom hook function. 
When the program calls the target function, it first jumps to the hook function, executes the custom code, and then returns to continue the original function's execution. 
This method effectively creates a detour in the program's normal execution path, allowing for runtime modification of program behavior without changing the original source code.
