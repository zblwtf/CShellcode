About
=====

Cshellcode is a template for writing shellcode in C


Overview
========

Just nothing

Build
=====

Open the 'CShellCode.sln' file in Visual Studio C++ and Control + ~ into the PowerShell in developer mode then 
+ In case of x64 architecture:  
`cl.exe(x64) /GS- /TC /GL /W4 /O1 /nologo /Zl /FA /Os ./ShellCode.cpp`
`link.exe(x64) /LTCG "./AdjustStack.obj" /ENTRY:"Begin" /OPT:REF /SAFESEH:NO /SUBSYSTEM:CONSOLE /MAP /ORDER:@"function_link_order64.txt" /OPT:ICF /NOLOGO /NODEFAULTLIB /out:<outputfilename>.exe`  
+ In case of x64 architecture:  
`cl.exe(x86) /GS- /TC /GL /W4 /O1 /nologo /Zl /FA /Os ./ShellCode.cpp`
`/LTCG /ENTRY:"ExecutePayload" /OPT:REF /SAFESEH:NO /SUBSYSTEM:CONSOLE /MAP /ORDER:@"function_link_order.txt" /OPT:ICF /NOLOGO /NODEFAULTLIB /out:<outputfilename>.exe`  
    


  
