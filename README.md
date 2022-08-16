# CShellcode
这是专门用C语言写ShellCode的模板
编译链接的命令
x86:
  cl.exe(x86) /GS- /TC /GL /W4 /O1 /nologo /Zl /FA /Os ./ShellCode.cpp
  link.exe(x86) /LTCG /ENTRY:"ExecutePayload" /OPT:REF /SAFESEH:NO /SUBSYSTEM:CONSOLE /MAP /ORDER:@"function_link_order.txt" /OPT:ICF /NOLOGO /NODEFAULTLIB
x64:
  cl.exe(x64) /GS- /TC /GL /W4 /O1 /nologo /Zl /FA /Os ./ShellCode.cpp
  link.exe(x64) /LTCG "./AdjustStack.obj" /ENTRY:"Begin" /OPT:REF /SAFESEH:NO /SUBSYSTEM:CONSOLE /MAP /ORDER:@"function_link_order64.txt" /OPT:ICF /NOLOGO /NODEFAULTLIB /out:<outputfilename.exe>
提取shellcode使用CFFExplorer
  
