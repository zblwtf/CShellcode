#include "ReflectiveDLLInjection.h"
#include "shellcode.h"

#pragma warning( disable : 4201 )
typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;
#define GET_API(a,b,c) (c)GetProcAddressWithHash(a,b)
// This compiles to a ROR instruction
// This is needed because _lrotr() is an external reference
// Also, there is not a consistent compiler intrinsic to accomplish this across all three platforms.

LPVOID GetProcAddressWithHash(DWORD dwModuleHash_,DWORD dwFunctionHash_)
{
	PPEB PebAddress;
	PMY_PEB_LDR_DATA pLdr;
	PMY_LDR_DATA_TABLE_ENTRY pDataTableEntry;
	PVOID pModuleBase;
	PIMAGE_NT_HEADERS pNTHeader;
	DWORD dwExportDirRVA;
	PIMAGE_EXPORT_DIRECTORY pExportDir;
	PLIST_ENTRY pNextModule;
	DWORD dwNumFunctions;
	USHORT usOrdinalTableIndex;
	PDWORD pdwFunctionNameBase;
	PCSTR pFunctionName;
	UNICODE_STRING BaseDllName;
	DWORD dwModuleHash;
	DWORD dwFunctionHash;
	PCSTR pTempChar;
	DWORD i;


#if defined(_WIN64)
	PebAddress = (PPEB)__readgsqword(0x60);
#elif defined(_M_ARM)
	// I can assure you that this is not a mistake. The C compiler improperly emits the proper opcodes
	// necessary to get the PEB.Ldr address
	PebAddress = (PPEB)((ULONG_PTR)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0);
	__emit(0x00006B1B);
#else
	PebAddress = (PPEB)__readfsdword(0x30);
#endif


	pLdr = (PMY_PEB_LDR_DATA)PebAddress->Ldr;
	pNextModule = pLdr->InLoadOrderModuleList.Flink;
	pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pNextModule;

	while (pDataTableEntry->DllBase != NULL)
	{
		dwModuleHash = 0;
		pModuleBase = pDataTableEntry->DllBase;
		BaseDllName = pDataTableEntry->BaseDllName;
		pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModuleBase + ((PIMAGE_DOS_HEADER)pModuleBase)->e_lfanew);
		dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress;

		// Get the next loaded module entry
		pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;

		// If the current module does not export any functions, move on to the next module.
		if (dwExportDirRVA == 0)
		{
			continue;
		}
		

		for (i = 0; i < BaseDllName.MaximumLength; i++)
		{
			pTempChar = ((PCSTR)BaseDllName.Buffer + i);

			dwModuleHash = ROTR32(dwModuleHash, 13);

			if (*pTempChar >= 'a')
			{
				dwModuleHash += *pTempChar - 0x20;
			}
			else
			{
				dwModuleHash += *pTempChar;
			}
		}
		if (dwModuleHash != dwModuleHash_)
			continue;
		pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pModuleBase + dwExportDirRVA);

		dwNumFunctions = pExportDir->NumberOfNames;
		pdwFunctionNameBase = (PDWORD)((PCHAR)pModuleBase + pExportDir->AddressOfNames);

		for (i = 0; i < dwNumFunctions; i++)
		{
			dwFunctionHash = 0;
			pFunctionName = (PCSTR)(*pdwFunctionNameBase + (ULONG_PTR)pModuleBase);
			pdwFunctionNameBase++;

			pTempChar = pFunctionName;

			do
			{
				dwFunctionHash = ROTR32(dwFunctionHash, 13);
				dwFunctionHash += *pTempChar;
				pTempChar++;
			} while (*(pTempChar - 1) != 0);
			if (dwFunctionHash == dwFunctionHash_)
			{
				usOrdinalTableIndex = *(PUSHORT)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfNameOrdinals) + (2 * i));
				return (HMODULE)((ULONG_PTR)pModuleBase + *(PDWORD)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfFunctions) + (4 * usOrdinalTableIndex)));
			}
		}
	}

	// All modules have been exhausted and the function was not found.
	return NULL;
}
//DLLEXPORT void CallShellCode()
//{
//	LOADLIBRARYA pLoadLibraryA = NULL;
//	GETPROCADDRESS pGetProcAddress = NULL;
//	CREATEFILEA pCreateFileA = NULL;
//	MESSAGEBOXA pMessageBoxA = NULL;
//	GETFILESIZE pGetFileSize = NULL;
//	VIRTUALALLOC pVirtualAlloc = NULL;
//	GETPROCESSHEAP pGetProcessHeap = NULL;
//	LPVOID lpHeap = NULL;
//	PRINTF pprintf = NULL;
//	HANDLE hFile = NULL;
//	DWORD dwFileSize = NULL;
//	READFILE pReadFile = NULL;
//	ULONG_PTR ULValueA = 0;
//	DWORD dwValueA = 0;
//	char __0[] = { 'u','s','e','r','3','2','.','d','l','l','\x0' };
//	char __1[] = { 'w','s','2','_','3','2','.','d','l','l','\x0' };
//	char __2[] = { 'm','s','v','c','r','t','.','d','l','l','\x0' };
//	char __3[] = { '%','s','\x0' };
//	char path1[] = { 'C',':','/','U','s','e','r','s' };
//	char path2[] = { '/','2','3','0','3','5','/','D','e','s','k' };
//	char path3[] ={'t','o','p','/','d','a','t','a','.','t','x','t','\x0' };
//	
//	char path[33];
//	char* temp = path;
//	int i = 0;
//	for (i = 0; i < 8; i++)
//	{
//		*temp++ = path1[i];
//	}
//	for (i = 0; i <11; i++)
//	{
//		*temp++ = path2[i];
//	}
//	for (i = 0; i < 13; i++)
//	{
//		*temp++ = path3[i];
//	}
//	pLoadLibraryA = GET_API(KERNEL32HASH, kern_LoadLibraryA, LOADLIBRARYA);
//	pLoadLibraryA(__0);
//	pLoadLibraryA(__1);
//	pLoadLibraryA(__2);
//	pprintf = GET_API(MSVCHASH, msvc_printf, PRINTF);
//	pMessageBoxA = GET_API(USER32HASH, user_MessageBoxA, MESSAGEBOXA);
//	pGetProcAddress = GET_API(KERNEL32HASH, kern_GetProcAddress, GETPROCADDRESS);
//	pCreateFileA = GET_API(KERNEL32HASH, kern_CreateFileA, CREATEFILEA);
//	pReadFile = GET_API(KERNEL32HASH, kern_ReadFile, READFILE);
//	pGetFileSize = GET_API(KERNEL32HASH, kern_GetFileSize, GETFILESIZE);
//	pVirtualAlloc = GET_API(KERNEL32HASH, kern_VirtualAlloc, VIRTUALALLOC);
//	pGetProcessHeap = GET_API(KERNEL32HASH, kern_GetProcessHeap, GETPROCESSHEAP);
//	hFile = pCreateFileA(path, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
//	dwFileSize = pGetFileSize(hFile, NULL);
//	ULValueA = (ULONG_PTR)pGetProcessHeap();
//	if (ULValueA == NULL)
//		return;
//   lpHeap = pVirtualAlloc(NULL, dwFileSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
//   if (lpHeap == NULL)
//	   return;
//	pReadFile(hFile, lpHeap, dwFileSize, &dwValueA, NULL);
//	if (dwValueA == NULL)
//		return;
//	pprintf(__3, (PCSTR)lpHeap);
//}
 VOID  ReflectiveLoader(LPVOID lpFileBase)
{
	ULONG_PTR uiLibraryAddress = (ULONG_PTR)lpFileBase;
	LOADLIBRARYA pLoadLibraryA = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	MESSAGEBOXA pMessageBoxA = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;
	PRINTF pprintf = NULL;
	ULONG_PTR uiHeaderValue = 0;
	ULONG_PTR uiBaseAddress = 0;
	ULONG_PTR uiValueA = 0;
	ULONG_PTR uiValueB = 0;
	ULONG_PTR uiValueC = 0;
	ULONG_PTR uiValueD = 0;
	ULONG_PTR uiValueE = 0;
	ULONG_PTR uiExportDir = 0;
	ULONG_PTR uiNameArray = 0;
	ULONG_PTR uiAddressArray = 0;

	char User32_Path[] = { 'u','s','e','r','3','2','.','d','l','l','\x0' };
	char MSVC_Path[] = { 'm','s','v','c','r','t','.','d','l','l','\x0' };
	pLoadLibraryA = GET_API(KERNEL32HASH, kern_LoadLibraryA, LOADLIBRARYA);
	pLoadLibraryA(User32_Path);
	pLoadLibraryA(MSVC_Path);
	pGetProcAddress = GET_API(KERNEL32HASH, kern_GetProcAddress, GETPROCADDRESS);
	pprintf = GET_API(MSVCHASH, msvc_printf, PRINTF);
	pVirtualAlloc = GET_API(KERNEL32HASH, kern_VirtualAlloc, VIRTUALALLOC);
	pNtFlushInstructionCache = GET_API(NTDLLHASH,ntdl_NtFlushInstructionCache , NTFLUSHINSTRUCTIONCACHE);
	

	
	uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	uiBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// we must now copy over the headers
	uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	uiValueB = uiLibraryAddress;
	uiValueC = uiBaseAddress;

	while (uiValueA--)
		*(BYTE*)uiValueC++ = *(BYTE*)uiValueB++;

	// STEP 3: load in all of our sections...

	// uiValueA = the VA of the first section
	uiValueA = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader);

	// itterate through all sections, loading them into memory.
	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	while (uiValueE--)
	{
		// uiValueB is the VA for this section
		uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);

		// uiValueC if the VA for this sections data
		uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);

		// copy the section over
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

		while (uiValueD--)
			*(BYTE*)uiValueB++ = *(BYTE*)uiValueC++;

		// get the VA of the next section
		uiValueA += sizeof(IMAGE_SECTION_HEADER);
	}

	// STEP 4: process our images import table...

	// uiValueB = the address of the import directory
	uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

	// itterate through all imports
	while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		uiLibraryAddress = (ULONG_PTR)pLoadLibraryA((LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));

		// uiValueD = VA of the OriginalFirstThunk
		uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);

		// itterate through all imported functions, importing by ordinal if no name present
		while (DEREF(uiValueA))
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// get the VA of the modules NT Header
				uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// get the VA of the export directory
				uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

				// get the VA for the array of addresses
				uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
			}
			else
			{
				// get the VA of this functions import by name struct
				uiValueB = (uiBaseAddress + DEREF(uiValueA));

				// use GetProcAddress and patch in the address for this imported function
				DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
			}
			// get the next imported function
			uiValueA += sizeof(ULONG_PTR);
			if (uiValueD)
				uiValueD += sizeof(ULONG_PTR);
		}

		// get the next import
		uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// check if their are any relocations present
	if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size)
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

		// and we itterate through all entries...
		while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock)
		{
			// uiValueA = the VA for this relocation block
			uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

			// uiValueB = number of entries in this relocation block
			uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while (uiValueB--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
					*(ULONG_PTR*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

				// get the next entry in the current relocation block
				uiValueD += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}


	uiValueA = (uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0);
	((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, NULL);
	uiValueA;
}