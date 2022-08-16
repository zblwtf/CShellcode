#pragma once
#pragma once
#include <Windows.h>
#include "��ͷ1.h"
#include "��ͷ2.h"
#define IndexKernelMax 22
#define IndexUser32Max 2
#define IndexWs2Max 9
#define CAPI _cdecl

	typedef BOOL(WINAPI* WSASTARTUP)(WORD, LPWSADATA);
	typedef BOOL(WINAPI* WRITEFILE)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
	typedef BOOL(WINAPI* READFILE)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
	typedef BOOL(WINAPI* MESSAGEBOXA)(HANDLE, LPCSTR, LPCSTR, UINT);
	typedef HANDLE(WINAPI* GETSTDHANDLE)(DWORD);
	typedef BOOL(WINAPI* ALLOCCONSOLE)(void);
	typedef BOOL(WINAPI* GETCONSOLETITLE)(LPTSTR, DWORD);
	typedef BOOL(WINAPI* GETCONSOLESCREENBUFFERINFO)(HANDLE, PCONSOLE_SCREEN_BUFFER_INFO);
	typedef BOOL(WINAPI* WRITECONSOLE)(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);
	typedef BOOL(WINAPI* READCONSOLE)(HANDLE, LPVOID, DWORD, LPDWORD, LPVOID);
	typedef BOOL(WINAPI* CREATEPROCESSA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
	typedef BOOL(WINAPI* CRERATEPIPE)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
	typedef HMODULE(WINAPI* GETMODULEHANDLEW)(LPCWSTR);
	typedef HANDLE(WINAPI* GETCURRENTTHREAD)(void);
	typedef DWORD(WINAPI* GETCURRENTTHREADID)(void);
	typedef HANDLE(WINAPI* GETCURRENTTHREADTOKEN)(void);
	typedef HANDLE(WINAPI* CREATEFILEA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
	typedef DWORD(WINAPI* GETFILESIZE)(HANDLE, LPDWORD);
	typedef LPVOID(WINAPI* HEAPALLOC)(HANDLE, DWORD, SIZE_T);
	typedef BOOL(WINAPI* CLOSEHANDLE)(HANDLE);
	typedef HANDLE(WINAPI* OPENPROCESS)(DWORD, BOOL, DWORD);
	typedef DWORD(WINAPI* WAITFORSINGLEOBJECT)(HANDLE, DWORD);
	typedef BOOL(WINAPI* HEAPFREE)(HANDLE, DWORD, LPVOID);
	typedef HANDLE(WINAPI* GETPROCESSHEAP)(void);
	typedef BOOL(WINAPI* MESSAGEBOXA)(HANDLE, LPCSTR, LPCSTR, UINT);
	typedef BOOL(WINAPI* MESSAGEBOXW)(HANDLE, LPCWSTR, LPCWSTR, UINT);
	typedef BOOL(WINAPI* WSASTARTUP)(WORD, LPWSADATA);
	typedef int(WINAPI* WSACLEANUP)(void);
	typedef int (WINAPI* WSAGETLASTERROR)(void);
	typedef UINT_PTR (WINAPI* GETSOCKET) (int, int, int);
	typedef int (WINAPI* CONNECT)(UINT_PTR,LPVOID, int);
	typedef int (WINAPI* RECV)(UINT_PTR, LPCSTR, UINT, UINT);
	typedef int(WINAPI* SEND)(UINT_PTR, LPCSTR, UINT, int);
	typedef USHORT(WINAPI* HTONS)(USHORT);
	typedef BOOL(WINAPI* SHUTDOWN)(UINT_PTR, UINT);
	typedef PVOID(WINAPI* RTLALLOCATEHEAP)(PVOID, ULONG, SIZE_T);
	typedef DWORD(NTAPI* NTFLUSHINSTRUCTIONCACHE)(HANDLE, PVOID, ULONG);
	typedef int(CAPI* PRINTF)(LPCSTR,...);

