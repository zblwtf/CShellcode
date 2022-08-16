#pragma once
#include <Windows.h>
#define IndexKernelMax 22
#define IndexUser32Max 2
#define IndexWs2Max 9
	
namespace API
{
	typedef enum
	{
		WriteFile = 0,
		ReadFile,
		AllocConsole,
		GetStdHandle,
		GetConsoleTitle,
		GetConsoleScreenBufferInfo,
		WriteConsole,
		ReadConsole,
		CreateProcessA,
		CreatePipe,
		GetModuleHandleW,
		GetCurrentThread,
		GetCurrentThreadId,
		GetCurrentThreadToken,
		CreateFileA,
		GetFileSize,
		HeapAlloc,
		CloseHandle,
		OpenProcess,
		WaitForSingleObject,
		HeapFree,
		GetProcessHeap
	}IndexKernel32;

	LPCSTR FNA_Kernel32[IndexKernelMax] = { "WriteFile","ReadFile","AllocConsole","GetStdHandle","GetConsoleTitle","GetConsoleScreenBufferInfo","WriteConsole",
											"ReadConsole","CreateProcessA","CreatePipe","GetModuleHandleW","GetCurrentThread","GetCurrentThreadId","GetCurrentThreadToken"
											"CreateFileA","GetFileSize","HeapAlloc","CloseHandle","OpenProcess","WaitForSingleObject","HeapFree","GetProcessHeap" };
}

	namespace BaseApi
	{
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
		typedef SOCKET(WINAPI* SOCKET)(int, int, int);
		typedef int (WINAPI* CONNECT)(::SOCKET, const sockaddr*, int);
		typedef int (WINAPI* RECV)(::SOCKET, LPCSTR, UINT, UINT);
		typedef int(WINAPI* SEND)(::SOCKET, LPCSTR, UINT, int);
		typedef USHORT(WINAPI* HTONS)(USHORT);
		typedef BOOL(WINAPI* SHUTDOWN)(::SOCKET, UINT);




		
		typedef enum
		{
			MessageBoxA = 22,
			MessageBoxW
		}IndexUser32;
		LPCSTR FNA_User32[IndexUser32Max] = { "MessageBoxA","MessageBoxW" };
		typedef  enum
		{

			WSAStartup = 24,
			WSACleanup,
			WSAGetLastError,
			socket,
			connect,
			recv,
			send,
			htons,
			shutdown
		}IndexWs2;
		LPCSTR FNA_Ws2[IndexWs2Max] = { "WSAStartup","WSACleanup","WSAGetLastError","socket","connect","recv","send","htons","shutdown" };
	}

