; Listing generated by Microsoft (R) Optimizing Compiler Version 19.32.31332.0 

	TITLE	c:\users\23035\desktop\home\c++\cshellcode\shellcode.obj
	.686P
	.XMM
	include listing.inc
	.model	flat

INCLUDELIB OLDNAMES

PUBLIC	??_C@_0L@IFGDCEAH@helloworld@			; `string'
PUBLIC	??_C@_02DKCKIIND@?$CFs@				; `string'
PUBLIC	??_C@_07BEIHKDLJ@Message@			; `string'
PUBLIC	??_C@_0L@EFDKOOG@HelloWorld@			; `string'
;	COMDAT ??_C@_0L@EFDKOOG@HelloWorld@
CONST	SEGMENT
??_C@_0L@EFDKOOG@HelloWorld@ DB 'HelloWorld', 00H	; `string'
CONST	ENDS
;	COMDAT ??_C@_07BEIHKDLJ@Message@
CONST	SEGMENT
??_C@_07BEIHKDLJ@Message@ DB 'Message', 00H		; `string'
CONST	ENDS
;	COMDAT ??_C@_02DKCKIIND@?$CFs@
CONST	SEGMENT
??_C@_02DKCKIIND@?$CFs@ DB '%s', 00H			; `string'
CONST	ENDS
;	COMDAT ??_C@_0L@IFGDCEAH@helloworld@
CONST	SEGMENT
??_C@_0L@IFGDCEAH@helloworld@ DB 'helloworld', 00H	; `string'
CONST	ENDS
PUBLIC	_CallShellCode
PUBLIC	?LoadNecessaryLibrary@@YAXP6GPAUHINSTANCE__@@PBD@Z@Z ; LoadNecessaryLibrary
PUBLIC	?GetProcAddressWithHash@@YAPAXKK@Z		; GetProcAddressWithHash
; Function compile flags: /Ogspy
;	COMDAT ?GetProcAddressWithHash@@YAPAXKK@Z
_TEXT	SEGMENT
_pModuleBase$1$ = -24					; size = 4
_dwExportDirRVA$1$ = -20				; size = 4
_BaseDllName$1$ = -16					; size = 4
_pTempChar$1$ = -16					; size = 4
_dwModuleHash_$1$ = -12					; size = 4
_dwFunctionHash_$1$ = -8				; size = 4
_dwNumFunctions$1$ = -4					; size = 4
?GetProcAddressWithHash@@YAPAXKK@Z PROC			; GetProcAddressWithHash, COMDAT
; _dwModuleHash_$ = ecx
; _dwFunctionHash_$ = edx
; File C:\Users\23035\Desktop\Home\C++\CShellcode\CShellcode\shellcode.cpp
; Line 11
	sub	esp, 24					; 00000018H
; Line 31
	mov	eax, DWORD PTR fs:48
	push	ebx
	push	ebp
	push	esi
; Line 36
	mov	eax, DWORD PTR [eax+12]
	push	edi
	mov	DWORD PTR _dwFunctionHash_$1$[esp+40], edx
	mov	DWORD PTR _dwModuleHash_$1$[esp+40], ecx
	mov	esi, DWORD PTR [eax+12]
	jmp	$LN37@GetProcAdd
$LL2@GetProcAdd:
; Line 41
	mov	edx, DWORD PTR [esi+24]
	xor	ecx, ecx
; Line 42
	mov	eax, DWORD PTR [esi+48]
	mov	ebx, DWORD PTR [esi+44]
; Line 47
	mov	esi, DWORD PTR [esi]
	mov	DWORD PTR _BaseDllName$1$[esp+40], eax
	mov	eax, DWORD PTR [edx+60]
	mov	DWORD PTR _pModuleBase$1$[esp+40], edx
	mov	eax, DWORD PTR [eax+edx+120]
	mov	DWORD PTR _dwExportDirRVA$1$[esp+40], eax
; Line 50
	test	eax, eax
	je	SHORT $LN37@GetProcAdd
; Line 56
	shr	ebx, 16					; 00000010H
	xor	edi, edi
	test	ebx, ebx
	je	SHORT $LN5@GetProcAdd
	mov	edx, DWORD PTR _BaseDllName$1$[esp+40]
$LL6@GetProcAdd:
; Line 62
	movsx	ebp, BYTE PTR [edx+edi]
	ror	ecx, 13					; 0000000dH
	cmp	BYTE PTR [edx+edi], 97			; 00000061H
	jl	SHORT $LN14@GetProcAdd
; Line 64
	add	ecx, -32				; ffffffe0H
$LN14@GetProcAdd:
; Line 56
	add	ecx, ebp
	inc	edi
	cmp	edi, ebx
	jb	SHORT $LL6@GetProcAdd
	mov	edx, DWORD PTR _pModuleBase$1$[esp+40]
	mov	eax, DWORD PTR _dwExportDirRVA$1$[esp+40]
$LN5@GetProcAdd:
; Line 71
	cmp	ecx, DWORD PTR _dwModuleHash_$1$[esp+40]
	jne	SHORT $LN37@GetProcAdd
; Line 76
	mov	ebp, DWORD PTR [eax+edx+32]
; Line 78
	xor	edi, edi
	mov	ecx, DWORD PTR [eax+edx+24]
	add	ebp, edx
	mov	DWORD PTR _dwNumFunctions$1$[esp+40], ecx
	test	ecx, ecx
	je	SHORT $LN37@GetProcAdd
$LL9@GetProcAdd:
; Line 81
	mov	eax, DWORD PTR [ebp]
	xor	ebx, ebx
	add	eax, edx
; Line 82
	lea	ebp, DWORD PTR [ebp+4]
	mov	DWORD PTR _pTempChar$1$[esp+40], eax
	mov	edx, eax
$LL12@GetProcAdd:
; Line 89
	mov	cl, BYTE PTR [edx]
	ror	ebx, 13					; 0000000dH
	movsx	eax, cl
	add	ebx, eax
; Line 90
	inc	edx
; Line 91
	test	cl, cl
	jne	SHORT $LL12@GetProcAdd
; Line 92
	mov	edx, DWORD PTR _pModuleBase$1$[esp+40]
	cmp	ebx, DWORD PTR _dwFunctionHash_$1$[esp+40]
	je	SHORT $LN25@GetProcAdd
; Line 78
	inc	edi
	cmp	edi, DWORD PTR _dwNumFunctions$1$[esp+40]
	jb	SHORT $LL9@GetProcAdd
$LN37@GetProcAdd:
; Line 38
	cmp	DWORD PTR [esi+24], 0
	jne	$LL2@GetProcAdd
; Line 101
	xor	eax, eax
$LN1@GetProcAdd:
	pop	edi
; Line 102
	pop	esi
	pop	ebp
	pop	ebx
	add	esp, 24					; 00000018H
	ret	0
$LN25@GetProcAdd:
; Line 94
	mov	esi, DWORD PTR _dwExportDirRVA$1$[esp+40]
	mov	eax, DWORD PTR [esi+edx+36]
	lea	eax, DWORD PTR [eax+edi*2]
; Line 95
	movzx	ecx, WORD PTR [eax+edx]
	mov	eax, DWORD PTR [esi+edx+28]
	lea	eax, DWORD PTR [eax+ecx*4]
	mov	eax, DWORD PTR [eax+edx]
	add	eax, edx
	jmp	SHORT $LN1@GetProcAdd
?GetProcAddressWithHash@@YAPAXKK@Z ENDP			; GetProcAddressWithHash
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT ?LoadNecessaryLibrary@@YAXP6GPAUHINSTANCE__@@PBD@Z@Z
_TEXT	SEGMENT
__2$ = -36						; size = 11
__1$ = -24						; size = 11
__0$ = -12						; size = 11
?LoadNecessaryLibrary@@YAXP6GPAUHINSTANCE__@@PBD@Z@Z PROC ; LoadNecessaryLibrary, COMDAT
; _pLoadLibraryA$ = ecx
; File C:\Users\23035\Desktop\Home\C++\CShellcode\CShellcode\shellcode.cpp
; Line 104
	push	ebp
	mov	ebp, esp
	sub	esp, 36					; 00000024H
; Line 105
	xor	eax, eax
	mov	DWORD PTR __0$[ebp], 1919251317		; 72657375H
	push	esi
	mov	BYTE PTR __0$[ebp+10], al
	mov	esi, ecx
; Line 106
	mov	BYTE PTR __1$[ebp+10], al
; Line 107
	mov	BYTE PTR __2$[ebp+10], al
; Line 108
	lea	eax, DWORD PTR __0$[ebp]
	push	eax
	mov	DWORD PTR __0$[ebp+4], 1680749107	; 642e3233H
	mov	WORD PTR __0$[ebp+8], 27756		; 00006c6cH
	mov	DWORD PTR __1$[ebp], 1597141879		; 5f327377H
	mov	DWORD PTR __1$[ebp+4], 1680749107	; 642e3233H
	mov	WORD PTR __1$[ebp+8], 27756		; 00006c6cH
	mov	DWORD PTR __2$[ebp], 1668707181		; 6376736dH
	mov	DWORD PTR __2$[ebp+4], 1680766066	; 642e7472H
	mov	WORD PTR __2$[ebp+8], 27756		; 00006c6cH
	call	esi
; Line 109
	lea	eax, DWORD PTR __1$[ebp]
	push	eax
	call	esi
; Line 110
	lea	eax, DWORD PTR __2$[ebp]
	push	eax
	call	esi
	pop	esi
; Line 111
	leave
	ret	0
?LoadNecessaryLibrary@@YAXP6GPAUHINSTANCE__@@PBD@Z@Z ENDP ; LoadNecessaryLibrary
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT _CallShellCode
_TEXT	SEGMENT
__2$1 = -36						; size = 11
__1$2 = -24						; size = 11
__0$3 = -12						; size = 11
_CallShellCode PROC					; COMDAT
; File C:\Users\23035\Desktop\Home\C++\CShellcode\CShellcode\shellcode.cpp
; Line 113
	push	ebp
	mov	ebp, esp
	sub	esp, 36					; 00000024H
	push	ebx
	push	esi
	push	edi
; Line 118
	mov	edx, 1953980530				; 74776072H
	mov	ecx, -1834019110			; 92af16daH
	call	?GetProcAddressWithHash@@YAPAXKK@Z	; GetProcAddressWithHash
	mov	esi, eax
; Line 105
	mov	DWORD PTR __0$3[ebp], 1919251317	; 72657375H
	xor	ebx, ebx
	mov	DWORD PTR __0$3[ebp+4], 1680749107	; 642e3233H
; Line 108
	lea	eax, DWORD PTR __0$3[ebp]
	mov	WORD PTR __0$3[ebp+8], 27756		; 00006c6cH
	push	eax
	mov	BYTE PTR __0$3[ebp+10], bl
	mov	DWORD PTR __1$2[ebp], 1597141879	; 5f327377H
	mov	DWORD PTR __1$2[ebp+4], 1680749107	; 642e3233H
	mov	WORD PTR __1$2[ebp+8], 27756		; 00006c6cH
	mov	BYTE PTR __1$2[ebp+10], bl
	mov	DWORD PTR __2$1[ebp], 1668707181	; 6376736dH
	mov	DWORD PTR __2$1[ebp+4], 1680766066	; 642e7472H
	mov	WORD PTR __2$1[ebp+8], 27756		; 00006c6cH
	mov	BYTE PTR __2$1[ebp+10], bl
	call	esi
; Line 109
	lea	eax, DWORD PTR __1$2[ebp]
	push	eax
	call	esi
; Line 110
	lea	eax, DWORD PTR __2$1[ebp]
	push	eax
	call	esi
; Line 122
	mov	edx, -520704711				; e0f6ad39H
	mov	ecx, 567320927				; 21d0a15fH
	call	?GetProcAddressWithHash@@YAPAXKK@Z	; GetProcAddressWithHash
; Line 123
	mov	edx, 356901485				; 1545e26dH
	mov	ecx, -233791272				; f210a0d8H
	mov	esi, eax
	call	?GetProcAddressWithHash@@YAPAXKK@Z	; GetProcAddressWithHash
; Line 124
	push	OFFSET ??_C@_0L@IFGDCEAH@helloworld@
	push	OFFSET ??_C@_02DKCKIIND@?$CFs@
	mov	edi, eax
	call	esi
	pop	ecx
	pop	ecx
; Line 125
	push	ebx
	push	OFFSET ??_C@_07BEIHKDLJ@Message@
	push	OFFSET ??_C@_0L@EFDKOOG@HelloWorld@
	push	ebx
	call	edi
	pop	edi
	pop	esi
	pop	ebx
; Line 126
	leave
	ret	0
_CallShellCode ENDP
_TEXT	ENDS
END
