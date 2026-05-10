; by Bighound (https://github.com/bighound)

.data
EXTERN sysNumber:DWORD
EXTERN functionAddress:QWORD

.code 

SanctuaryGate PROC
	mov r11, rcx
	mov r10, r11
	mov eax, sysNumber
	jmp QWORD PTR [functionAddress]
SanctuaryGate ENDP

end