;----------------------------------------------------------
; 文件名: SyscallTrampoline.asm
; 描述: ETW for syscall - 跳板
;   ScTrampoline 被 KiSystemServiceHandler 当作服务例程调用。
;   调用 ScTrampolineCallback 获取目标地址（原始服务例程或错误处理），
;   然后 jmp 过去。
;
;   注意栈对齐：
;     被内核 call 后 RSP = 16n - 8（返回地址 8 字节破坏了 16 字节对齐）。
;     4 次 push（32 字节）后 RSP = 16n - 40 ≡ 8 mod 16。
;     再加 sub rsp, 28h（40 字节）= 16n - 80 = 16(n-5) → 16 字节对齐！
;     满足 x64 ABI 中 call 前 RSP 必须 16 字节对齐的要求。
;----------------------------------------------------------

ScTrampolineCallback    proto

.CODE

ScTrampoline PROC
    ; 保存 volatile 寄存器（x64 调用约定）
    push    rcx
    push    rdx
    push    r8
    push    r9
    sub     rsp, 28h            ; shadow space + 对齐 padding (20h + 8h)

    call    ScTrampolineCallback

    ; 恢复栈
    add     rsp, 28h
    pop     r9
    pop     r8
    pop     rdx
    pop     rcx

    ; rax = ScTrampolineCallback 返回的目标地址
    ;   Allow → 原始系统调用例程地址
    ;   Deny  → NULL（由调用方自行处理）
    jmp     rax
ScTrampoline ENDP

END