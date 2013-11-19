bits 64
section .text

%define AES_BIT (1 << 25)
%define SSE2_BIT (1 << 26)

global _aesniIsSupported
_aesniIsSupported:
    ; callee-saved register clobbered by cpuid
    push rbx
    
    ; I don't know of any x86-64 CPUs without cpuid,
    ; so I'm assuming it's safe to use without checking.
    mov eax, 1
    cpuid
    
    ; check if AES-NI is supported
    test ecx, AES_BIT
    je .fail
    
    ; check if SSE2 is supported
    test edx, SSE2_BIT
    je .fail
    
    ; all instructions are supported, return 1
    mov rax, 1
    jmp .cleanup
.fail:
    mov rax, 0
.cleanup:
    pop rbx
    ret

; args: doubleword[11*4] expanded key buffer
global _aesniScheduleKeys128
_aesniScheduleKeys128:
    ; the address of the key buffer is in rdi
    ; load original key into xmm1
    movdqu xmm1, [rdi]
    add rdi, 16
    
    aeskeygenassist xmm2, xmm1, 0x01
    call expandKeyAssist128
    aeskeygenassist xmm2, xmm1, 0x02
    call expandKeyAssist128
    aeskeygenassist xmm2, xmm1, 0x04
    call expandKeyAssist128
    aeskeygenassist xmm2, xmm1, 0x08
    call expandKeyAssist128
    aeskeygenassist xmm2, xmm1, 0x10
    call expandKeyAssist128
    aeskeygenassist xmm2, xmm1, 0x20
    call expandKeyAssist128
    aeskeygenassist xmm2, xmm1, 0x40
    call expandKeyAssist128
    aeskeygenassist xmm2, xmm1, 0x80
    call expandKeyAssist128
    aeskeygenassist xmm2, xmm1, 0x1b
    call expandKeyAssist128
    aeskeygenassist xmm2, xmm1, 0x36
    call expandKeyAssist128
    
    ret

; helper function which uses the result of aeskeygenassist to
; compute the next round key for 128 bit keys
expandKeyAssist128:
    ; this instruction basically copies the most significant
    ; doubleword to every other doubleword. it's complicated.
    pshufd xmm2, xmm2, 0xff
    ; copy xmm1 to xmm3
    movdqa xmm3, xmm1
    ; `pslldq xmm3, 4` shifts xmm3 left by 4 bytes
    pslldq xmm3, 4
    pxor xmm1, xmm3
    pslldq xmm3, 4
    pxor xmm1, xmm3
    pslldq xmm3, 4
    pxor xmm1, xmm3
    pxor xmm1, xmm2
    ; now xmm1 has been transformed into the next round key
    movdqu [rdi], xmm1
    add rdi, 16
    
    ret

; args: doubleword[13*4] expanded key buffer
global _aesniScheduleKeys192
_aesniScheduleKeys192:
    movdqu xmm1, [rdi]
    add rdi, 16
    movlpd xmm2, [rdi]
    add rdi, 8
    
    aeskeygenassist xmm3, xmm2, 0x01
    call expandKeyAssist192
    aeskeygenassist xmm3, xmm2, 0x02
    call expandKeyAssist192
    aeskeygenassist xmm3, xmm2, 0x04
    call expandKeyAssist192
    aeskeygenassist xmm3, xmm2, 0x08
    call expandKeyAssist192
    aeskeygenassist xmm3, xmm2, 0x10
    call expandKeyAssist192
    aeskeygenassist xmm3, xmm2, 0x20
    call expandKeyAssist192
    aeskeygenassist xmm3, xmm2, 0x40
    call expandKeyAssist192
    aeskeygenassist xmm3, xmm2, 0x80
    call expandKeyAssist192
    
    ret

; input: most recent six columns, [c6 c5 c4 c3 c2 c1]
; xmm2 = [ _  _ c6 c5]
; xmm1 = [c4 c3 c2 c1]
; xmm3 = aeskeygenassist xmm2, rcon
; output: next six columns in same format
expandKeyAssist192:
    pshufd xmm3, xmm3, 01010101b
    
    movdqa xmm4, xmm1
    pslldq xmm4, 4
    pxor xmm1, xmm4
    pslldq xmm4, 4
    pxor xmm1, xmm4
    pslldq xmm4, 4
    pxor xmm1, xmm4
    pxor xmm1, xmm3
    
    movdqa xmm4, xmm2
    pslldq xmm4, 4
    pxor xmm2, xmm4
    pshufd xmm4, xmm1, 11111111b
    pxor xmm2, xmm4
    
    movdqu [rdi], xmm1
    add rdi, 16
    movlpd [rdi], xmm2
    add rdi, 8
    
    ret

; args: doubleword[15*4] expanded key buffer
global _aesniScheduleKeys256
_aesniScheduleKeys256:
    movdqu xmm1, [rdi]
    add rdi, 16
    movdqu xmm2, [rdi]
    add rdi, 16
    
    aeskeygenassist xmm3, xmm2, 0x01
    pshufd xmm3, xmm3, 11111111b
    call expandKeyAssist256
    aeskeygenassist xmm3, xmm2, 0x00
    pshufd xmm3, xmm3, 10101010b
    call expandKeyAssist256
    aeskeygenassist xmm3, xmm2, 0x02
    pshufd xmm3, xmm3, 11111111b
    call expandKeyAssist256
    aeskeygenassist xmm3, xmm2, 0x00
    pshufd xmm3, xmm3, 10101010b
    call expandKeyAssist256
    aeskeygenassist xmm3, xmm2, 0x04
    pshufd xmm3, xmm3, 11111111b
    call expandKeyAssist256
    aeskeygenassist xmm3, xmm2, 0x00
    pshufd xmm3, xmm3, 10101010b
    call expandKeyAssist256
    aeskeygenassist xmm3, xmm2, 0x08
    pshufd xmm3, xmm3, 11111111b
    call expandKeyAssist256
    aeskeygenassist xmm3, xmm2, 0x00
    pshufd xmm3, xmm3, 10101010b
    call expandKeyAssist256
    aeskeygenassist xmm3, xmm2, 0x10
    pshufd xmm3, xmm3, 11111111b
    call expandKeyAssist256
    aeskeygenassist xmm3, xmm2, 0x00
    pshufd xmm3, xmm3, 10101010b
    call expandKeyAssist256
    aeskeygenassist xmm3, xmm2, 0x20
    pshufd xmm3, xmm3, 11111111b
    call expandKeyAssist256
    aeskeygenassist xmm3, xmm2, 0x00
    pshufd xmm3, xmm3, 10101010b
    call expandKeyAssist256
    aeskeygenassist xmm3, xmm2, 0x40
    pshufd xmm3, xmm3, 11111111b
    call expandKeyAssist256
    
    ret

expandKeyAssist256:
    movdqa xmm4, xmm1
    pslldq xmm4, 4
    pxor xmm1, xmm4
    pslldq xmm4, 4
    pxor xmm1, xmm4
    pslldq xmm4, 4
    pxor xmm1, xmm4
    pxor xmm1, xmm3
    ; next round key is now in xmm1
    movdqu [rdi], xmm1
    add rdi, 16
    ; swap xmm1 and xmm2
    movdqa xmm4, xmm1
    movdqa xmm1, xmm2
    movdqa xmm2, xmm4
    
    ret

global _aesniPrepareDecryptionKeys
_aesniPrepareDecryptionKeys:
    add rdi, 16
    sub rsi, 1
    
    .preploop:
        movdqu xmm1, [rdi]
        aesimc xmm1, xmm1
        movdqu [rdi], xmm1
        add rdi, 16
        sub rsi, 1
        jne .preploop
    
    ret

global _aesniEncryptRound128
_aesniEncryptRound128:
    movdqu xmm15, [rdi]
    
    pxor xmm15, xmm0
    aesenc xmm15, xmm1
    aesenc xmm15, xmm2
    aesenc xmm15, xmm3
    aesenc xmm15, xmm4
    aesenc xmm15, xmm5
    aesenc xmm15, xmm6
    aesenc xmm15, xmm7
    aesenc xmm15, xmm8
    aesenc xmm15, xmm9
    aesenclast xmm15, xmm10
    
    movdqu [rdi], xmm15
    ret

global _aesniEncryptRound192
_aesniEncryptRound192:
    movdqu xmm15, [rdi]
    
    pxor xmm15, xmm0
    aesenc xmm15, xmm1
    aesenc xmm15, xmm2
    aesenc xmm15, xmm3
    aesenc xmm15, xmm4
    aesenc xmm15, xmm5
    aesenc xmm15, xmm6
    aesenc xmm15, xmm7
    aesenc xmm15, xmm8
    aesenc xmm15, xmm9
    aesenc xmm15, xmm10
    aesenc xmm15, xmm11
    aesenclast xmm15, xmm12
    
    movdqu [rdi], xmm15
    ret

global _aesniEncryptRound256
_aesniEncryptRound256:
    movdqu xmm15, [rdi]
    
    pxor xmm15, xmm0
    aesenc xmm15, xmm1
    aesenc xmm15, xmm2
    aesenc xmm15, xmm3
    aesenc xmm15, xmm4
    aesenc xmm15, xmm5
    aesenc xmm15, xmm6
    aesenc xmm15, xmm7
    aesenc xmm15, xmm8
    aesenc xmm15, xmm9
    aesenc xmm15, xmm10
    aesenc xmm15, xmm11
    aesenc xmm15, xmm12
    aesenc xmm15, xmm13
    aesenclast xmm15, xmm14
    
    movdqu [rdi], xmm15
    ret
    
global _aesniDecryptRound128
_aesniDecryptRound128:
    movdqu xmm15, [rdi]
    
    pxor xmm15, xmm10
    aesdec xmm15, xmm9
    aesdec xmm15, xmm8
    aesdec xmm15, xmm7
    aesdec xmm15, xmm6
    aesdec xmm15, xmm5
    aesdec xmm15, xmm4
    aesdec xmm15, xmm3
    aesdec xmm15, xmm2
    aesdec xmm15, xmm1
    aesdeclast xmm15, xmm0
    
    movdqu [rdi], xmm15
    ret
    
global _aesniDecryptRound192
_aesniDecryptRound192:
    movdqu xmm15, [rdi]
    
    pxor xmm15, xmm12
    aesdec xmm15, xmm11
    aesdec xmm15, xmm10
    aesdec xmm15, xmm9
    aesdec xmm15, xmm8
    aesdec xmm15, xmm7
    aesdec xmm15, xmm6
    aesdec xmm15, xmm5
    aesdec xmm15, xmm4
    aesdec xmm15, xmm3
    aesdec xmm15, xmm2
    aesdec xmm15, xmm1
    aesdeclast xmm15, xmm0
    
    movdqu [rdi], xmm15
    ret
    
global _aesniDecryptRound256
_aesniDecryptRound256:
    movdqu xmm15, [rdi]
    
    pxor xmm15, xmm14
    aesdec xmm15, xmm13
    aesdec xmm15, xmm12
    aesdec xmm15, xmm11
    aesdec xmm15, xmm10
    aesdec xmm15, xmm9
    aesdec xmm15, xmm8
    aesdec xmm15, xmm7
    aesdec xmm15, xmm6
    aesdec xmm15, xmm5
    aesdec xmm15, xmm4
    aesdec xmm15, xmm3
    aesdec xmm15, xmm2
    aesdec xmm15, xmm1
    aesdeclast xmm15, xmm0
    
    movdqu [rdi], xmm15
    ret

global _aesniLoadRoundKeys128
_aesniLoadRoundKeys128:
    movdqu xmm0, [rdi]
    add rdi, 16
    movdqu xmm1, [rdi]
    add rdi, 16
    movdqu xmm2, [rdi]
    add rdi, 16
    movdqu xmm3, [rdi]
    add rdi, 16
    movdqu xmm4, [rdi]
    add rdi, 16
    movdqu xmm5, [rdi]
    add rdi, 16
    movdqu xmm6, [rdi]
    add rdi, 16
    movdqu xmm7, [rdi]
    add rdi, 16
    movdqu xmm8, [rdi]
    add rdi, 16
    movdqu xmm9, [rdi]
    add rdi, 16
    movdqu xmm10, [rdi]
    ret

global _aesniLoadRoundKeys192
_aesniLoadRoundKeys192:
    movdqu xmm0, [rdi]
    add rdi, 16
    movdqu xmm1, [rdi]
    add rdi, 16
    movdqu xmm2, [rdi]
    add rdi, 16
    movdqu xmm3, [rdi]
    add rdi, 16
    movdqu xmm4, [rdi]
    add rdi, 16
    movdqu xmm5, [rdi]
    add rdi, 16
    movdqu xmm6, [rdi]
    add rdi, 16
    movdqu xmm7, [rdi]
    add rdi, 16
    movdqu xmm8, [rdi]
    add rdi, 16
    movdqu xmm9, [rdi]
    add rdi, 16
    movdqu xmm10, [rdi]
    add rdi, 16
    movdqu xmm11, [rdi]
    add rdi, 16
    movdqu xmm12, [rdi]
    ret

global _aesniLoadRoundKeys256
_aesniLoadRoundKeys256:
    movdqu xmm0, [rdi]
    add rdi, 16
    movdqu xmm1, [rdi]
    add rdi, 16
    movdqu xmm2, [rdi]
    add rdi, 16
    movdqu xmm3, [rdi]
    add rdi, 16
    movdqu xmm4, [rdi]
    add rdi, 16
    movdqu xmm5, [rdi]
    add rdi, 16
    movdqu xmm6, [rdi]
    add rdi, 16
    movdqu xmm7, [rdi]
    add rdi, 16
    movdqu xmm8, [rdi]
    add rdi, 16
    movdqu xmm9, [rdi]
    add rdi, 16
    movdqu xmm10, [rdi]
    add rdi, 16
    movdqu xmm11, [rdi]
    add rdi, 16
    movdqu xmm12, [rdi]
    add rdi, 16
    movdqu xmm13, [rdi]
    add rdi, 16
    movdqu xmm14, [rdi]
    ret
    