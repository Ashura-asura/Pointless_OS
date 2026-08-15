target triple = "x86_64-unknown-linux-gnu"

; Aegis Phase J: minimal static x86-64 Linux ELF binary.
; write(1, msg, 49) then exit(0), both via int 0x80.
; The message is a local label inside the same .text as the code, so the
; whole binary is a single PT_LOAD R+E segment — exactly what
; linux_compat_elf.rs requires (one segment, R+X, not writable).

; _start is a naked asm entry: no prologue; the message label lives in text.
define void @_start() #0 {
entry:
  call void asm sideeffect
    "movq $$49, %rdx\0A\09leaq msg(%rip), %rsi\0A\09movq $$1, %rdi\0A\09movl $$1, %eax\0A\09int $$0x80\0A\09movq $$0, %rdi\0A\09movl $$60, %eax\0A\09int $$0x80\0A\09msg:\0A\09.ascii \22Aegis: real Linux ELF binary executing in ring-3\5Cn\22\0A",
    "~{rax},~{rcx},~{rdx},~{rsi},~{rdi},~{r8},~{r9},~{r10},~{r11},~{memory}"
    ()
  unreachable
}

attributes #0 = { nounwind noreturn }
