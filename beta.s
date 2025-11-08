.section __TEXT,__cstring,cstring_literals
L_str_1:
  .asciz "%d\n"
L_str_2:
  .asciz "%lld\n"
.text
.globl _main
_main:
stp x29, x30, [sp, #-16]!
mov x29, sp
sub sp, sp, #256
movz w2, #7
adrp x0, L_str_1@PAGE
add  x0, x0, L_str_1@PAGEOFF
mov  w1, w2
bl _printf
movz w0, #0
b L_exit
mov w0, #0
b L_exit
L_exit:
add sp, sp, #256
ldp x29, x30, [sp], #16
ret
