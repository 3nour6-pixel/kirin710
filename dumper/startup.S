/*
 * XLoader Dumper - Startup Assembly
 * Minimal startup code to set up stack and call C main
 */

.syntax unified
.thumb
.cpu cortex-a53

.section .text.entry
.global _start
.type _start, %function

_start:
    /* Disable interrupts */
    cpsid   if
    
    /* Setup stack pointer */
    ldr     sp, =0x70000
    
    /* Clear BSS if we have one */
    ldr     r0, =__bss_start
    ldr     r1, =__bss_end
    mov     r2, #0
1:
    cmp     r0, r1
    bge     2f
    str     r2, [r0], #4
    b       1b
2:
    
    /* Call C main */
    bl      dumper_main
    
    /* Infinite loop if main returns */
3:
    b       3b

.size _start, . - _start

/* Provide weak symbols for BSS section */
.weak __bss_start
.weak __bss_end
__bss_start:
__bss_end:

.end
