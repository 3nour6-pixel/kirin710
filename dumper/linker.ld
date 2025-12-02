/*
 * Linker Script for XLoader Dumper
 * 
 * This code runs from SRAM after being uploaded via BootROM exploit
 * Load address: 0x22000 (same as XLoader)
 */

ENTRY(_start)

MEMORY
{
    /* SRAM region where code will be loaded */
    SRAM (rwx) : ORIGIN = 0x22000, LENGTH = 0x5E000
}

SECTIONS
{
    /* Code section */
    .text : 
    {
        *(.text)
        *(.text.*)
        . = ALIGN(4);
    } > SRAM

    /* Read-only data */
    .rodata :
    {
        *(.rodata)
        *(.rodata.*)
        . = ALIGN(4);
    } > SRAM

    /* Initialized data */
    .data :
    {
        *(.data)
        *(.data.*)
        . = ALIGN(4);
    } > SRAM

    /* Uninitialized data (BSS) */
    .bss :
    {
        __bss_start = .;
        *(.bss)
        *(.bss.*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end = .;
    } > SRAM

    /* Stack at end of SRAM */
    .stack (NOLOAD) :
    {
        . = ALIGN(8);
        . = . + 0x2000;  /* 8KB stack */
        __stack_top = .;
    } > SRAM
}
