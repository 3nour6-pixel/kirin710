/*
 * Linker Script for XLoader Dumper (C Version)
 * Loads into SRAM at 0x22000
 */

ENTRY(_start)

MEMORY
{
    /* SRAM region for dumper code */
    SRAM (rwx) : ORIGIN = 0x00022000, LENGTH = 0x10000
}

SECTIONS
{
    . = ORIGIN(SRAM);
    
    /* Entry point first */
    .text.entry : {
        *(.text.entry)
    } > SRAM
    
    /* Code section */
    .text : {
        *(.text)
        *(.text.*)
        . = ALIGN(4);
    } > SRAM
    
    /* Read-only data */
    .rodata : {
        *(.rodata)
        *(.rodata.*)
        . = ALIGN(4);
    } > SRAM
    
    /* Initialized data */
    .data : {
        __data_start = .;
        *(.data)
        *(.data.*)
        . = ALIGN(4);
        __data_end = .;
    } > SRAM
    
    /* Uninitialized data (BSS) */
    .bss : {
        __bss_start = .;
        *(.bss)
        *(.bss.*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end = .;
    } > SRAM
    
    /* Stack at end of SRAM */
    . = ALIGN(8);
    __stack_start = .;
    . = . + 0x1000;  /* 4KB stack */
    __stack_end = .;
    
    /* Discard unwanted sections */
    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.ARM.attributes)
    }
}

/* Provide symbols for startup code */
PROVIDE(__stack_top = __stack_end);
