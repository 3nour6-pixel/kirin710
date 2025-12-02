/*
 * XLoader Dumper for Kirin 710 BootROM Exploit
 * 
 * Purpose: Read original XLoader from eMMC and send via VCOM/UART
 * Target: Kirin 710 / 710A (ARMv8 in AArch32 mode at BootROM level)
 * 
 * Memory Map (from bootloader_mmumem.txt):
 *   BootROM:  0x00000000 - 0x00010000
 *   SRAM:     0x00020000 - 0x00080000
 *   Stack:    0x00049BFC
 * 
 * This code runs from SRAM after BootROM exploit
 */

.syntax unified
.thumb
.cpu cortex-a53

/*============================================================================
 * Constants and Register Definitions
 *============================================================================*/

/* UART Configuration (Kirin 710 UART0) */
.equ UART0_BASE,        0xFFD74000
.equ UART_DR,           0x00        /* Data Register */
.equ UART_FR,           0x18        /* Flag Register */
.equ UART_IBRD,         0x24        /* Integer Baud Rate Divisor */
.equ UART_FBRD,         0x28        /* Fractional Baud Rate Divisor */
.equ UART_LCR_H,        0x2C        /* Line Control Register */
.equ UART_CR,           0x30        /* Control Register */
.equ UART_IMSC,         0x38        /* Interrupt Mask Set/Clear */
.equ UART_FR_TXFF,      0x20        /* TX FIFO Full flag */
.equ UART_FR_RXFE,      0x10        /* RX FIFO Empty flag */
.equ UART_FR_BUSY,      0x08        /* UART Busy flag */

/* eMMC Controller (Kirin 710 - DWC_mshc compatible) */
.equ EMMC_BASE,         0xFF3E0000
.equ EMMC_CTRL,         0x00        /* Control Register */
.equ EMMC_PWREN,        0x04        /* Power Enable */
.equ EMMC_CLKDIV,       0x08        /* Clock Divider */
.equ EMMC_CLKSRC,       0x0C        /* Clock Source */
.equ EMMC_CLKENA,       0x10        /* Clock Enable */
.equ EMMC_TMOUT,        0x14        /* Timeout */
.equ EMMC_CTYPE,        0x18        /* Card Type */
.equ EMMC_BLKSIZ,       0x1C        /* Block Size */
.equ EMMC_BYTCNT,       0x20        /* Byte Count */
.equ EMMC_INTMASK,      0x24        /* Interrupt Mask */
.equ EMMC_CMDARG,       0x28        /* Command Argument */
.equ EMMC_CMD,          0x2C        /* Command Register */
.equ EMMC_RESP0,        0x30        /* Response 0 */
.equ EMMC_RESP1,        0x34        /* Response 1 */
.equ EMMC_RESP2,        0x38        /* Response 2 */
.equ EMMC_RESP3,        0x3C        /* Response 3 */
.equ EMMC_MINTSTS,      0x40        /* Masked Interrupt Status */
.equ EMMC_RINTSTS,      0x44        /* Raw Interrupt Status */
.equ EMMC_STATUS,       0x48        /* Status Register */
.equ EMMC_FIFOTH,       0x4C        /* FIFO Threshold */
.equ EMMC_CDETECT,      0x50        /* Card Detect */
.equ EMMC_WRTPRT,       0x54        /* Write Protect */
.equ EMMC_GPIO,         0x58        /* GPIO */
.equ EMMC_TCBCNT,       0x5C        /* Transfer CIU Byte Count */
.equ EMMC_TBBCNT,       0x60        /* Transfer BIU Byte Count */
.equ EMMC_DEBNCE,       0x64        /* Debounce */
.equ EMMC_USRID,        0x68        /* User ID */
.equ EMMC_VERID,        0x6C        /* Version ID */
.equ EMMC_HCON,         0x70        /* Hardware Configuration */
.equ EMMC_UHS_REG,      0x74        /* UHS Register */
.equ EMMC_BMOD,         0x80        /* Bus Mode */
.equ EMMC_PLDMND,       0x84        /* Poll Demand */
.equ EMMC_DBADDR,       0x88        /* Descriptor Base Address */
.equ EMMC_IDSTS,        0x8C        /* Internal DMAC Status */
.equ EMMC_IDINTEN,      0x90        /* Internal DMAC Interrupt Enable */
.equ EMMC_DSCADDR,      0x94        /* Current Host Descriptor Address */
.equ EMMC_BUFADDR,      0x98        /* Current Buffer Descriptor Address */
.equ EMMC_DATA,         0x200       /* Data FIFO (can also be 0x100) */

/* XLoader Location in eMMC */
.equ XLOADER_EMMC_OFFSET,   0x0         /* XLoader starts at beginning of boot partition */
.equ XLOADER_SIZE,          0x40000     /* 256KB - typical xloader size */
.equ CHUNK_SIZE,            0x400       /* 1024 bytes per chunk */

/* Buffer in SRAM for reading */
.equ READ_BUFFER,           0x60000     /* Use upper SRAM for buffer */

/* Protocol markers */
.equ MARKER_START,          0xAA55AA55  /* Start of dump marker */
.equ MARKER_CHUNK,          0x55AA55AA  /* Chunk marker */
.equ MARKER_END,            0xDEADBEEF  /* End of dump marker */

/*============================================================================
 * Entry Point
 *============================================================================*/
.section .text
.global _start
.thumb_func

_start:
    /* Save context */
    push    {r4-r12, lr}
    
    /* Initialize stack pointer if needed */
    ldr     sp, =0x70000
    
    /* Initialize UART for VCOM communication */
    bl      uart_init
    
    /* Send start marker */
    ldr     r0, =MARKER_START
    bl      uart_send_word
    
    /* Send total size */
    ldr     r0, =XLOADER_SIZE
    bl      uart_send_word
    
    /* Send chunk size */
    ldr     r0, =CHUNK_SIZE
    bl      uart_send_word
    
    /* Initialize eMMC if not already done */
    bl      emmc_init
    
    /* Start dumping XLoader */
    bl      dump_xloader
    
    /* Send end marker */
    ldr     r0, =MARKER_END
    bl      uart_send_word
    
    /* Restore context and return */
    pop     {r4-r12, pc}

/*============================================================================
 * UART Functions
 *============================================================================*/

/*
 * uart_init - Initialize UART0 for 115200 baud
 */
.thumb_func
uart_init:
    push    {r0-r3, lr}
    
    ldr     r3, =UART0_BASE
    
    /* Disable UART */
    mov     r0, #0
    str     r0, [r3, #UART_CR]
    
    /* Wait for UART to finish any transmission */
1:  ldr     r0, [r3, #UART_FR]
    tst     r0, #UART_FR_BUSY
    bne     1b
    
    /* Disable all interrupts */
    mov     r0, #0
    str     r0, [r3, #UART_IMSC]
    
    /* Set baud rate divisors for 115200 @ 19.2MHz clock */
    /* IBRD = 19200000 / (16 * 115200) = 10 */
    /* FBRD = ((19200000 % (16 * 115200)) * 64 + (16 * 115200) / 2) / (16 * 115200) = 26 */
    mov     r0, #10
    str     r0, [r3, #UART_IBRD]
    mov     r0, #26
    str     r0, [r3, #UART_FBRD]
    
    /* 8 bits, 1 stop bit, no parity, FIFOs enabled */
    mov     r0, #0x70       /* WLEN=8bits, FEN=1 */
    str     r0, [r3, #UART_LCR_H]
    
    /* Enable UART, TX and RX */
    mov     r0, #0x301      /* UARTEN=1, TXE=1, RXE=1 */
    str     r0, [r3, #UART_CR]
    
    pop     {r0-r3, pc}

/*
 * uart_send_byte - Send a single byte over UART
 * Input: r0 = byte to send
 */
.thumb_func
uart_send_byte:
    push    {r1-r2, lr}
    
    ldr     r2, =UART0_BASE
    
    /* Wait for TX FIFO to have space */
1:  ldr     r1, [r2, #UART_FR]
    tst     r1, #UART_FR_TXFF
    bne     1b
    
    /* Send byte */
    strb    r0, [r2, #UART_DR]
    
    pop     {r1-r2, pc}

/*
 * uart_send_word - Send a 32-bit word (little-endian) over UART
 * Input: r0 = word to send
 */
.thumb_func
uart_send_word:
    push    {r4, lr}
    
    mov     r4, r0
    
    /* Send byte 0 (LSB) */
    and     r0, r4, #0xFF
    bl      uart_send_byte
    
    /* Send byte 1 */
    lsr     r0, r4, #8
    and     r0, r0, #0xFF
    bl      uart_send_byte
    
    /* Send byte 2 */
    lsr     r0, r4, #16
    and     r0, r0, #0xFF
    bl      uart_send_byte
    
    /* Send byte 3 (MSB) */
    lsr     r0, r4, #24
    bl      uart_send_byte
    
    pop     {r4, pc}

/*
 * uart_send_buffer - Send a buffer of bytes over UART
 * Input: r0 = buffer address, r1 = length
 */
.thumb_func
uart_send_buffer:
    push    {r4-r6, lr}
    
    mov     r4, r0          /* buffer address */
    mov     r5, r1          /* length */
    mov     r6, #0          /* counter */
    
1:  cmp     r6, r5
    bge     2f
    
    ldrb    r0, [r4, r6]
    bl      uart_send_byte
    
    add     r6, r6, #1
    b       1b
    
2:  pop     {r4-r6, pc}

/*============================================================================
 * eMMC Functions
 *============================================================================*/

/*
 * emmc_init - Initialize eMMC controller
 * Note: At BootROM level, eMMC should already be partially initialized
 *       This function ensures proper configuration for reading
 */
.thumb_func
emmc_init:
    push    {r0-r3, lr}
    
    ldr     r3, =EMMC_BASE
    
    /* Software reset */
    mov     r0, #0x7        /* Reset controller, FIFO, DMA */
    str     r0, [r3, #EMMC_CTRL]
    
    /* Wait for reset to complete */
1:  ldr     r0, [r3, #EMMC_CTRL]
    tst     r0, #0x7
    bne     1b
    
    /* Set timeout */
    ldr     r0, =0xFFFFFFFF
    str     r0, [r3, #EMMC_TMOUT]
    
    /* Set block size to 512 bytes */
    mov     r0, #512
    str     r0, [r3, #EMMC_BLKSIZ]
    
    /* Enable power */
    mov     r0, #1
    str     r0, [r3, #EMMC_PWREN]
    
    /* Small delay for power stabilization */
    ldr     r0, =0x10000
2:  subs    r0, r0, #1
    bne     2b
    
    /* Enable clock */
    mov     r0, #1
    str     r0, [r3, #EMMC_CLKENA]
    
    /* Update clock */
    ldr     r0, =0x80202000     /* CMD_DONE, START_CMD, UPDATE_CLK, WAIT_PRVDATA */
    str     r0, [r3, #EMMC_CMD]
    
    /* Wait for command to complete */
3:  ldr     r0, [r3, #EMMC_CMD]
    tst     r0, #0x80000000     /* START_CMD bit */
    bne     3b
    
    /* Clear all pending interrupts */
    ldr     r0, =0xFFFFFFFF
    str     r0, [r3, #EMMC_RINTSTS]
    
    /* Set FIFO threshold */
    ldr     r0, =0x00070007
    str     r0, [r3, #EMMC_FIFOTH]
    
    pop     {r0-r3, pc}

/*
 * emmc_send_cmd - Send a command to eMMC
 * Input: r0 = command index, r1 = argument
 * Output: r0 = response (RESP0)
 */
.thumb_func
emmc_send_cmd:
    push    {r2-r4, lr}
    
    ldr     r4, =EMMC_BASE
    
    /* Set argument */
    str     r1, [r4, #EMMC_CMDARG]
    
    /* Clear pending interrupts */
    ldr     r2, =0xFFFFFFFF
    str     r2, [r4, #EMMC_RINTSTS]
    
    /* Build command register value */
    /* START_CMD | WAIT_PRVDATA | response flags based on cmd */
    ldr     r2, =0x80200000     /* START_CMD | WAIT_PRVDATA */
    orr     r2, r2, r0          /* Add command index */
    
    /* Add response expect bit for commands that need it */
    cmp     r0, #0              /* CMD0 has no response */
    beq     1f
    orr     r2, r2, #0x40       /* RESPONSE_EXPECT */
    
    /* Check if long response needed (CMD2, CMD9, CMD10) */
    cmp     r0, #2
    beq     0f
    cmp     r0, #9
    beq     0f
    cmp     r0, #10
    bne     1f
0:  orr     r2, r2, #0x80       /* RESPONSE_LENGTH (long response) */
    
1:  /* Send command */
    str     r2, [r4, #EMMC_CMD]
    
    /* Wait for command done */
2:  ldr     r2, [r4, #EMMC_RINTSTS]
    tst     r2, #0x4            /* Command done bit */
    beq     2b
    
    /* Read response */
    ldr     r0, [r4, #EMMC_RESP0]
    
    pop     {r2-r4, pc}

/*
 * emmc_read_block - Read a single 512-byte block from eMMC
 * Input: r0 = block number, r1 = buffer address
 */
.thumb_func
emmc_read_block:
    push    {r2-r6, lr}
    
    mov     r5, r1              /* Save buffer address */
    ldr     r6, =EMMC_BASE
    
    /* Set byte count (512 bytes) */
    mov     r2, #512
    str     r2, [r6, #EMMC_BYTCNT]
    
    /* Clear pending interrupts */
    ldr     r2, =0xFFFFFFFF
    str     r2, [r6, #EMMC_RINTSTS]
    
    /* Set argument (block address for CMD17) */
    str     r0, [r6, #EMMC_CMDARG]
    
    /* Send CMD17 (READ_SINGLE_BLOCK) */
    /* START_CMD | WAIT_PRVDATA | RESPONSE_EXPECT | DATA_EXPECTED | READ */
    ldr     r2, =0x80200251     /* CMD17 with data read */
    str     r2, [r6, #EMMC_CMD]
    
    /* Wait for command accepted */
1:  ldr     r2, [r6, #EMMC_CMD]
    tst     r2, #0x80000000
    bne     1b
    
    /* Read data from FIFO */
    mov     r3, #0              /* Bytes read counter */
    
2:  /* Wait for data available in FIFO */
    ldr     r2, [r6, #EMMC_STATUS]
    tst     r2, #0x4            /* FIFO empty bit */
    bne     3f                  /* If empty, check if transfer complete */
    
    /* Read word from FIFO */
    ldr     r4, [r6, #EMMC_DATA]
    str     r4, [r5, r3]
    add     r3, r3, #4
    
    cmp     r3, #512
    blt     2b
    b       4f
    
3:  /* Check if transfer complete */
    ldr     r2, [r6, #EMMC_RINTSTS]
    tst     r2, #0x8            /* Data transfer over */
    beq     2b                  /* Not done, keep waiting */
    
4:  /* Clear interrupts */
    ldr     r2, =0xFFFFFFFF
    str     r2, [r6, #EMMC_RINTSTS]
    
    pop     {r2-r6, pc}

/*============================================================================
 * Main Dump Function
 *============================================================================*/

/*
 * dump_xloader - Read XLoader from eMMC and send over UART
 */
.thumb_func
dump_xloader:
    push    {r4-r8, lr}
    
    ldr     r4, =XLOADER_EMMC_OFFSET    /* Starting block (in 512-byte blocks) */
    lsr     r4, r4, #9                  /* Convert byte offset to block number */
    
    ldr     r5, =XLOADER_SIZE           /* Total bytes to read */
    ldr     r6, =READ_BUFFER            /* Buffer address */
    mov     r7, #0                      /* Current offset in dump */
    
dump_loop:
    /* Check if we've read everything */
    cmp     r7, r5
    bge     dump_done
    
    /* Calculate how much to read in this iteration */
    sub     r8, r5, r7                  /* Remaining bytes */
    cmp     r8, #CHUNK_SIZE
    ble     1f
    mov     r8, #CHUNK_SIZE             /* Limit to chunk size */
1:
    
    /* Send chunk marker */
    ldr     r0, =MARKER_CHUNK
    bl      uart_send_word
    
    /* Send current offset */
    mov     r0, r7
    bl      uart_send_word
    
    /* Send chunk length */
    mov     r0, r8
    bl      uart_send_word
    
    /* Read blocks for this chunk */
    push    {r7, r8}
    mov     r7, #0                      /* Bytes read in chunk */
    
read_chunk_loop:
    cmp     r7, r8
    bge     read_chunk_done
    
    /* Read one block */
    mov     r0, r4                      /* Block number */
    add     r1, r6, r7                  /* Buffer offset */
    bl      emmc_read_block
    
    add     r4, r4, #1                  /* Next block */
    add     r7, r7, #512                /* 512 bytes read */
    b       read_chunk_loop
    
read_chunk_done:
    pop     {r7, r8}
    
    /* Send the chunk data */
    mov     r0, r6                      /* Buffer address */
    mov     r1, r8                      /* Chunk length */
    bl      uart_send_buffer
    
    /* Calculate simple checksum of chunk */
    push    {r4-r6}
    mov     r4, r6                      /* Buffer */
    mov     r5, r8                      /* Length */
    mov     r6, #0                      /* Checksum */
    
checksum_loop:
    cmp     r5, #0
    ble     checksum_done
    ldrb    r0, [r4], #1
    add     r6, r6, r0
    sub     r5, r5, #1
    b       checksum_loop
    
checksum_done:
    mov     r0, r6
    bl      uart_send_word              /* Send checksum */
    pop     {r4-r6}
    
    /* Update total offset */
    add     r7, r7, r8
    b       dump_loop
    
dump_done:
    pop     {r4-r8, pc}

/*============================================================================
 * Data Section
 *============================================================================*/
.section .data
.align 4

/* Reserved space for variables if needed */
chunk_buffer:
    .space CHUNK_SIZE

.end
