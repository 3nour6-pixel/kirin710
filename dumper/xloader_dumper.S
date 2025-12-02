/*
 * XLoader Dumper for Kirin 710 BootROM Exploit
 * USB Version - Uses Patched Inquiry Protocol
 * 
 * Works exactly like the patched inquiry command in exploit.py:
 * - Host sends: inquiry_patched_cmd(seq, address)
 * - Dumper reads 1024 bytes from eMMC at that offset  
 * - Dumper sends 1024 bytes back via USB
 *
 * This replaces the UART version to use the same USB protocol
 * that's already used for fastboot dumping.
 */

.syntax unified
.thumb
.cpu cortex-a53

/*============================================================================
 * Constants and Register Definitions
 *============================================================================*/

/* USB Protocol Constants */
.equ CMD_INQUIRY,       0xCD            /* Inquiry command byte */
.equ CHUNK_SIZE,        0x400           /* 1024 bytes per chunk */
.equ ACK_BYTE,          0xAA
.equ NAK_BYTE,          0x55

/* USB OTG Controller (DWC2) - Kirin 710 */
.equ USB_BASE,          0xE8A10000
.equ USB_FIFO,          0xE8A11000      /* USB FIFO base */

/* USB Registers */
.equ GOTGCTL,           0x000
.equ GOTGINT,           0x004
.equ GAHBCFG,           0x008
.equ GUSBCFG,           0x00C
.equ GRSTCTL,           0x010
.equ GINTSTS,           0x014
.equ GINTMSK,           0x018
.equ GRXSTSR,           0x01C
.equ GRXSTSP,           0x020
.equ GRXFSIZ,           0x024
.equ GNPTXFSIZ,         0x028
.equ DCTL,              0x804
.equ DSTS,              0x808
.equ DIEPMSK,           0x810
.equ DOEPMSK,           0x814
.equ DAINT,             0x818
.equ DAINTMSK,          0x81C
.equ DIEPCTL0,          0x900
.equ DIEPINT0,          0x908
.equ DIEPTSIZ0,         0x910
.equ DIEPDMA0,          0x914
.equ DOEPCTL0,          0xB00
.equ DOEPINT0,          0xB08
.equ DOEPTSIZ0,         0xB10
.equ DOEPDMA0,          0xB14

/* eMMC Controller (Kirin 710 - DWC_mshc compatible) */
.equ EMMC_BASE,         0xFF3E0000
.equ EMMC_CTRL,         0x00
.equ EMMC_PWREN,        0x04
.equ EMMC_CLKDIV,       0x08
.equ EMMC_CLKSRC,       0x0C
.equ EMMC_CLKENA,       0x10
.equ EMMC_TMOUT,        0x14
.equ EMMC_CTYPE,        0x18
.equ EMMC_BLKSIZ,       0x1C
.equ EMMC_BYTCNT,       0x20
.equ EMMC_INTMASK,      0x24
.equ EMMC_CMDARG,       0x28
.equ EMMC_CMD,          0x2C
.equ EMMC_RESP0,        0x30
.equ EMMC_MINTSTS,      0x40
.equ EMMC_RINTSTS,      0x44
.equ EMMC_STATUS,       0x48
.equ EMMC_FIFOTH,       0x4C
.equ EMMC_DATA,         0x200

/* Memory Layout in SRAM */
.equ USB_RX_BUFFER,     0x60000         /* USB receive buffer */
.equ USB_TX_BUFFER,     0x61000         /* USB transmit buffer */
.equ EMMC_BUFFER,       0x62000         /* eMMC read buffer */
.equ STACK_TOP,         0x70000

/*============================================================================
 * Entry Point
 *============================================================================*/
.section .text
.global _start
.thumb_func

_start:
    /* Disable interrupts */
    cpsid   if
    
    /* Setup stack */
    ldr     sp, =STACK_TOP
    
    /* Initialize eMMC */
    bl      emmc_init
    
    /* Main command loop - wait for inquiry commands */
main_loop:
    bl      usb_receive_command
    
    /* Check if we got a valid command */
    cmp     r0, #0
    beq     main_loop               /* No data, keep waiting */
    
    /* Parse and handle command */
    bl      handle_command
    
    b       main_loop

/*============================================================================
 * USB Functions
 *============================================================================*/

/*
 * usb_receive_command - Wait for and receive USB command
 * Returns: r0 = bytes received (0 if none)
 */
.thumb_func
usb_receive_command:
    push    {r4-r6, lr}
    
    ldr     r4, =USB_BASE
    ldr     r5, =USB_RX_BUFFER
    
    /* Check OUT endpoint for received data */
    ldr     r0, [r4, #DOEPINT0]
    tst     r0, #0x1                /* Transfer complete bit */
    beq     no_data
    
    /* Clear interrupt */
    str     r0, [r4, #DOEPINT0]
    
    /* Get received size from GRXSTSP */
    ldr     r0, [r4, #GRXSTSP]
    lsr     r6, r0, #4
    and     r6, r6, #0x7FF          /* Extract byte count (bits 4-14) */
    
    /* If no data, return */
    cmp     r6, #0
    beq     no_data
    
    /* Read data from FIFO into buffer */
    ldr     r1, =USB_FIFO
    mov     r2, #0
    
read_fifo_loop:
    cmp     r2, r6
    bge     read_fifo_done
    
    ldr     r0, [r1]                /* Read from FIFO */
    str     r0, [r5, r2]
    add     r2, r2, #4
    b       read_fifo_loop
    
read_fifo_done:
    /* Re-enable OUT endpoint for next packet */
    ldr     r0, [r4, #DOEPCTL0]
    orr     r0, r0, #0x84000000     /* Enable + Clear NAK */
    str     r0, [r4, #DOEPCTL0]
    
    /* Return bytes received */
    mov     r0, r6
    pop     {r4-r6, pc}
    
no_data:
    mov     r0, #0
    pop     {r4-r6, pc}

/*
 * usb_send_data - Send data over USB IN endpoint
 * Input: r0 = buffer, r1 = size
 */
.thumb_func
usb_send_data:
    push    {r4-r7, lr}
    
    mov     r4, r0                  /* Buffer */
    mov     r5, r1                  /* Size */
    ldr     r6, =USB_BASE
    ldr     r7, =USB_FIFO
    
    /* Setup transfer size */
    mov     r0, r5
    orr     r0, r0, #0x80000        /* 1 packet */
    str     r0, [r6, #DIEPTSIZ0]
    
    /* Enable IN endpoint */
    ldr     r0, [r6, #DIEPCTL0]
    orr     r0, r0, #0x84000000     /* Enable + Clear NAK */
    str     r0, [r6, #DIEPCTL0]
    
    /* Write data to FIFO */
    mov     r2, #0
    
write_fifo_loop:
    cmp     r2, r5
    bge     write_fifo_done
    
    ldr     r0, [r4, r2]
    str     r0, [r7]                /* Write to FIFO */
    add     r2, r2, #4
    b       write_fifo_loop
    
write_fifo_done:
    /* Wait for transfer complete */
wait_tx_complete:
    ldr     r0, [r6, #DIEPINT0]
    tst     r0, #0x1                /* Transfer complete */
    beq     wait_tx_complete
    
    /* Clear interrupt */
    str     r0, [r6, #DIEPINT0]
    
    pop     {r4-r7, pc}

/*============================================================================
 * Command Handler
 *============================================================================*/

/*
 * handle_command - Parse and execute received command
 * Expects command in USB_RX_BUFFER
 * Format: CMD(1) + SEQ(1) + ~SEQ(1) + ADDR(4, LE) + CRC(2)
 */
.thumb_func
handle_command:
    push    {r4-r7, lr}
    
    ldr     r4, =USB_RX_BUFFER
    
    /* Check command byte */
    ldrb    r5, [r4, #0]
    cmp     r5, #CMD_INQUIRY
    bne     unknown_command
    
    /* Extract address (bytes 3-6, little endian) */
    ldr     r6, [r4, #3]
    
    /* Read from eMMC at this address */
    mov     r0, r6                  /* Address/offset */
    ldr     r1, =EMMC_BUFFER
    mov     r2, #CHUNK_SIZE
    bl      emmc_read_data
    
    /* Send data back via USB */
    ldr     r0, =EMMC_BUFFER
    mov     r1, #CHUNK_SIZE
    bl      usb_send_data
    
    b       handle_command_done
    
unknown_command:
    /* Send NAK for unknown commands */
    ldr     r0, =USB_TX_BUFFER
    mov     r1, #NAK_BYTE
    strb    r1, [r0]
    mov     r1, #1
    bl      usb_send_data
    
handle_command_done:
    pop     {r4-r7, pc}

/*============================================================================
 * eMMC Functions  
 *============================================================================*/

/*
 * emmc_init - Initialize eMMC controller
 * Note: At BootROM level, eMMC should already be partially initialized
 */
.thumb_func
emmc_init:
    push    {r0-r3, lr}
    
    ldr     r3, =EMMC_BASE
    
    /* Software reset */
    mov     r0, #0x7
    str     r0, [r3, #EMMC_CTRL]
    
    /* Wait for reset complete */
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
    
    /* Delay */
    ldr     r0, =0x10000
2:  subs    r0, r0, #1
    bne     2b
    
    /* Enable clock */
    mov     r0, #1
    str     r0, [r3, #EMMC_CLKENA]
    
    /* Update clock command */
    ldr     r0, =0x80202000
    str     r0, [r3, #EMMC_CMD]
    
3:  ldr     r0, [r3, #EMMC_CMD]
    tst     r0, #0x80000000
    bne     3b
    
    /* Clear interrupts */
    ldr     r0, =0xFFFFFFFF
    str     r0, [r3, #EMMC_RINTSTS]
    
    /* Set FIFO threshold */
    ldr     r0, =0x00070007
    str     r0, [r3, #EMMC_FIFOTH]
    
    pop     {r0-r3, pc}

/*
 * emmc_read_data - Read data from eMMC
 * Input: r0 = byte offset, r1 = buffer, r2 = size
 */
.thumb_func
emmc_read_data:
    push    {r4-r8, lr}
    
    mov     r4, r0                  /* Byte offset */
    mov     r5, r1                  /* Buffer */
    mov     r6, r2                  /* Size */
    
    /* Convert byte offset to block number (divide by 512) */
    lsr     r7, r4, #9
    
    /* Calculate number of blocks */
    add     r8, r6, #511
    lsr     r8, r8, #9              /* Round up */
    
    /* Read blocks */
read_blocks_loop:
    cmp     r8, #0
    beq     read_blocks_done
    
    mov     r0, r7                  /* Block number */
    mov     r1, r5                  /* Buffer */
    bl      emmc_read_block
    
    add     r7, r7, #1              /* Next block */
    add     r5, r5, #512            /* Next buffer position */
    sub     r8, r8, #1
    b       read_blocks_loop
    
read_blocks_done:
    pop     {r4-r8, pc}

/*
 * emmc_read_block - Read single 512-byte block
 * Input: r0 = block number, r1 = buffer
 */
.thumb_func
emmc_read_block:
    push    {r2-r6, lr}
    
    mov     r5, r1                  /* Save buffer */
    ldr     r6, =EMMC_BASE
    
    /* Set byte count */
    mov     r2, #512
    str     r2, [r6, #EMMC_BYTCNT]
    
    /* Clear interrupts */
    ldr     r2, =0xFFFFFFFF
    str     r2, [r6, #EMMC_RINTSTS]
    
    /* Set block address */
    str     r0, [r6, #EMMC_CMDARG]
    
    /* Send CMD17 (READ_SINGLE_BLOCK) */
    ldr     r2, =0x80200251
    str     r2, [r6, #EMMC_CMD]
    
    /* Wait for command accepted */
1:  ldr     r2, [r6, #EMMC_CMD]
    tst     r2, #0x80000000
    bne     1b
    
    /* Read data from FIFO */
    mov     r3, #0
    
2:  /* Wait for data in FIFO */
    ldr     r2, [r6, #EMMC_STATUS]
    tst     r2, #0x4                /* FIFO empty */
    bne     3f
    
    /* Read word */
    ldr     r4, [r6, #EMMC_DATA]
    str     r4, [r5, r3]
    add     r3, r3, #4
    
    cmp     r3, #512
    blt     2b
    b       4f
    
3:  /* Check transfer complete */
    ldr     r2, [r6, #EMMC_RINTSTS]
    tst     r2, #0x8
    beq     2b
    
4:  /* Clear interrupts */
    ldr     r2, =0xFFFFFFFF
    str     r2, [r6, #EMMC_RINTSTS]
    
    pop     {r2-r6, pc}

/*============================================================================
 * Utility Functions
 *============================================================================*/

.thumb_func
delay:
    push    {lr}
1:  subs    r0, r0, #1
    bne     1b
    pop     {pc}

.end
