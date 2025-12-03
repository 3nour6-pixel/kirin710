/*
 * XLoader eMMC Dumper for Kirin 710 BootROM Exploit
 * C Version - Uses Patched Inquiry Protocol
 * 
 * Protocol (same as exploit.py):
 * - Host sends: 0xCD + SEQ + ~SEQ + ADDRESS(4 bytes LE) + CRC(2 bytes)
 * - Dumper reads 1024 bytes from eMMC at that offset  
 * - Dumper sends 1024 bytes back via USB
 *
 * Based on reverse engineering of xloader-orig.img
 * 
 * XLoader area in eMMC: 0x20000 - 0x50000 (192KB)
 */

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef volatile unsigned int reg32_t;

/*============================================================================
 * Constants
 *============================================================================*/

#define CHUNK_SIZE          0x400       /* 1024 bytes per chunk */
#define CMD_INQUIRY         0xCD        /* Inquiry command byte */
#define ACK_BYTE            0xAA
#define NAK_BYTE            0x55

/* XLoader location in eMMC */
#define XLOADER_START       0x20000
#define XLOADER_END         0x50000
#define XLOADER_SIZE        (XLOADER_END - XLOADER_START)

/* Memory addresses (from xloader analysis) */
#define USB_CONTEXT_ADDR    0x00022000  /* USB context structure */
#define USB_RX_BUFFER       0x000223D8  /* Offset 0x3D8 from context */
#define SRAM_BUFFER         0x00024000  /* Working buffer in SRAM */

/* eMMC Controller (DWC_mshc) - Kirin 710 */
#define EMMC_BASE           0xFF3E0000
#define EMMC_CTRL           (EMMC_BASE + 0x00)
#define EMMC_PWREN          (EMMC_BASE + 0x04)
#define EMMC_CLKDIV         (EMMC_BASE + 0x08)
#define EMMC_CLKENA         (EMMC_BASE + 0x10)
#define EMMC_TMOUT          (EMMC_BASE + 0x14)
#define EMMC_BLKSIZ         (EMMC_BASE + 0x1C)
#define EMMC_BYTCNT         (EMMC_BASE + 0x20)
#define EMMC_CMDARG         (EMMC_BASE + 0x28)
#define EMMC_CMD            (EMMC_BASE + 0x2C)
#define EMMC_RESP0          (EMMC_BASE + 0x30)
#define EMMC_RINTSTS        (EMMC_BASE + 0x44)
#define EMMC_STATUS         (EMMC_BASE + 0x48)
#define EMMC_DATA           (EMMC_BASE + 0x200)

/*============================================================================
 * Register Access Macros
 *============================================================================*/

#define REG32(addr)         (*(reg32_t*)(addr))
#define REG8(addr)          (*(volatile uint8_t*)(addr))

/*============================================================================
 * External Functions from XLoader (called via function pointers)
 * These are the actual addresses found in the xloader binary
 *============================================================================*/

/* USB Send Function - FUN_000314f8 */
typedef void (*usb_send_func_t)(uint32_t ctx, uint8_t* data, uint32_t size);
#define USB_SEND_FUNC       ((usb_send_func_t)0x000314f8)

/* Memory copy - FUN_000239d6 */
typedef void (*memcpy_func_t)(void* dst, const void* src, uint32_t size);
#define MEMCPY_FUNC         ((memcpy_func_t)0x000239d6)

/* Memory set - FUN_000239c6 */
typedef void (*memset_func_t)(void* dst, int val, uint32_t size);
#define MEMSET_FUNC         ((memset_func_t)0x000239c6)

/* Delay - FUN_00024324 */
typedef void (*delay_func_t)(uint32_t ms);
#define DELAY_FUNC          ((delay_func_t)0x00024324)

/* Print/Debug - FUN_0002fc1c */
typedef void (*print_func_t)(const char* fmt, ...);
#define PRINT_FUNC          ((print_func_t)0x0002fc1c)

/*============================================================================
 * USB Protocol Context Structure (reverse engineered)
 * Based on FUN_000314f8 and related functions
 *============================================================================*/

typedef struct {
    uint32_t base_ptr;          /* 0x000 - Base pointer */
    uint32_t pad1[0xF6];        /* Padding to offset 0x3D8 */
    uint8_t  rx_buffer[0x400];  /* 0x3D8 - Receive buffer (1024 bytes) */
    /* More fields follow... */
} usb_context_t;

/*============================================================================
 * CRC Calculation (same as exploit.py)
 *============================================================================*/

static const uint16_t crc_table[16] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
    0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF
};

static uint16_t calc_crc(uint8_t* data, uint32_t len) {
    uint16_t crc = 0;
    for (uint32_t i = 0; i < len; i++) {
        crc = (crc << 4) ^ crc_table[(data[i] >> 4) ^ (crc >> 12)];
        crc = (crc << 4) ^ crc_table[(data[i] & 0x0F) ^ (crc >> 12)];
    }
    /* Append two zero bytes for CRC finalization */
    crc = (crc << 4) ^ crc_table[(crc >> 12)];
    crc = (crc << 4) ^ crc_table[(crc >> 12)];
    crc = (crc << 4) ^ crc_table[(crc >> 12)];
    crc = (crc << 4) ^ crc_table[(crc >> 12)];
    return crc;
}

/*============================================================================
 * eMMC Functions
 *============================================================================*/

static void emmc_wait_busy(void) {
    while (REG32(EMMC_STATUS) & 0x200) {
        /* Wait for card not busy */
    }
}

static void emmc_wait_cmd_done(void) {
    while (REG32(EMMC_CMD) & 0x80000000) {
        /* Wait for command accepted */
    }
}

/*
 * Read a single 512-byte block from eMMC
 * block_num: Block number (each block is 512 bytes)
 * buffer: Destination buffer (must be at least 512 bytes)
 */
static int emmc_read_block(uint32_t block_num, uint8_t* buffer) {
    /* Clear interrupts */
    REG32(EMMC_RINTSTS) = 0xFFFFFFFF;
    
    /* Set byte count */
    REG32(EMMC_BYTCNT) = 512;
    
    /* Set block address (CMD17 argument) */
    REG32(EMMC_CMDARG) = block_num;
    
    /* Send CMD17 (READ_SINGLE_BLOCK) */
    /* Bits: start_cmd | use_hold | resp_expect | data_expect | read */
    REG32(EMMC_CMD) = 0x80200251;  /* CMD17 with data read */
    
    emmc_wait_cmd_done();
    
    /* Read data from FIFO */
    uint32_t* buf32 = (uint32_t*)buffer;
    for (int i = 0; i < 128; i++) {  /* 512 / 4 = 128 words */
        /* Wait for data in FIFO */
        while (REG32(EMMC_STATUS) & 0x4) {
            /* FIFO empty, check for errors */
            if (REG32(EMMC_RINTSTS) & 0x80) {
                return -1;  /* Data timeout */
            }
        }
        buf32[i] = REG32(EMMC_DATA);
    }
    
    /* Wait for transfer complete */
    while (!(REG32(EMMC_RINTSTS) & 0x8)) {
        /* Data transfer complete interrupt */
    }
    
    /* Clear interrupts */
    REG32(EMMC_RINTSTS) = 0xFFFFFFFF;
    
    return 0;
}

/*
 * Read data from eMMC (multiple blocks if needed)
 * offset: Byte offset in eMMC
 * buffer: Destination buffer
 * size: Number of bytes to read
 */
static int emmc_read_data(uint32_t offset, uint8_t* buffer, uint32_t size) {
    uint32_t block_num = offset / 512;
    uint32_t block_offset = offset % 512;
    uint32_t bytes_read = 0;
    uint8_t temp_block[512];
    
    while (bytes_read < size) {
        /* Read block */
        if (emmc_read_block(block_num, temp_block) != 0) {
            return -1;
        }
        
        /* Copy relevant portion */
        uint32_t copy_start = (bytes_read == 0) ? block_offset : 0;
        uint32_t copy_len = 512 - copy_start;
        if (copy_len > (size - bytes_read)) {
            copy_len = size - bytes_read;
        }
        
        MEMCPY_FUNC(buffer + bytes_read, temp_block + copy_start, copy_len);
        
        bytes_read += copy_len;
        block_num++;
        block_offset = 0;
    }
    
    return 0;
}

/*============================================================================
 * USB Communication using XLoader's existing functions
 *============================================================================*/

/*
 * Get the USB context pointer
 * This is set up by the bootrom/xloader USB initialization
 */
static usb_context_t* get_usb_context(void) {
    /* The USB context is typically at a fixed address after initialization
     * We can find it from DAT_00030564 which points to the active USB context */
    return (usb_context_t*)USB_CONTEXT_ADDR;
}

/*
 * Send data via USB using XLoader's FUN_000314f8
 * This function handles the USB IN endpoint transfer
 */
static void usb_send_data(uint8_t* data, uint32_t size) {
    usb_context_t* ctx = get_usb_context();
    
    /* Use the XLoader's USB send function directly */
    /* FUN_000314f8(ctx, data, size) */
    USB_SEND_FUNC((uint32_t)ctx, data, size);
}

/*============================================================================
 * Command Handler
 *============================================================================*/

/*
 * Parse incoming command and check CRC
 * Returns: 0 on success, -1 on error
 */
static int parse_command(uint8_t* cmd_buf, uint32_t* address) {
    /* Command format: CMD(1) + SEQ(1) + ~SEQ(1) + ADDR(4, LE) + CRC(2) */
    
    /* Check command byte */
    if (cmd_buf[0] != CMD_INQUIRY) {
        return -1;
    }
    
    /* Check sequence number complement */
    if ((cmd_buf[1] ^ cmd_buf[2]) != 0xFF) {
        return -1;
    }
    
    /* Verify CRC (on first 7 bytes) */
    uint16_t expected_crc = (cmd_buf[7] << 8) | cmd_buf[8];
    uint16_t calc = calc_crc(cmd_buf, 7);
    if (calc != expected_crc) {
        return -1;
    }
    
    /* Extract address (little endian) */
    *address = cmd_buf[3] | (cmd_buf[4] << 8) | (cmd_buf[5] << 16) | (cmd_buf[6] << 24);
    
    return 0;
}

/*
 * Handle incoming inquiry command
 * Reads eMMC data and sends it back via USB
 */
static void handle_inquiry(usb_context_t* ctx, uint8_t* cmd_buf, uint32_t cmd_len) {
    uint32_t address;
    static uint8_t data_buffer[CHUNK_SIZE];
    
    /* Parse command */
    if (parse_command(cmd_buf, &address) != 0) {
        /* Send NAK */
        uint8_t nak = NAK_BYTE;
        usb_send_data(&nak, 1);
        return;
    }
    
    /* Read data from eMMC */
    if (emmc_read_data(address, data_buffer, CHUNK_SIZE) != 0) {
        /* Send NAK on read error */
        uint8_t nak = NAK_BYTE;
        usb_send_data(&nak, 1);
        return;
    }
    
    /* Send data back via USB */
    usb_send_data(data_buffer, CHUNK_SIZE);
}

/*============================================================================
 * Main Entry Point
 *============================================================================*/

/*
 * Main dumper loop
 * This is called after the dumper is loaded into SRAM
 */
void dumper_main(void) {
    usb_context_t* ctx = get_usb_context();
    
    /* Main loop - wait for commands and respond */
    while (1) {
        /* Check if we have received data
         * The USB receive is handled by XLoader's existing USB interrupt/poll
         * We check the receive buffer for new commands
         */
        
        /* The rx_buffer is at offset 0x3D8 in the USB context
         * When a command arrives, it will be placed there by the USB handler
         * We need to check if we have a complete command (9 bytes for inquiry)
         */
        
        uint8_t* rx_buf = ctx->rx_buffer;
        
        /* Simple polling - check if first byte is a valid command */
        if (rx_buf[0] == CMD_INQUIRY) {
            /* Handle the inquiry command */
            handle_inquiry(ctx, rx_buf, 9);
            
            /* Clear the buffer to wait for next command */
            rx_buf[0] = 0;
        }
        
        /* Small delay to avoid tight loop */
        DELAY_FUNC(1);
    }
}

/*
 * Entry point - called from startup assembly
 */
void _start(void) __attribute__((section(".text.entry")));
void _start(void) {
    /* Initialize stack (done in assembly startup if needed) */
    
    /* Run main dumper */
    dumper_main();
    
    /* Should never reach here */
    while (1);
}
