# XLoader Dumper for Kirin 710

This dumper reads the original XLoader from eMMC and sends it over VCOM/UART.

## Files

- `xloader_dumper.S` - Main assembly source code
- `linker.ld` - Linker script for SRAM execution
- `Makefile` - Build automation
- `create_image.py` - Creates uploadable image
- `receiver.py` - Python script to receive the dump

## Building

### Prerequisites

1. ARM cross-compiler toolchain:
   ```bash
   # Ubuntu/Debian
   sudo apt install gcc-arm-none-eabi binutils-arm-none-eabi
   
   # Arch Linux
   sudo pacman -S arm-none-eabi-gcc arm-none-eabi-binutils
   
   # macOS (with Homebrew)
   brew install arm-none-eabi-gcc
   ```

2. Python 3 with pyserial:
   ```bash
   pip install pyserial
   ```

### Build

```bash
cd dumper
make
```

This produces:
- `xloader_dumper.img` - Ready to upload via exploit
- `xloader_dumper.bin` - Raw binary
- `xloader_dumper.lst` - Disassembly listing

## Usage

### 1. Upload via BootROM Exploit

Modify `exploit.py` to upload the dumper instead of the regular xloader:

```python
# In exploit.py, replace xloader upload with:
with open("dumper/xloader_dumper.img", "rb") as file:
    dumper = file.read()
    dumper_len = len(dumper)

xupload(0x22000, dumper, dumper_len, pwn=True)
```

### 2. Receive the Dump

In another terminal, run the receiver:

```bash
python3 receiver.py -o original_xloader.bin
```

Or specify the port manually:

```bash
python3 receiver.py -p /dev/ttyUSB0 -o original_xloader.bin
```

### 3. Verify

The receiver will show progress and verify checksums for each chunk.

## Protocol

```
┌─────────────────────────────────────────┐
│ START MARKER (0xAA55AA55)               │ 4 bytes
├─────────────────────────────────────────┤
│ Total Size                              │ 4 bytes
├─────────────────────────────────────────┤
│ Chunk Size                              │ 4 bytes
├─────────────────────────────────────────┤
│ ┌─────────────────────────────────────┐ │
│ │ CHUNK MARKER (0x55AA55AA)           │ │ 4 bytes
│ ├─────────────────────────────────────┤ │
│ │ Offset                              │ │ 4 bytes
│ ├─────────────────────────────────────┤ │
│ │ Length                              │ │ 4 bytes
│ ├─────────────────────────────────────┤ │
│ │ Data                                │ │ Length bytes
│ ├─────────────────────────────────────┤ │
│ │ Checksum                            │ │ 4 bytes
│ └─────────────────────────────────────┘ │
│          ... repeat for each chunk ...  │
├─────────────────────────────────────────┤
│ END MARKER (0xDEADBEEF)                 │ 4 bytes
└─────────────────────────────────────────┘
```

## Memory Map

```
0x00000000 - 0x00010000  BootROM (16KB)
0x00020000 - 0x00080000  SRAM (384KB)
0x00022000              Dumper load address
0x00060000              Read buffer
0x00070000              Stack
```

## Configuration

Edit constants in `xloader_dumper.S`:

```asm
.equ XLOADER_EMMC_OFFSET,   0x0         /* eMMC byte offset */
.equ XLOADER_SIZE,          0x40000     /* Size to dump (256KB) */
.equ CHUNK_SIZE,            0x400       /* Bytes per chunk (1024) */
```

## Notes

1. **UART vs VCOM**: The code uses UART0 which is typically exposed as VCOM over USB. If your device uses a different UART, modify `UART0_BASE`.

2. **eMMC Boot Partition**: XLoader is typically in the eMMC boot partition. You may need to switch partitions first if the boot partition isn't selected.

3. **Timing**: If you experience data corruption, try reducing the baud rate or adding delays between chunks.

4. **Alternative**: If UART doesn't work, consider using the USB download protocol (like the patched inquiry command in the original exploit).

## Troubleshooting

### No output from device
- Check UART base address for your specific Kirin 710 variant
- Verify the dumper is actually executing (check for USB re-enumeration)

### Checksum errors
- Reduce baud rate
- Check for electrical noise/interference
- Add delays in assembly code between byte transmissions

### eMMC read failures
- eMMC controller base address may differ
- Boot partition may need to be explicitly selected
- Controller may need different initialization sequence
