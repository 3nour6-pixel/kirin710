# XLoader eMMC Dumper (USB Version)

Dumps the original XLoader from eMMC using the **patched inquiry protocol** - the same USB protocol used in exploit.py for dumping decrypted fastboot.

## Versions

- **C Version** (default): `xloader_dumper.c` - Easier to understand and modify
- **Assembly Version**: `xloader_dumper.S` - Original low-level implementation

## XLoader Location in eMMC

- **Start**: `0x20000` (128KB offset)
- **End**: `0x50000` (320KB offset)
- **Size**: `0x30000` (192KB)

## Protocol

Uses the exact same protocol as `inquiry_patched_cmd()` in exploit.py:

```
Host sends:    0xCD + SEQ + ~SEQ + ADDRESS(4 bytes LE) + CRC(2 bytes)
Device sends:  1024 bytes of eMMC data
```

This is compatible with the existing exploit infrastructure.

## Files

| File | Description |
|------|-------------|
| **C Version** | |
| `xloader_dumper.c` | C source code - main dumper logic |
| `startup.S` | Assembly startup code for C version |
| `linker_c.ld` | Linker script for C version |
| **Assembly Version** | |
| `xloader_dumper.S` | ARM Thumb assembly dumper |
| `linker.ld` | Linker script for assembly version |
| **Common** | |
| `receiver.py` | Python script to receive dump via USB |
| `Makefile` | Build instructions |
| `create_image.py` | Prepares binary for bootrom exploit |

## Building

```bash
cd dumper
make clean

# Build C version (default)
make

# Build assembly version
make asm
```

Output: `xloader_dumper_c.img` (C) or `xloader_dumper.img` (ASM)

## Usage

### Method 1: Standalone Receiver

#### Step 1: Modify exploit.py to upload dumper

```python
# Replace xloader.img with dumper
with open("dumper/xloader_dumper.img", "rb") as file:
    loader = file.read()
    loader_len = len(loader)
```

#### Step 2: Run exploit to upload dumper

```bash
python exploit.py
```

#### Step 3: Run receiver

```bash
# Default: dump 256KB XLoader
python dumper/receiver.py

# Custom output and size
python dumper/receiver.py -o original_xloader.bin -s 0x80000

# Dump from specific offset
python dumper/receiver.py -o bootpart.bin --offset 0x10000 -s 0x20000
```

### Method 2: Integrated in exploit.py

Add this code directly to exploit.py after uploading the dumper:

```python
# Upload dumper instead of xloader
with open("dumper/xloader_dumper.img", "rb") as file:
    dumper = file.read()
xupload(0x22000, dumper, len(dumper), pwn=True)

print("Dumping XLoader from eMMC...")

# Dump using patched inquiry protocol
myfile = open('xloader_dump.bin', 'wb')
addr = 0x0
final = 0x40000  # 256KB

while addr < final:
    serialPort.write(inquiry_patched_cmd(1, addr))
    time.sleep(0.01)
    rsp = serialPort.read(0x400)  # 1024 bytes
    
    if len(rsp) != 0x400:
        print(f"\nError at 0x{addr:X}: got {len(rsp)} bytes")
        break
    
    myfile.write(rsp)
    print(f"\r0x{addr:08X} / 0x{final:08X}", end="")
    addr += 0x400

myfile.close()
print("\nDump complete!")
```

## How It Works

```
┌─────────────┐                    ┌─────────────┐
│   Host PC   │                    │  Kirin 710  │
│             │                    │   (SRAM)    │
│  exploit.py │                    │             │
│      or     │                    │   Dumper    │
│ receiver.py │                    │     ▼       │
│             │ ──inquiry_cmd───▶ │  Parse CMD  │
│             │   (0xCD + addr)    │     ▼       │
│             │                    │ Read eMMC   │
│             │ ◀──1024 bytes──── │     ▼       │
│             │                    │  Send USB   │
│  ┌───────┐  │                    │             │
│  │ .bin  │  │                    │             │
│  └───────┘  │                    │             │
└─────────────┘                    └─────────────┘
```

## Command Line Options

```
usage: receiver.py [-h] [-o OUTPUT] [-s SIZE] [--offset OFFSET] [-p PORT] [--no-verify]

Options:
  -o, --output    Output filename (default: xloader_dump.bin)
  -s, --size      Size to dump in bytes (default: 0x40000 = 256KB)
  --offset        Starting offset in eMMC (default: 0)
  -p, --port      Serial port (auto-detect if not specified)
  --no-verify     Skip verification after dump
```

## Examples

```bash
# Dump XLoader (default 256KB)
python receiver.py

# Dump 512KB
python receiver.py -s 0x80000

# Dump specific region
python receiver.py --offset 0x20000 -s 0x10000 -o region.bin

# Specify port manually
python receiver.py -p /dev/ttyUSB0
```

## Memory Layout

```
SRAM:
  0x22000 - Dumper code (load address)
  0x60000 - USB RX buffer
  0x61000 - USB TX buffer  
  0x62000 - eMMC read buffer
  0x70000 - Stack top

Peripherals:
  0xE8A10000 - USB OTG controller
  0xFF3E0000 - eMMC controller
```

## Notes

1. **Same Protocol**: Uses identical USB protocol as fastboot dump in exploit.py
2. **Boot Partition**: XLoader typically resides in eMMC boot partition
3. **Chunk Size**: Fixed 1024 bytes per request (0x400)
4. **Compatibility**: Works with Kirin 710/710A (VID:0x12D1 PID:0x3609)

## Troubleshooting

### No response from dumper
- Ensure dumper uploaded successfully via exploit
- Check USB connection and device enumeration
- Increase timeout in receiver.py

### Short reads / incomplete chunks
- Increase `time.sleep()` delay between commands
- Check for USB buffer issues
- Try lower chunk rate

### All zeros or 0xFF
- eMMC boot partition may need explicit selection
- Check if eMMC is initialized
- Verify offset is correct

### Device not found
- Check if device is in download mode
- Verify VID/PID (should be 0x12D1:0x3609)
- Try specifying port manually with `-p`
