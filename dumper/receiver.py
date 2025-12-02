#!/usr/bin/env python3
"""
XLoader eMMC Dumper - USB Receiver
Uses the same patched inquiry protocol as exploit.py

Protocol:
- Host sends: 0xCD + SEQ + ~SEQ + ADDRESS(4 bytes LE) + CRC(2 bytes)
- Device responds with 1024 bytes of eMMC data

Usage:
    python receiver.py [output_file] [size]
    python receiver.py xloader_dump.bin 0x40000
"""

import serial
import serial.tools.list_ports
import struct
import binascii
import sys
import time
import os
import argparse

CHUNK_SIZE = 0x400  # 1024 bytes
DEFAULT_SIZE = 0x40000  # 256KB


def calc_crc(data, crc=0):
    """Calculate CRC for command packet (same as exploit.py)"""
    for char in data:
        crc = ((crc << 8) | char) ^ binascii.crc_hqx(bytes([(crc >> 8) & 0xFF]), 0)
    for i in range(0, 2):
        crc = ((crc << 8) | 0) ^ binascii.crc_hqx(bytes([(crc >> 8) & 0xFF]), 0)
    return crc & 0xFFFF


def inquiry_patched_cmd(seq, address):
    """Create patched inquiry command with address (same as exploit.py)"""
    cmd = struct.pack(">BBB", 0xCD, seq & 0xFF, ~seq & 0xFF)
    cmd += address.to_bytes(length=4, byteorder="little")
    cmd += calc_crc(cmd).to_bytes(length=2, byteorder="big")
    return cmd


def connect_device():
    """Connect to Kirin 710 device in USB download mode"""
    device = None
    ports = serial.tools.list_ports.comports(include_links=False)
    
    for port in ports:
        if port.vid == 0x12D1 and port.pid == 0x3609:
            device = port.device
            print(f"[+] Found Kirin 710: {device}")
            break
    
    if device is None:
        # List all available ports for debugging
        print("[-] Kirin 710 device not found (VID:0x12D1 PID:0x3609)")
        print("[*] Available ports:")
        for port in ports:
            vid = f"0x{port.vid:04X}" if port.vid else "None"
            pid = f"0x{port.pid:04X}" if port.pid else "None"
            print(f"    {port.device} - VID:{vid} PID:{pid} - {port.description}")
        sys.exit(1)
    
    return serial.Serial(
        port=device,
        baudrate=115200,
        dsrdtr=True,
        rtscts=True,
        timeout=2
    )


def dump_emmc(serial_port, output_file, start_offset=0, size=DEFAULT_SIZE):
    """
    Dump eMMC using patched inquiry protocol
    
    Args:
        serial_port: Open serial connection
        output_file: Output filename
        start_offset: Starting byte offset in eMMC
        size: Number of bytes to dump
    """
    print(f"\n[*] Starting eMMC dump")
    print(f"    Start offset: 0x{start_offset:08X}")
    print(f"    Size: 0x{size:X} ({size // 1024} KB)")
    print(f"    Output: {output_file}")
    print()
    
    with open(output_file, 'wb') as f:
        offset = start_offset
        end_offset = start_offset + size
        seq = 1
        total_chunks = size // CHUNK_SIZE
        chunk_num = 0
        errors = 0
        
        while offset < end_offset:
            # Send inquiry command with current offset
            cmd = inquiry_patched_cmd(seq, offset)
            serial_port.write(cmd)
            
            # Small delay for device to process
            time.sleep(0.01)
            
            # Read response (1024 bytes)
            data = serial_port.read(CHUNK_SIZE)
            
            if len(data) != CHUNK_SIZE:
                print(f"\n[!] Short read at 0x{offset:08X}: got {len(data)} bytes")
                
                # Retry up to 3 times
                for retry in range(3):
                    time.sleep(0.1)
                    serial_port.write(cmd)
                    time.sleep(0.02)
                    data = serial_port.read(CHUNK_SIZE)
                    if len(data) == CHUNK_SIZE:
                        print(f"    Retry {retry + 1} successful")
                        break
                
                if len(data) != CHUNK_SIZE:
                    print(f"[-] Failed to read chunk at 0x{offset:08X}")
                    # Pad with zeros and continue
                    data = data + b'\x00' * (CHUNK_SIZE - len(data))
                    errors += 1
            
            # Write to file
            f.write(data)
            
            # Progress
            chunk_num += 1
            progress = (chunk_num * 100) // total_chunks
            print(f"\r[*] Progress: {chunk_num}/{total_chunks} ({progress}%) - 0x{offset:08X}", end="")
            
            # Next chunk
            offset += CHUNK_SIZE
            seq = (seq + 1) & 0xFF
        
        print()
    
    file_size = os.path.getsize(output_file)
    print(f"\n[+] Dump complete!")
    print(f"    File: {output_file}")
    print(f"    Size: {file_size} bytes")
    print(f"    Errors: {errors}")
    
    return errors == 0


def verify_dump(filename):
    """Basic verification of dumped data"""
    print(f"\n[*] Verifying dump: {filename}")
    
    with open(filename, 'rb') as f:
        data = f.read()
    
    # Check for all zeros
    if all(b == 0 for b in data[:256]):
        print("[-] WARNING: First 256 bytes are all zeros!")
    
    # Check for all 0xFF
    if all(b == 0xFF for b in data[:256]):
        print("[-] WARNING: First 256 bytes are all 0xFF (empty/erased)!")
    
    # Simple checksum
    checksum = sum(data) & 0xFFFFFFFF
    print(f"[+] Checksum: 0x{checksum:08X}")
    print(f"[+] Size: {len(data)} bytes")
    
    # Look for ARM code patterns
    first_word = struct.unpack('<I', data[:4])[0]
    print(f"[+] First word: 0x{first_word:08X}")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description='XLoader eMMC Dumper - USB Receiver (Patched Inquiry Protocol)'
    )
    parser.add_argument(
        '-o', '--output',
        default='xloader_dump.bin',
        help='Output filename (default: xloader_dump.bin)'
    )
    parser.add_argument(
        '-s', '--size',
        default='0x40000',
        help='Size to dump in bytes (default: 0x40000 = 256KB)'
    )
    parser.add_argument(
        '--offset',
        default='0',
        help='Starting offset in eMMC (default: 0)'
    )
    parser.add_argument(
        '-p', '--port',
        help='Serial port (auto-detect if not specified)'
    )
    parser.add_argument(
        '--no-verify',
        action='store_true',
        help='Skip verification after dump'
    )
    
    args = parser.parse_args()
    
    # Parse size and offset
    size = int(args.size, 0)
    offset = int(args.offset, 0)
    
    print("=" * 60)
    print("  XLoader eMMC Dumper - USB Receiver")
    print("  (Patched Inquiry Protocol)")
    print("=" * 60)
    
    # Connect to device
    if args.port:
        print(f"[*] Using port: {args.port}")
        serial_port = serial.Serial(
            port=args.port,
            baudrate=115200,
            dsrdtr=True,
            rtscts=True,
            timeout=2
        )
    else:
        print("[*] Auto-detecting device...")
        serial_port = connect_device()
    
    # Clear any pending data
    serial_port.reset_input_buffer()
    
    # Wait a moment for dumper to be ready
    print("[*] Waiting for dumper to initialize...")
    time.sleep(0.5)
    
    # Perform dump
    success = dump_emmc(serial_port, args.output, offset, size)
    
    # Verify
    if success and not args.no_verify:
        verify_dump(args.output)
    
    serial_port.close()
    print("\n[*] Done!")
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
