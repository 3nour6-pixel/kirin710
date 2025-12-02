#!/usr/bin/env python3
"""
XLoader Dump Receiver

This script receives the XLoader dump sent by the dumper payload
over VCOM/UART and saves it to a file.

Protocol:
    1. Start marker (4 bytes): 0xAA55AA55
    2. Total size (4 bytes): Little-endian
    3. Chunk size (4 bytes): Little-endian
    4. For each chunk:
       - Chunk marker (4 bytes): 0x55AA55AA
       - Offset (4 bytes): Little-endian
       - Length (4 bytes): Little-endian
       - Data (length bytes)
       - Checksum (4 bytes): Sum of all bytes in data
    5. End marker (4 bytes): 0xDEADBEEF
"""

import serial
import serial.tools.list_ports
import struct
import sys
import time
import argparse

# Protocol markers
MARKER_START = 0xAA55AA55
MARKER_CHUNK = 0x55AA55AA
MARKER_END = 0xDEADBEEF

def find_device():
    """Find Huawei device in VCOM mode."""
    ports = serial.tools.list_ports.comports()
    for port in ports:
        # Huawei VCOM typically shows up with VID 0x12D1
        if port.vid == 0x12D1:
            print(f"Found device: {port.device} (VID={hex(port.vid)}, PID={hex(port.pid)})")
            return port.device
    return None

def read_word(ser):
    """Read a 32-bit little-endian word from serial."""
    data = ser.read(4)
    if len(data) != 4:
        raise Exception(f"Failed to read word, got {len(data)} bytes")
    return struct.unpack('<I', data)[0]

def calculate_checksum(data):
    """Calculate simple sum checksum of data."""
    return sum(data) & 0xFFFFFFFF

def receive_dump(port, output_file, baudrate=115200):
    """Receive XLoader dump and save to file."""
    
    print(f"Opening {port} at {baudrate} baud...")
    ser = serial.Serial(port=port, baudrate=baudrate, timeout=30)
    
    # Flush any pending data
    ser.reset_input_buffer()
    
    print("Waiting for start marker...")
    
    # Wait for start marker
    buffer = b''
    start_marker_bytes = struct.pack('<I', MARKER_START)
    
    while True:
        byte = ser.read(1)
        if not byte:
            continue
        buffer += byte
        if len(buffer) > 4:
            buffer = buffer[-4:]
        if buffer == start_marker_bytes:
            print("Start marker received!")
            break
    
    # Read header
    total_size = read_word(ser)
    chunk_size = read_word(ser)
    
    print(f"Total size: {total_size} bytes (0x{total_size:X})")
    print(f"Chunk size: {chunk_size} bytes (0x{chunk_size:X})")
    
    # Prepare output buffer
    output_data = bytearray(total_size)
    bytes_received = 0
    chunks_received = 0
    errors = 0
    
    # Receive chunks
    while bytes_received < total_size:
        # Wait for chunk marker
        marker = read_word(ser)
        if marker != MARKER_CHUNK:
            if marker == MARKER_END:
                print("Received end marker early!")
                break
            print(f"Warning: Expected chunk marker, got 0x{marker:08X}")
            errors += 1
            continue
        
        # Read chunk header
        offset = read_word(ser)
        length = read_word(ser)
        
        # Read chunk data
        chunk_data = ser.read(length)
        if len(chunk_data) != length:
            print(f"Warning: Expected {length} bytes, got {len(chunk_data)}")
            errors += 1
            continue
        
        # Read and verify checksum
        received_checksum = read_word(ser)
        calculated_checksum = calculate_checksum(chunk_data)
        
        if received_checksum != calculated_checksum:
            print(f"Warning: Checksum mismatch at offset 0x{offset:X}")
            print(f"  Received: 0x{received_checksum:08X}, Calculated: 0x{calculated_checksum:08X}")
            errors += 1
            # Still store the data, user can decide what to do
        
        # Store data
        output_data[offset:offset+length] = chunk_data
        bytes_received += length
        chunks_received += 1
        
        # Progress
        percent = (bytes_received * 100) // total_size
        print(f"\rProgress: {bytes_received}/{total_size} bytes ({percent}%) - {chunks_received} chunks", end='')
    
    print()  # Newline after progress
    
    # Wait for end marker
    marker = read_word(ser)
    if marker == MARKER_END:
        print("End marker received!")
    else:
        print(f"Warning: Expected end marker, got 0x{marker:08X}")
    
    ser.close()
    
    # Save to file
    with open(output_file, 'wb') as f:
        f.write(output_data)
    
    print(f"\nDump saved to: {output_file}")
    print(f"Total bytes: {bytes_received}")
    print(f"Total chunks: {chunks_received}")
    print(f"Errors: {errors}")
    
    return errors == 0

def main():
    parser = argparse.ArgumentParser(description='Receive XLoader dump over VCOM')
    parser.add_argument('-p', '--port', help='Serial port (auto-detect if not specified)')
    parser.add_argument('-o', '--output', default='xloader_dump.bin', help='Output file')
    parser.add_argument('-b', '--baudrate', type=int, default=115200, help='Baud rate')
    
    args = parser.parse_args()
    
    # Find port if not specified
    port = args.port
    if not port:
        port = find_device()
        if not port:
            print("Error: No device found. Please specify port with -p")
            sys.exit(1)
    
    # Receive dump
    success = receive_dump(port, args.output, args.baudrate)
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
