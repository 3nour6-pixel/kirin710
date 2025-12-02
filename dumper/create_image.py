#!/usr/bin/env python3
"""
Create uploadable image from raw binary for Kirin 710 BootROM exploit.

This script takes a raw binary and prepares it for upload via the
BootROM exploit by optionally adding any required headers.
"""

import sys
import struct

def create_image(input_file, output_file):
    """
    Create image file from raw binary.
    
    For the BootROM exploit, we typically just need the raw binary,
    but this script can add headers if needed.
    """
    
    # Read input binary
    with open(input_file, 'rb') as f:
        binary_data = f.read()
    
    print(f"Input binary size: {len(binary_data)} bytes (0x{len(binary_data):X})")
    
    # Pad to 4-byte alignment if needed
    padding = (4 - (len(binary_data) % 4)) % 4
    if padding:
        binary_data += b'\x00' * padding
        print(f"Added {padding} bytes padding for alignment")
    
    # Write output image
    with open(output_file, 'wb') as f:
        f.write(binary_data)
    
    print(f"Output image size: {len(binary_data)} bytes (0x{len(binary_data):X})")
    print(f"Created: {output_file}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.bin> <output.img>")
        sys.exit(1)
    
    create_image(sys.argv[1], sys.argv[2])

if __name__ == '__main__':
    main()
