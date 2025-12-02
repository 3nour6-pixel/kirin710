# Makefile for XLoader Dumper
# Target: Kirin 710 BootROM Exploit

# Toolchain
CROSS_COMPILE ?= arm-none-eabi-
AS = $(CROSS_COMPILE)as
LD = $(CROSS_COMPILE)ld
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump

# Flags
ASFLAGS = -mcpu=cortex-a53 -mthumb
LDFLAGS = -T linker.ld -nostdlib

# Files
TARGET = xloader_dumper
SOURCES = xloader_dumper.S
OBJECTS = $(SOURCES:.S=.o)

# Default target
all: $(TARGET).img $(TARGET).bin $(TARGET).lst

# Assemble
%.o: %.S
	$(AS) $(ASFLAGS) -o $@ $<

# Link
$(TARGET).elf: $(OBJECTS) linker.ld
	$(LD) $(LDFLAGS) -o $@ $(OBJECTS)

# Create raw binary
$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -O binary $< $@

# Create image with header (for BootROM upload)
$(TARGET).img: $(TARGET).bin
	python3 create_image.py $< $@

# Create disassembly listing
$(TARGET).lst: $(TARGET).elf
	$(OBJDUMP) -d -S $< > $@

# Clean
clean:
	rm -f $(OBJECTS) $(TARGET).elf $(TARGET).bin $(TARGET).img $(TARGET).lst

# Phony targets
.PHONY: all clean
