# Makefile for XLoader Dumper
# Target: Kirin 710 BootROM Exploit
# Supports both Assembly and C versions

# Toolchain
CROSS_COMPILE ?= arm-none-eabi-
CC = $(CROSS_COMPILE)gcc
AS = $(CROSS_COMPILE)as
LD = $(CROSS_COMPILE)ld
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump

# Flags
CFLAGS = -mcpu=cortex-a53 -mthumb -nostdlib -nostartfiles -ffreestanding
CFLAGS += -O2 -Wall -Wextra -fno-builtin -fno-stack-protector
ASFLAGS = -mcpu=cortex-a53 -mthumb

# Default: build C version
TARGET_C = xloader_dumper_c
TARGET_ASM = xloader_dumper

.PHONY: all clean c asm

# Build C version by default
all: c

# === C Version ===
c: $(TARGET_C).img $(TARGET_C).lst
	@echo "Built C version: $(TARGET_C).img"

$(TARGET_C).o: xloader_dumper.c
	$(CC) $(CFLAGS) -c -o $@ $<

startup.o: startup.S
	$(AS) $(ASFLAGS) -o $@ $<

$(TARGET_C).elf: startup.o $(TARGET_C).o linker_c.ld
	$(LD) -T linker_c.ld -nostdlib -o $@ startup.o $(TARGET_C).o

$(TARGET_C).bin: $(TARGET_C).elf
	$(OBJCOPY) -O binary $< $@

$(TARGET_C).lst: $(TARGET_C).elf
	$(OBJDUMP) -d $< > $@

$(TARGET_C).img: $(TARGET_C).bin
	python3 create_image.py $< $@

# === Assembly Version ===
asm: $(TARGET_ASM).img $(TARGET_ASM).lst
	@echo "Built assembly version: $(TARGET_ASM).img"

$(TARGET_ASM).o: $(TARGET_ASM).S
	$(AS) $(ASFLAGS) -o $@ $<

$(TARGET_ASM).elf: $(TARGET_ASM).o linker.ld
	$(LD) -T linker.ld -nostdlib -o $@ $(TARGET_ASM).o

$(TARGET_ASM).bin: $(TARGET_ASM).elf
	$(OBJCOPY) -O binary $< $@

$(TARGET_ASM).lst: $(TARGET_ASM).elf
	$(OBJDUMP) -d $< > $@

$(TARGET_ASM).img: $(TARGET_ASM).bin
	python3 create_image.py $< $@

# Clean everything
clean:
	rm -f *.o *.elf *.bin *.img *.lst
