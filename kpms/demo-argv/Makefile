ifndef TARGET_COMPILE
$(error TARGET_COMPILE not set)
endif
ifndef KP_DIR
KP_DIR = ../..
endif
CC = $(TARGET_COMPILE)gcc
INCLUDE_DIRS := . include patch/include patch/include/uapi linux/include linux/include/uapi linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))
all: argv_demo.kpm
argv_demo.kpm: argv_demo.o
	$(CC) -r -o $@ $^
argv_demo.o: argv_demo.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -Targv_demo.lds -c -O2 -o $@ $<
.PHONY: clean
clean:
	rm -f argv_demo.kpm argv_demo.o
