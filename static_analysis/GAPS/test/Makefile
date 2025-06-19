# Get absolute paths of all test dirs relative to this Makefile
MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
MKFILE_DIR := $(dir $(MKFILE_PATH))
TARGET_DIRS=$(shell find $(MKFILE_DIR) -mindepth 1 -type d)

TOPTARGETS := all clean

$(TOPTARGETS): $(TARGET_DIRS)
$(TARGET_DIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(TARGET_DIRS)
