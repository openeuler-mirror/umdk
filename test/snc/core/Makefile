#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: Unit test Makefile for snc_ping module (gtest + stubs)
#
# Usage:
#   make          - build and run tests
#   make build    - build only
#   make run      - run tests only
#   make clean    - clean build artifacts
#
# Prerequisites:
#   - g++ (C++11)
#   - gtest installed (or set GTEST_DIR to point to googletest source)
#   - pthread
#

CXX := g++
TARGET := test_snc_ping

CXXFLAGS := -std=c++11\
        -fstack-protector-strong\
        -g\
        -Wall\
        -Wextra

LDFLAGS := -lpthread

# gtest can come from system or a local source tree
GTEST_SYS_INC := $(shell echo "\#include <gtest/gtest.h>" | $(CXX) -x c++ -E - 2>/dev/null >/dev/null && echo yes)
ifeq ($(GTEST_SYS_INC),yes)
    GTEST_FLAGS :=
    GTEST_LIBS := -lgtest -lgtest_main
else
    # If gtest is not installed system-wide, set GTEST_DIR
    GTEST_DIR ?= /usr/src/googletest
    GTEST_FLAGS := -I$(GTEST_DIR)/googletest/include
    GTEST_LIBS := $(GTEST_DIR)/googletest/make/gtest_main.a -lpthread
endif

SNC_CORE_DIR := ../../../src/snc/src/core
STUB_DIR := stubs

INC := -I$(SNC_CORE_DIR)/include\
       -I$(SNC_CORE_DIR)/src\
       -I$(SNC_CORE_DIR)/log\
       -I$(STUB_DIR)

SRC_FILES := $(SNC_CORE_DIR)/src/snc_ping.cc\
             $(SNC_CORE_DIR)/log/snc_ping_log.cc\
             $(STUB_DIR)/stub_impl.cc\
             test_snc_ping.cc\
             test_snc_ping_log.cc

.PHONY: all build run clean

all: build run

build: $(TARGET)

$(TARGET): $(SRC_FILES)
	$(CXX) $(CXXFLAGS) $(GTEST_FLAGS) $(INC) $(SRC_FILES) -o $(TARGET) $(GTEST_LIBS) $(LDFLAGS)
	@printf "\nBuild complete: %s\n" $(TARGET)

run: $(TARGET)
	./$(TARGET) --gtest_color=yes

clean:
	rm -f $(TARGET)
