# HFA (HBM Fast Allocator)

## Overview

**HFA** is a lightweight C++ library that provides fast memory allocation utilities optimized for high-bandwidth memory (HBM) environments. The project is designed to be easy to build, test, and integrate into existing systems.

This document describes how to build the library, run tests, and link it with your application.

---

## Prerequisites

- CMake (>= 4.1.0 recommended)
- A C++ compiler compatible with GCC 11.4.0 or later
- make 4.3
- Google Test 1.10.0 (only required if building tests)

---

## Installing Google Test (Optional)

If Google Test is not already installed on your system, download the prebuilt package:

https://open.codehub.huawei.com/api/codehub/v1/projects/4211/repository/blobs/cdb01d9c9f1d2e1573a84c4f9d8682e150b1b415/raw?file_name=gtest_1.10.0_gcc7.3.0_linux_arm64.tar.gz

Unpack it and ensure the headers and libraries are discoverable by CMake (e.g., via `CMAKE_PREFIX_PATH` or standard system locations).

---

## Building HFA

Create a build directory:

```bash
mkdir -p build
cd build
```

### Build with Tests

```bash
cmake -DBUILD_TESTS=ON ..
make -j
```

### Build without Tests

```bash
cmake -DBUILD_TESTS=OFF ..
make -j
```

After a successful build, the HFA shared library will be located at:

```
<project-home>/lib/libhfa.so
```

---

## Running Tests

If built with `BUILD_TESTS=ON`, run the Google Test binary:

```bash
cd build/bin
./gtest
```

---

## Using HFA in Your Project

### Include Headers

Add the HFA include directory to your include path and include the main header:

```cpp
#include <hbm_fast_alloc.h>
```

### Link the Library

Link your application against `libhfa.so`:

```bash
-lhfa
```

Make sure the runtime linker can locate the library (e.g., by setting `LD_LIBRARY_PATH` or installing the library to a standard location).

---


