/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: HFA test
 * Author: Nikita Merkulov
 * Note:
 * History:
 */


#include "test_utils.h"

#include <string>
#include <iostream>
#include <fstream>

int read_rands_from_file(const char *file_name, std::vector<size_t> &numbers)
{
    std::ifstream inputFile(file_name);
    std::string line;

    if (!inputFile) {
        std::cerr << "Error: Could not open file.\n";
        return 1;
    }

    size_t sum = 0;
    while (std::getline(inputFile, line)) {
        try {
            size_t num = std::stoull(line); // Convert string to unsigned long long
            sum += num;
            numbers.push_back(num);
        } catch (const std::exception& e) {
            std::cerr << "Skipping invalid line: " << line << "\n";
        }
    }

    inputFile.close();

    std::cout << "Read " << numbers.size() << " numbers from file. sum: " << sum << std::endl;
    return 0;
}
