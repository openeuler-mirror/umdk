#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# options for building

set -e

function usage()
{
  echo "Usage:"
  echo "$0 [options]"
  echo "--coverage                    Enable coverage"
  echo "--debug                       Enable debug compiling"
  echo "--fuzz                        Enable fuzz test"
  echo "--ut                          Enable ut building and execution"
  echo "--rpm                         Enable build rpm package"
  echo "--version                     aigw version"
  echo "--release                     aigw release"
  echo "--notest                      remove all test file"
  echo "--commit-id                   commit id"
  echo "--at                          Enable at building and execution"
  echo "--tsan                        Enable tsan building"
  echo "--clean                       Clean build artifacts"
}

function process_options() {
  WITH_COVERAGE=OFF
  WITH_DEBUG=OFF
  WITH_FUZZ=OFF
  WITH_UT=OFF
  WITH_AT=OFF
  WITH_RPM=OFF
  VERSION=1.0.0
  RELEASE=B001
  WITH_TEST_FILE=ON
  COMMIT_ID=(none)
  WITH_TSAN=OFF
  WITH_CLEAN=OFF

  while [ ${#} -gt 0 ]; do
    case "$1" in
      --coverage)
          WITH_COVERAGE=ON
          shift
          ;;
      --debug)
          WITH_DEBUG=ON
          shift
          ;;
      --fuzz)
          WITH_FUZZ=ON
          shift
          ;;
      --ut)
          WITH_UT=ON
          shift
          ;;
      --at)
          WITH_AT=ON
          shift
          ;;
      --rpm)
          WITH_RPM=ON
          shift
          ;;
      --version)
          shift
          if [ -n "$1" ]; then
            VERSION=$1
          fi
          shift
          ;;
      --release)
          shift
          if [ -n "$1" ]; then
            RELEASE=$1
          fi
          shift
          ;;
      --commit-id)
          shift
          if [ -n "$1" ]; then
            COMMIT_ID=$1
          fi
          shift
          ;;
      --notest)
          WITH_TEST_FILE=OFF
          shift
          ;;
      --tsan)
          WITH_TSAN=ON
          shift
          ;;
      --clean)
          WITH_CLEAN=ON
          shift
          ;;
      *)
          usage
          exit 1
          ;;
    esac
  done
}
