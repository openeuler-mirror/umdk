#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# build rpm

set -e

#build rpm
build_rpm () {
  rm -rf /home/aigw/rpmbuild
  mkdir -p /home/aigw/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
  tar --warning no-file-changed -zcf /home/aigw/rpmbuild/SOURCES/aigw-${VERSION}-${RELEASE}.tar.gz --exclude .git --exclude ./rpmbuild --exclude ./output --exclude ./target --exclude ./example/build --exclude ./open_source/LightGBM-v4.6.0 --exclude ./open_source/eigen-3.4.0 --exclude ./open_source/compute-1.87.0.beta1 --exclude ./open_source/fast_double_parser-v0.8.0 --exclude ./open_source/fmt-11.1.2  .

  cp -r $ROOT_DIR/aigw.spec /home/aigw/rpmbuild/SPECS
  dos2unix /home/aigw/rpmbuild/SPECS/aigw.spec
  rpmbuild --define "_topdir /home/aigw/rpmbuild" --define "rpm_version $VERSION" --define "rpm_release $RELEASE" --define "commit_id $COMMIT_ID" -bb  /home/aigw/rpmbuild/SPECS/aigw.spec
}
