#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# build rpm

set -e

#build rpm
build_rpm () {
  rm -rf /home/aigw/rpmbuild
  mkdir -p /home/aigw/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
  tar --warning no-file-changed -zcf /home/aigw/rpmbuild/SOURCES/aigw-${VERSION}-${RELEASE}.tar.gz --exclude .git --exclude ./rpmbuild  .

  cp -r $ROOT_DIR/aigw.spec /home/aigw/rpmbuild/SPECS
  dos2unix /home/aigw/rpmbuild/SPECS/aigw.spec
  rpmbuild --define "_topdir /home/aigw/rpmbuild" --define "rpm_version $VERSION" --define "rpm_release $RELEASE" --define "commit_id $COMMIT_ID" -bb  /home/aigw/rpmbuild/SPECS/aigw.spec
}