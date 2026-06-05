#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WORKSPACE_DIR="${SCRIPT_DIR}"
PACKAGE_NAME="urma-bazel"
LIBDIR="/usr/lib64"
BINDIR="/usr/bin"
INCLUDEDIR="/usr/include/ub/umdk/urma"
DOCDIR="/usr/share/doc/umdk-examples/urma_example"
UMMU_INCLUDEDIR="/usr/include"
UMMU_DOCDIR="/usr/share/doc/ub/libummu"
MANDIR="/usr/share/man/man3"
ROOTFS_DIR="rootfs"
METADATA_DIR="metadata"
INSTALL_MANIFEST="install_manifest"
THIRD_PARTY_DIR="${WORKSPACE_DIR}/third_party"
LIBUMMU_DIR="${THIRD_PARTY_DIR}/libummu"

BUILD_DEPENDENCY_PACKAGES=(
    "bazel"
    "git"
    "gcc"
    "gcc-c++"
    "glibc-devel"
    "libnl3-devel"
    "tar"
    "gzip"
)

RUNTIME_DEPENDENCY_PACKAGES=(
    "glibc"
    "libgcc"
    "libstdc++"
    "libnl3"
)

ARCHIVE_TOOL_PACKAGES=(
    "tar"
    "gzip"
)

BAZEL_TARGETS=(
    "//:ummu"
    "//:urma"
    "//:urma_common"
    "//:urma_ubagg"
    "//:urma-udma"
    "//:tpsa"
    "//:urma_admin"
    "//:urma_perftest"
    "//:urma_ping"
    "//:urma_sample"
)

usage()
{
    cat <<EOF
Usage:
  $0 <command> [options]

Commands:
  compile [bazel build args...]
      Build URMA and libummu with Bazel, stage the install payload, and
      create a ${PACKAGE_NAME}-<timestamp>.tar.gz package in the workspace.
      Any extra arguments are passed directly to 'bazel build'.

  install [package.tar.gz]
      Install files from a generated package. If no package is provided, run
      this command from an extracted package directory and it installs the
      package beside this script.

  remove [package.tar.gz|extracted_package_dir]
      Remove files listed in the package install manifest. If no argument is
      provided, run this command from an extracted package directory and it
      removes the package beside this script.
      Third-party dependencies installed by yum, and the bundled libummu
      payload, are left installed.

  help, -h, --help
      Show this help message.

Examples:
  # Build a release package for AArch64 with the UDMA provider enabled.
  $0 compile --config=release --config=arm64 --define=build_udma=true

  # Install directly from a generated package archive.
  $0 install ${PACKAGE_NAME}-20260605120000.tar.gz

  # Extract a package, then install from the extracted package directory.
  tar -xzf ${PACKAGE_NAME}-20260605120000.tar.gz -C /tmp/urma-bazel
  /tmp/urma-bazel/urma_bazel.sh install

  # Remove files by reading the manifest from a generated package archive.
  $0 remove ${PACKAGE_NAME}-20260605120000.tar.gz

  # Remove files by running the script from an extracted package directory.
  /tmp/urma-bazel/urma_bazel.sh remove

Notes:
  - The compile and install commands check required yum dependencies first.
    Already satisfied dependencies are left untouched; missing dependencies are
    installed with 'yum install -y'.
  - The compile command fetches the configured libummu commit into
    ${THIRD_PARTY_DIR}/libummu and builds it through Bazel.
  - The install command refreshes ldconfig and restarts rsyslog when available.
  - The remove command does not uninstall third-party libraries.
EOF
}

need_cmd()
{
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: command '$1' not found" >&2
        exit 1
    fi
}

append_unique()
{
    local value="$1"
    shift
    local item

    for item in "$@"; do
        if [ "${item}" = "${value}" ]; then
            return
        fi
    done
    printf '%s\n' "${value}"
}

library_glob_exists()
{
    local pattern="$1"
    local dir

    for dir in /lib64 /usr/lib64 /lib /usr/lib; do
        if compgen -G "${dir}/${pattern}" >/dev/null; then
            return 0
        fi
    done
    return 1
}

library_exists()
{
    local library="$1"

    if command -v ldconfig >/dev/null 2>&1 &&
        ldconfig -p 2>/dev/null | awk '{print $1}' | grep -Fxq "${library}"; then
        return 0
    fi
    library_glob_exists "${library}"
}

libnl3_devel_exists()
{
    if command -v pkg-config >/dev/null 2>&1 &&
        pkg-config --exists libnl-3.0 libnl-genl-3.0; then
        return 0
    fi

    [ -f /usr/include/libnl3/netlink/netlink.h ] &&
        library_glob_exists "libnl-3.so" &&
        library_glob_exists "libnl-genl-3.so"
}

dependency_satisfied()
{
    local package="$1"

    case "${package}" in
        bazel)
            command -v bazel >/dev/null 2>&1
            ;;
        git)
            command -v git >/dev/null 2>&1
            ;;
        gcc)
            command -v gcc >/dev/null 2>&1
            ;;
        gcc-c++)
            command -v g++ >/dev/null 2>&1 || command -v c++ >/dev/null 2>&1
            ;;
        glibc-devel)
            [ -f /usr/include/stdio.h ] &&
                { [ -f /usr/lib64/libc.so ] || [ -f /usr/lib/libc.so ]; }
            ;;
        libnl3-devel)
            libnl3_devel_exists
            ;;
        tar)
            command -v tar >/dev/null 2>&1
            ;;
        gzip)
            command -v gzip >/dev/null 2>&1
            ;;
        glibc)
            library_exists "libc.so.6"
            ;;
        libgcc)
            library_exists "libgcc_s.so.1"
            ;;
        libstdc++)
            library_exists "libstdc++.so.6"
            ;;
        libnl3)
            library_exists "libnl-3.so.200" && library_exists "libnl-genl-3.so.200"
            ;;
        libasan)
            library_glob_exists "libasan.so*"
            ;;
        libtsan)
            library_glob_exists "libtsan.so*"
            ;;
        *)
            command -v rpm >/dev/null 2>&1 && rpm -q "${package}" >/dev/null 2>&1
            ;;
    esac
}

yum_install_packages()
{
    local reason="$1"
    shift

    if [ "$#" -eq 0 ]; then
        return
    fi
    if ! command -v yum >/dev/null 2>&1; then
        echo "Error: missing ${reason} dependencies: $*. The 'yum' command is not available." >&2
        exit 1
    fi

    echo "Installing missing ${reason} dependencies: $*"
    if [ "$(id -u)" -eq 0 ]; then
        yum install -y "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo yum install -y "$@"
    else
        echo "Error: missing ${reason} dependencies: $*. Run as root or install them manually." >&2
        exit 1
    fi
}

require_root()
{
    local command="$1"

    if [ "$(id -u)" -ne 0 ]; then
        echo "Error: '${command}' modifies system files. Run it as root or with sudo." >&2
        exit 1
    fi
}

ensure_yum_dependencies()
{
    local reason="$1"
    shift
    local missing=()
    local package
    local unique

    for package in "$@"; do
        if dependency_satisfied "${package}"; then
            continue
        fi
        unique=$(append_unique "${package}" "${missing[@]}")
        if [ -n "${unique}" ]; then
            missing+=("${unique}")
        fi
    done

    yum_install_packages "${reason}" "${missing[@]}"
}

ensure_archive_tool_dependencies()
{
    ensure_yum_dependencies "archive tool" "${ARCHIVE_TOOL_PACKAGES[@]}"
}

ensure_build_dependencies()
{
    local build_args=("$@")
    local package
    local packages=("${BUILD_DEPENDENCY_PACKAGES[@]}")

    for package in "${build_args[@]}"; do
        case "${package}" in
            --config=asan|--config=*asan*|--copt=-fsanitize=address|--linkopt=-fsanitize=address)
                packages+=("libasan")
                ;;
            --config=tsan|--config=*tsan*|--copt=-fsanitize=thread|--linkopt=-fsanitize=thread)
                packages+=("libtsan")
                ;;
            *)
                ;;
        esac
    done

    ensure_yum_dependencies "build" "${packages[@]}"
}

ensure_runtime_dependencies()
{
    local source_dir="$1"
    local version_file="${source_dir}/${METADATA_DIR}/urma_version"
    local packages=("${RUNTIME_DEPENDENCY_PACKAGES[@]}")
    local build_command=""

    if [ -f "${version_file}" ]; then
        build_command=$(sed -n 's/^build_command=//p' "${version_file}" | head -n 1)
    fi

    case "${build_command}" in
        *--config=asan*|*--copt=-fsanitize=address*|*--linkopt=-fsanitize=address*)
            packages+=("libasan")
            ;;
        *)
            ;;
    esac
    case "${build_command}" in
        *--config=tsan*|*--copt=-fsanitize=thread*|*--linkopt=-fsanitize=thread*)
            packages+=("libtsan")
            ;;
        *)
            ;;
    esac

    ensure_yum_dependencies "runtime" "${packages[@]}"
}

copy_file()
{
    local src="$1"
    local dst="$2"
    install -D -m 0644 "${src}" "${dst}"
}

copy_private_file()
{
    local src="$1"
    local dst="$2"
    install -D -m 0600 "${src}" "${dst}"
}

copy_exec()
{
    local src="$1"
    local dst="$2"
    install -D -m 0755 "${src}" "${dst}"
}

remove_path()
{
    local path="$1"
    if [ -L "${path}" ]; then
        rm -f "${path}"
    elif [ -e "${path}" ]; then
        rm -rf "${path}"
    fi
}

cleanup_compile_artifacts()
{
    rm -f "${WORKSPACE_DIR}/urma_version"
    remove_path "${WORKSPACE_DIR}/bazel-urma-package"
    remove_path "${WORKSPACE_DIR}/bazel-bin"
    remove_path "${WORKSPACE_DIR}/bazel-out"
    remove_path "${WORKSPACE_DIR}/bazel-testlogs"
    remove_path "${WORKSPACE_DIR}/bazel-urma"
}

workspace_var()
{
    local name="$1"
    local value

    value=$(sed -n "s/^${name}[[:space:]]*=[[:space:]]*\"\\(.*\\)\"[[:space:]]*$/\\1/p" \
        "${WORKSPACE_DIR}/WORKSPACE" "${WORKSPACE_DIR}/bazel/urma_deps.bzl" | head -n 1)
    if [ -z "${value}" ]; then
        echo "Error: ${name} is not configured in WORKSPACE or bazel/urma_deps.bzl" >&2
        exit 1
    fi
    echo "${value}"
}

metadata_var()
{
    local name="$1"
    local file="${SCRIPT_DIR}/${METADATA_DIR}/urma_version"
    local value=""

    if [ -f "${file}" ]; then
        value=$(sed -n "s/^${name}=\\(.*\\)$/\\1/p" "${file}" | head -n 1)
    fi
    echo "${value}"
}

config_var()
{
    local name="$1"
    local value=""

    if [ -f "${WORKSPACE_DIR}/WORKSPACE" ]; then
        value=$(sed -n "s/^${name}[[:space:]]*=[[:space:]]*\"\\(.*\\)\"[[:space:]]*$/\\1/p" "${WORKSPACE_DIR}/WORKSPACE" | head -n 1)
    fi
    if [ -z "${value}" ] && [ -f "${WORKSPACE_DIR}/bazel/urma_deps.bzl" ]; then
        value=$(sed -n "s/^${name}[[:space:]]*=[[:space:]]*\"\\(.*\\)\"[[:space:]]*$/\\1/p" "${WORKSPACE_DIR}/bazel/urma_deps.bzl" | head -n 1)
    fi
    if [ -z "${value}" ]; then
        value=$(metadata_var "${name}")
    fi
    if [ -z "${value}" ]; then
        echo "Error: ${name} is not configured in WORKSPACE, bazel/urma_deps.bzl, or metadata/urma_version" >&2
        exit 1
    fi
    echo "${value}"
}

extract_cmake_version()
{
    local file="$1"
    local version

    if [ ! -f "${file}" ]; then
        echo "Error: ${file} not found; cannot determine project version" >&2
        exit 1
    fi

    version=$(
        sed -n \
            -e 's/^[[:space:]]*VERSION[[:space:]]*\([0-9][0-9.]*\).*/\1/p' \
            -e 's/^[[:space:]]*set[[:space:]]*([[:space:]]*PROJECT_VERSION[[:space:]]*"\{0,1\}\([0-9][0-9.]*\)"\{0,1\}.*/\1/p' \
            "${file}" | head -n 1
    )
    if [ -n "${version}" ]; then
        echo "${version}"
    else
        echo "Error: cannot determine project version from ${file}" >&2
        exit 1
    fi
}

project_version()
{
    local key="$1"
    local cmake_file="$2"
    local value

    if [ -f "${cmake_file}" ]; then
        extract_cmake_version "${cmake_file}"
        return
    fi

    value=$(metadata_var "${key}")
    if [ -n "${value}" ]; then
        echo "${value}"
    else
        echo "Error: ${key} is not available in source CMakeLists.txt or metadata/urma_version" >&2
        exit 1
    fi
}

stage_versioned_so()
{
    local src="$1"
    local dir="$2"
    local name="$3"
    local version="$4"
    local major="${5:-${version%%.*}}"

    install -D -m 0755 "${src}" "${dir}/${name}.so.${version}"
    ln -sfn "${name}.so.${version}" "${dir}/${name}.so.${major}"
    ln -sfn "${name}.so.${major}" "${dir}/${name}.so"
}

prepare_libummu()
{
    local remote
    local commit
    local actual_commit

    remote=$(workspace_var LIBUMMU_REMOTE)
    commit=$(workspace_var LIBUMMU_COMMIT)

    need_cmd git
    mkdir -p "${THIRD_PARTY_DIR}"

    if [ ! -d "${LIBUMMU_DIR}/.git" ]; then
        remove_path "${LIBUMMU_DIR}"
        git clone "${remote}" "${LIBUMMU_DIR}"
    fi

    git -C "${LIBUMMU_DIR}" remote set-url origin "${remote}"
    git -C "${LIBUMMU_DIR}" fetch origin "${commit}"
    git -C "${LIBUMMU_DIR}" reset --hard "${commit}"
    git -C "${LIBUMMU_DIR}" clean -fdx

    actual_commit=$(git -C "${LIBUMMU_DIR}" rev-parse HEAD)
    if [ "${actual_commit}" != "${commit}" ]; then
        echo "Error: libummu HEAD ${actual_commit} does not match configured commit ${commit}" >&2
        exit 1
    fi

    if [ ! -f "${WORKSPACE_DIR}/bazel/libummu.BUILD.bazel" ]; then
        echo "Error: ${WORKSPACE_DIR}/bazel/libummu.BUILD.bazel not found" >&2
        exit 1
    fi
    if [ ! -f "${LIBUMMU_DIR}/include/ummu_api.h" ] || [ ! -f "${LIBUMMU_DIR}/kernel_headers/ummu_core.h" ]; then
        echo "Error: configured libummu source tree is incomplete" >&2
        exit 1
    fi
}

create_version_file()
{
    local version_file="$1"
    local build_cmd="$2"
    local commit_id="unknown"

    if git -C "${WORKSPACE_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        commit_id=$(git -C "${WORKSPACE_DIR}" rev-parse HEAD)
    fi

    {
        echo "commit_id=${commit_id}"
        echo "build_time=$(date '+%Y-%m-%d %H:%M:%S %z')"
        echo "build_command=${build_cmd}"
        echo "COMMON_VERSION=$(extract_cmake_version "${WORKSPACE_DIR}/../CMakeLists.txt")"
        echo "URMA_VERSION=$(extract_cmake_version "${WORKSPACE_DIR}/lib/urma/core/CMakeLists.txt")"
        echo "libummu_remote=$(workspace_var LIBUMMU_REMOTE)"
        echo "libummu_commit=$(workspace_var LIBUMMU_COMMIT)"
        echo "LIBUMMU_VERSION=$(workspace_var LIBUMMU_VERSION)"
        echo "LIBUMMU_ABI_VERSION=$(workspace_var LIBUMMU_ABI_VERSION)"
    } > "${version_file}"
}

stage_libummu_payload()
{
    local rootfs="$1"
    local bin_dir="$2"
    local libummu_version
    local libummu_abi_version

    libummu_version=$(config_var LIBUMMU_VERSION)
    libummu_abi_version=$(config_var LIBUMMU_ABI_VERSION)

    stage_versioned_so "${bin_dir}/libummu.so" "${rootfs}${LIBDIR}" "libummu" "${libummu_version}" "${libummu_abi_version}"
    copy_file "${LIBUMMU_DIR}/include/ummu_api.h" "${rootfs}${UMMU_INCLUDEDIR}/ummu_api.h"
    copy_file "${LIBUMMU_DIR}/kernel_headers/ummu_core.h" "${rootfs}${UMMU_INCLUDEDIR}/ummu_core.h"
    copy_file "${LIBUMMU_DIR}/README.md" "${rootfs}${UMMU_DOCDIR}/README.md"
    copy_file "${LIBUMMU_DIR}/doc/API.md" "${rootfs}${UMMU_DOCDIR}/API.md"
    copy_file "${LIBUMMU_DIR}/doc/Design.md" "${rootfs}${UMMU_DOCDIR}/Design.md"
    copy_file "${LIBUMMU_DIR}/doc/man3/libummu.3" "${rootfs}${UMMU_DOCDIR}/man3/libummu.3"
    copy_file "${LIBUMMU_DIR}/doc/man3/libummu.3" "${rootfs}${MANDIR}/libummu.3"
    gzip -f9n "${rootfs}${MANDIR}/libummu.3"
    chmod 0644 "${rootfs}${MANDIR}/libummu.3.gz"
}

generate_install_manifest()
{
    local rootfs="$1"
    local manifest="$2"

    : > "${manifest}"
    (
        cd "${rootfs}"
        find . -mindepth 1 -type d -printf '%P\n' | sort | while IFS= read -r rel; do
            printf 'd\t%s\t%s\t-\n' "$(stat -c '%a' "${rel}")" "${rel}"
        done
        find . -mindepth 1 ! -type d -printf '%P\n' | sort | while IFS= read -r rel; do
            if [ -L "${rel}" ]; then
                printf 'l\t777\t%s\t%s\n' "${rel}" "$(readlink "${rel}")"
            else
                printf 'f\t%s\t%s\t-\n' "$(stat -c '%a' "${rel}")" "${rel}"
            fi
        done
    ) > "${manifest}"
}

strip_payload_elfs()
{
    local rootfs="$1"

    if ! command -v strip >/dev/null 2>&1 || ! command -v readelf >/dev/null 2>&1; then
        return
    fi

    find "${rootfs}" -type f -exec sh -c '
        for file do
            if readelf -h "${file}" >/dev/null 2>&1; then
                strip --strip-unneeded "${file}" >/dev/null 2>&1 || true
            fi
        done
    ' sh {} +
}

stage_payload()
{
    local stage_dir="$1"
    local bin_dir="${WORKSPACE_DIR}/bazel-bin"
    local rootfs="${stage_dir}/${ROOTFS_DIR}"
    local common_version
    local library_version

    common_version=$(project_version COMMON_VERSION "${WORKSPACE_DIR}/../CMakeLists.txt")
    library_version=$(project_version URMA_VERSION "${WORKSPACE_DIR}/lib/urma/core/CMakeLists.txt")

    rm -rf "${stage_dir}"
    mkdir -p "${rootfs}${LIBDIR}/urma" "${rootfs}${BINDIR}" "${rootfs}${INCLUDEDIR}/udma"

    stage_versioned_so "${bin_dir}/liburma.so" "${rootfs}${LIBDIR}" "liburma" "${library_version}"
    stage_versioned_so "${bin_dir}/liburma_common.so" "${rootfs}${LIBDIR}" "liburma_common" "${common_version}"
    stage_versioned_so "${bin_dir}/libtpsa.so" "${rootfs}${LIBDIR}" "libtpsa" "${library_version}"
    stage_versioned_so "${bin_dir}/liburma_ubagg.so" "${rootfs}${LIBDIR}/urma" "liburma_ubagg" "${library_version}"
    copy_exec "${bin_dir}/liburma-udma.so" "${rootfs}${LIBDIR}/urma/liburma-udma.so"
    stage_libummu_payload "${rootfs}" "${bin_dir}"

    copy_exec "${bin_dir}/urma_admin" "${rootfs}${BINDIR}/urma_admin"
    copy_exec "${bin_dir}/urma_perftest" "${rootfs}${BINDIR}/urma_perftest"
    copy_exec "${bin_dir}/urma_ping" "${rootfs}${BINDIR}/urma_ping"
    copy_exec "${bin_dir}/urma_sample" "${rootfs}${BINDIR}/urma_sample"

    copy_file "${WORKSPACE_DIR}/lib/urma/core/include/urma_api.h" "${rootfs}${INCLUDEDIR}/urma_api.h"
    copy_file "${WORKSPACE_DIR}/lib/urma/core/include/urma_cmd.h" "${rootfs}${INCLUDEDIR}/urma_cmd.h"
    copy_file "${WORKSPACE_DIR}/lib/urma/core/include/urma_opcode.h" "${rootfs}${INCLUDEDIR}/urma_opcode.h"
    copy_file "${WORKSPACE_DIR}/lib/urma/core/include/urma_provider.h" "${rootfs}${INCLUDEDIR}/urma_provider.h"
    copy_file "${WORKSPACE_DIR}/lib/urma/core/include/urma_types_str.h" "${rootfs}${INCLUDEDIR}/urma_types_str.h"
    copy_file "${WORKSPACE_DIR}/lib/urma/core/include/urma_types.h" "${rootfs}${INCLUDEDIR}/urma_types.h"
    copy_file "${WORKSPACE_DIR}/lib/urma/core/include/urma_perf.h" "${rootfs}${INCLUDEDIR}/urma_perf.h"
    copy_file "${WORKSPACE_DIR}/lib/urma/bond/include/urma_ubagg.h" "${rootfs}${INCLUDEDIR}/urma_ubagg.h"
    copy_file "${WORKSPACE_DIR}/lib/uvs/core/include/uvs_api.h" "${rootfs}${INCLUDEDIR}/uvs_api.h"
    copy_file "${WORKSPACE_DIR}/lib/uvs/core/include/uvs_types.h" "${rootfs}${INCLUDEDIR}/uvs_types.h"
    copy_file "${WORKSPACE_DIR}/hw/udma/include/udma_u_ctl.h" "${rootfs}${INCLUDEDIR}/udma/udma_u_ctl.h"
    copy_file "${WORKSPACE_DIR}/examples/README.md" "${rootfs}${DOCDIR}/README.md"

    copy_private_file "${WORKSPACE_DIR}/lib/urma/config/urma.conf" "${rootfs}/etc/rsyslog.d/urma.conf"
    copy_private_file "${WORKSPACE_DIR}/lib/urma/config/urma" "${rootfs}/etc/logrotate.d/urma"
    copy_private_file "${WORKSPACE_DIR}/lib/uvs/config/tpsa.conf" "${rootfs}/etc/rsyslog.d/tpsa.conf"
    copy_file "${WORKSPACE_DIR}/lib/uvs/config/tpsa" "${rootfs}/etc/logrotate.d/tpsa"
    copy_private_file "${WORKSPACE_DIR}/tools/urma_admin/config/urma_admin.conf" "${rootfs}/etc/rsyslog.d/urma_admin.conf"

    find "${rootfs}" -type d -exec chmod 0755 {} +
    strip_payload_elfs "${rootfs}"
}

compile_cmd()
{
    local build_args=("$@")

    ensure_build_dependencies "${build_args[@]}"
    need_cmd bazel
    need_cmd git
    need_cmd gzip
    need_cmd tar

    local build_cmd="$0 compile"
    if [ "${#build_args[@]}" -gt 0 ]; then
        build_cmd="${build_cmd} ${build_args[*]}"
    fi

    local stage_dir="${WORKSPACE_DIR}/bazel-urma-package"
    local tarball="${WORKSPACE_DIR}/${PACKAGE_NAME}-$(date '+%Y%m%d%H%M%S').tar.gz"

    trap cleanup_compile_artifacts EXIT
    prepare_libummu
    bazel sync --only=libummu
    create_version_file "${WORKSPACE_DIR}/urma_version" "${build_cmd}"
    bazel build "${BAZEL_TARGETS[@]}" "${build_args[@]}"

    stage_payload "${stage_dir}"
    mkdir -p "${stage_dir}/${METADATA_DIR}"
    generate_install_manifest "${stage_dir}/${ROOTFS_DIR}" "${stage_dir}/${METADATA_DIR}/${INSTALL_MANIFEST}"
    copy_file "${WORKSPACE_DIR}/urma_version" "${stage_dir}/${METADATA_DIR}/urma_version"
    copy_exec "${WORKSPACE_DIR}/urma_bazel.sh" "${stage_dir}/urma_bazel.sh"

    tar -C "${stage_dir}" -czf "${tarball}" .
    echo "Created ${tarball}"
}

extract_package()
{
    local package="$1"
    local tmp_dir="$2"

    mkdir -p "${tmp_dir}"
    tar -C "${tmp_dir}" -xzf "${package}"
    echo "${tmp_dir}"
}

restart_rsyslog()
{
    if [ -x /usr/bin/systemctl ] && [ -x /usr/sbin/rsyslogd ]; then
        timeout 10s /usr/bin/systemctl restart rsyslog >/dev/null 2>&1 || true
    fi
}

restore_selinux_contexts()
{
    local manifest="$1"

    if command -v restorecon >/dev/null 2>&1 && [ -f "${manifest}" ]; then
        {
            awk -F '\t' 'NF >= 3 { print "/" $3 }' "${manifest}"
            echo "/etc/ld.so.cache"
        } | xargs -r restorecon -F >/dev/null 2>&1 || true
    fi
}

install_from_manifest()
{
    local source_dir="$1"
    local rootfs="${source_dir}/${ROOTFS_DIR}"
    local manifest="${source_dir}/${METADATA_DIR}/${INSTALL_MANIFEST}"
    local type
    local mode
    local rel
    local target
    local src
    local dst

    if [ ! -f "${manifest}" ]; then
        echo "Error: ${manifest} not found." >&2
        exit 1
    fi

    while IFS=$'\t' read -r type mode rel target; do
        [ -n "${type}" ] || continue
        src="${rootfs}/${rel}"
        dst="/${rel}"

        case "${type}" in
            d)
                install -d -m "${mode}" "${dst}"
                ;;
            f)
                if [ -d "${dst}" ] && [ ! -L "${dst}" ]; then
                    rm -rf "${dst}"
                fi
                install -D -m "${mode}" "${src}" "${dst}"
                ;;
            l)
                if [ -d "${dst}" ] && [ ! -L "${dst}" ]; then
                    rm -rf "${dst}"
                fi
                mkdir -p "$(dirname "${dst}")"
                rm -f "${dst}"
                ln -s "${target}" "${dst}"
                ;;
            *)
                echo "Error: unsupported manifest entry type '${type}' in ${manifest}" >&2
                exit 1
                ;;
        esac
    done < "${manifest}"
}

remove_from_manifest()
{
    local manifest="$1"
    local type
    local mode
    local rel
    local target
    local dst

    if [ ! -f "${manifest}" ]; then
        echo "Error: ${manifest} not found. Run remove from an extracted package directory." >&2
        exit 1
    fi

    tac "${manifest}" | while IFS=$'\t' read -r type mode rel target; do
        [ -n "${type}" ] || continue
        dst="/${rel}"

        if is_third_party_manifest_entry "${rel}"; then
            continue
        fi

        case "${type}" in
            f|l)
                remove_one "${dst}"
                ;;
            d)
                remove_empty_dir "${dst}"
                ;;
            *)
                echo "Error: unsupported manifest entry type '${type}' in ${manifest}" >&2
                exit 1
                ;;
        esac
    done
}

is_third_party_manifest_entry()
{
    local rel="$1"

    case "${rel}" in
        usr/lib64/libummu.so|usr/lib64/libummu.so.*)
            return 0
            ;;
        usr/include/ummu_api.h|usr/include/ummu_core.h)
            return 0
            ;;
        usr/share/doc/ub/libummu|usr/share/doc/ub/libummu/*)
            return 0
            ;;
        usr/share/man/man3/libummu.3.gz)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

install_cmd()
{
    local package="${1:-}"
    local source_dir="${SCRIPT_DIR}"
    local tmp_dir=""

    require_root "install"

    if [ -n "${package}" ]; then
        ensure_archive_tool_dependencies
        need_cmd tar
        tmp_dir=$(mktemp -d)
        source_dir=$(extract_package "${package}" "${tmp_dir}")
    fi

    if [ ! -d "${source_dir}/${ROOTFS_DIR}" ]; then
        echo "Error: ${source_dir}/${ROOTFS_DIR} not found. Run from an extracted package or pass package.tar.gz." >&2
        exit 1
    fi

    ensure_runtime_dependencies "${source_dir}"

    if [ -d /usr/bin/urma_admin ] && [ ! -L /usr/bin/urma_admin ]; then
        rm -rf /usr/bin/urma_admin
    fi

    install_from_manifest "${source_dir}"
    if command -v ldconfig >/dev/null 2>&1; then
        ldconfig
    fi
    restore_selinux_contexts "${source_dir}/${METADATA_DIR}/${INSTALL_MANIFEST}"
    if [ -x /usr/bin/systemctl ]; then
        timeout 10s /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    restart_rsyslog

    if [ -n "${tmp_dir}" ]; then
        rm -rf "${tmp_dir}"
    fi
}

remove_one()
{
    local path="$1"
    if [ -e "${path}" ] || [ -L "${path}" ]; then
        rm -f "${path}"
    fi
}

remove_empty_dir()
{
    local dir="$1"
    rmdir "${dir}" >/dev/null 2>&1 || true
}

remove_cmd()
{
    local package="${1:-}"
    local source_dir="${SCRIPT_DIR}"
    local tmp_dir=""
    local manifest

    require_root "remove"

    if [ -n "${package}" ]; then
        if [ -d "${package}" ]; then
            source_dir="${package}"
        else
            ensure_archive_tool_dependencies
            need_cmd tar
            tmp_dir=$(mktemp -d)
            source_dir=$(extract_package "${package}" "${tmp_dir}")
        fi
    fi

    manifest="${source_dir}/${METADATA_DIR}/${INSTALL_MANIFEST}"

    remove_from_manifest "${manifest}"

    if command -v ldconfig >/dev/null 2>&1; then
        ldconfig
    fi
    restore_selinux_contexts "${manifest}"
    restart_rsyslog

    if [ -n "${tmp_dir}" ]; then
        rm -rf "${tmp_dir}"
    fi
}

main()
{
    local command="${1:-}"
    if [ -z "${command}" ]; then
        usage
        exit 1
    fi
    shift

    case "${command}" in
        compile)
            compile_cmd "$@"
            ;;
        install)
            install_cmd "$@"
            ;;
        remove)
            remove_cmd "$@"
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
