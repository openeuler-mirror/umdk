# add --with asan option, i.e. disable asan by default
%bcond_with asan

# add --with tsan option, i.e. disable tsan by default
%bcond_with tsan

# add --with gcov option, i.e. disable gcov by default
%bcond_with gcov

# add --with test option, i.e. disable test by default
%bcond_with test

# add --with ubagg_disable option, i.e. enable ubagg by default
%bcond_with ubagg_disable

# add --with release_enable option, i.e. disable release by default
%bcond_with release_enable

# add --with urma option, i.e. disable urma by default
%bcond_with urma

# add --with ums option, i.e. disable ums by default
%bcond_with ums

# add --with urpc option, i.e. disable urpc by default
%bcond_with urpc

# add --with dlock option, i.e. disable dlock by default
%bcond_with dlock

%define build_all 1

%if %{with ums} || %{with urma} || %{with urpc} || %{with dlock}
    %define build_all 0
%endif

%if %{defined kernel_version}
    %define kernel_build_path /lib/modules/%{kernel_version}/build
%else
    %define kernel_version %( \
        rpm -q --qf "%%{VERSION}-%%{RELEASE}.%%{ARCH}" kernel-devel 2>/dev/null || \
        uname -r \
    )
    %define kernel_build_path /lib/modules/%{kernel_version}/build
%endif
%define kernel_requires_version %(echo %{kernel_version} | awk -F"." 'OFS="."{$NF="";print}' | sed 's/\.$//g')

%if %{undefined rpm_release}
    %define rpm_release 0
%endif

Name          : umdk
Summary       : Unified memory development kit
Version       : 25.12.0
Release       : %{rpm_release}%{?dist}
Group         : umdk
License       : Proprietary
Vendor        : Huawei Technologies Co., Ltd
Source0       : %{name}-%{version}.tar.gz
BuildRoot     : %{_buildirootdir}/%{name}-%{version}-build
buildArch     : x86_64 aarch64

BuildRequires : rpm-build, make, cmake, gcc, gcc-c++, glibc-devel, openssl-devel, glib2-devel, libnl3-devel, kernel-devel, libummu-devel
Requires: glibc, glib2, libummu
%if %{with asan}
Requires: libasan
%endif
%if %{with tsan}
Requires: libtsan
%endif

%description
A new system interconnect architecture

%if %{build_all} || %{with urma} || %{with urpc}
%package urma-lib
Requires:       libummu
Summary:        Basic URMA libraries of UMDK

%description urma-lib
This package contains basic URMA libraries of UMDK, such as liburma.so.

%package urma-devel
Summary:        Include Files and Libraries mandatory for URMA
AutoReqProv:    on

%description urma-devel
This package contains all necessary include files and libraries needed
to develop applications that require the provided includes and
libraries.

%package urma-tools
Summary:        tools of urma
Requires:       umdk-urma-lib = %{version}
%description urma-tools
tools of urma, contains  urma_perftest, urma_admin, ubagg_cli.

%package urma-bin
Summary:        binary file of urma
BuildRequires:  gcc
Requires:       glibc
%description urma-bin
binary file of urma

%package urma-example
Summary:        UMDK examples
Requires:       umdk-urma-lib = %{version}
AutoReqProv:    on
%description urma-example
This package contains all the executable examples of UMDK.

%if %{with test}
%package urma-test
Summary:        Include Libraries for URMA test
Requires:       umdk-urma-lib = %{version}
AutoReqProv:    on
%description urma-test
This package contains all necessary libraries needed
to develop applications based on urma_test.
%endif
%endif

%if %{build_all} || %{with dlock}
%package dlock-lib
Summary:        Library files of dlock
Requires:       umdk-urma-lib = %{version}

%description dlock-lib
This package contains the libdlock*.so files for the distributed lock feature.

%package dlock-devel
Summary:        Include development libraries and headers for dlock
Requires:       umdk-dlock-lib = %{version}
AutoReqProv:    on

%description dlock-devel
This package contains all necessary include files and libraries needed
to develop applications based on dlock.

%package dlock-example
Summary:        Executable examples of dlock
Requires:       umdk-dlock-lib = %{version}
AutoReqProv:    on

%description dlock-example
This package contains all the executable examples of dlock.

%files dlock-example
%defattr(-,root,root)
    %{_bindir}/dlock_primary_test
    %{_bindir}/dlock_client_test
    %{_bindir}/dlock_client_object_test
%endif

%if %{build_all} || %{with urpc}
%package urpc-framework
Summary:        URPC framework shared library
Requires:       umdk-urma-lib
%description urpc-framework
This package contains the URPC framework shared libraries (e.g. liburpc.so).

%package urpc-umq
Summary:        URPC umq shared library
Requires:       umdk-urma-lib
%description urpc-umq
This package contains the URPC umq shared libraries (e.g. libumq.so).

%package urpc-framework-devel
Summary:        URPC framework development headers
Requires:       umdk-urpc-framework = %{version}
AutoReqProv:    on
%description urpc-framework-devel
This package contains all necessary headers for URPC framework development.

%package urpc-umq-devel
Summary:        UMQ development headers
Requires:       umdk-urpc-umq = %{version}
AutoReqProv:    on
%description urpc-umq-devel
This package contains all necessary headers for UMQ development.

%package urpc-framework-example
Summary:        URPC framework example
Requires:       umdk-urma-lib umdk-urpc-framework-devel = %{version}
AutoReqProv:    on
%description urpc-framework-example
This package contains example for URPC framework.

%package urpc-umq-example
Summary:        UMQ example
Requires:       umdk-urma-lib umdk-urpc-umq-devel = %{version}
AutoReqProv:    on
%description urpc-umq-example
This package contains example for URPC umq.

%package urpc-framework-tools
Summary:        URPC framework tools
Requires:       umdk-urma-lib umdk-urpc-framework-devel = %{version}
AutoReqProv:    on
%description urpc-framework-tools
This package contains urpc_admin and related URPC framework tools.

%package urpc-umq-tools
Summary:        UMQ tools
Requires:       umdk-urma-lib umdk-urpc-umq-devel = %{version}
AutoReqProv:    on
%description urpc-umq-tools
This package contains umq_perftest and related UMQ tools.
%endif

%if %{build_all} || %{with ums}
%package ums
Summary:        kmod file of ums
BuildRequires:  glib2-devel, libnl3-devel
Requires:       glib2, libnl3
%description ums
kmod file of ums

%package ums-tools
Summary:        tools of ums
%description ums-tools
tools of ums, contains ums_run
%endif

%if "%{build_all}" == "0"
    %global debug_package %{nil}
%endif

%prep
%setup -c -n %{name}-%{version}

%build
    cmake ./src/ -DCMAKE_INSTALL_PREFIX=/usr\
    -DBUILD_DATE=%{rpm_build_date} \
%if %{with asan}
    -DASAN="enable" \
%endif
%if %{with tsan}
    -DTSAN="enable" \
%endif
%if %{with gcov}
    -DCODE_COVERAGE="enable" \
%endif
%if %{with release_enable}
    -DRELEASE_ENABLE="enable" \
%endif
%if %{with test}
    -DURMA_TEST="enable" \
    -DRELEASE_ENABLE="disable" \
%endif
%if %{defined kernel_version}
    -DKERNEL_RELEASE=%{kernel_version} \
    -DKERNEL_PATH=%{kernel_build_path} \
%endif
%if %{without ubagg_disable}
    -DUB_AGG="enable" \
%endif
%if %{with dfx_tool}
    -DDFX_TOOL="enable" \
%endif
%if %{build_all}
    -DBUILD_ALL="enable" \
%else
    -DBUILD_ALL="disable" \
%endif
%if %{build_all} || %{with urma} || %{with urpc}
    -DBUILD_URMA="enable" \
%else
    -DBUILD_URMA="disable" \
%endif
%if %{with ums}
    -DBUILD_UMS="enable" \
%endif
%if %{build_all} || %{with urpc}
    -DBUILD_URPC="enable" \
%else
    -DBUILD_URPC="disable" \
%endif
%if %{with dlock}
    -DBUILD_DLOCK="enable" \
%endif
%if %{without udma_stb64_disable}
    -DUDMA_ST64B="enable" \
%endif

make %{?_smp_mflags}

%install
%{__rm} -rf %{buildroot}
make install DESTDIR=%{buildroot}

%if %{with gcov}
    mkdir -p %{buildroot}/var/lib/umdk/gcov/%{name}
    find %{_builddir} -name '*.gcno' -exec cp --parents {} %{buildroot}/var/lib/umdk/gcov/%{name} \;
%endif

%clean
%{__rm} -rf %{buildroot}

%if %{build_all} || %{with urma} || %{with urpc}
%files urma-lib
%defattr(-,root,root)
    %{_libdir}/liburma.so.*
    %{_libdir}/liburma_common.so.*
    %{_libdir}/urma/liburma_ubagg.so.*
    %{_libdir}/urma/liburma-udma.so
    /etc/rsyslog.d/urma.conf
    /etc/logrotate.d/urma

%post urma-lib
if [ -x %{_bindir}/systemctl ] && [ -x %{_sbindir}/rsyslogd ]; then
    %{_bindir}/systemctl restart rsyslog >/dev/null  2>&1
fi

%files urma-devel
%defattr(-,root,root)
    %{_libdir}/liburma.so
    %{_libdir}/liburma_common.so
    %{_libdir}/urma/liburma_ubagg.so
    %{_libdir}/urma/liburma-udma.so
    %dir %{_includedir}/ub/umdk/urma
    %dir %{_includedir}/ub/umdk/urma/udma
    %{_includedir}/ub/umdk/urma/urma_*.h
    %{_includedir}/ub/umdk/urma/uvs_types.h
    %{_includedir}/ub/umdk/urma/uvs_api.h
    %{_includedir}/ub/umdk/urma/udma/udma_u_ctl.h
%if %{with gcov}
    %dir /var/lib/ub/umdk/urma/gcov/%{name}
    /var/lib/ub/umdk/urma/gcov/%{name}/
%endif

%files urma-tools
%defattr(-,root,root)
    %{_bindir}/urma_admin
    /etc/rsyslog.d/urma_admin.conf
    %{_bindir}/urma_perftest
    %{_bindir}/ubagg_cli

%post urma-tools
if [ -x %{_bindir}/systemctl ] && [ -x %{_sbindir}/rsyslogd ]; then
    %{_bindir}/systemctl restart rsyslog >/dev/null  2>&1
fi

%files urma-bin
%defattr(-,root,root)
    /etc/rsyslog.d/tpsa.conf
    /etc/logrotate.d/tpsa
    %{_libdir}/libtpsa.so
    %{_libdir}/libtpsa.so.*
%post urma-bin
if [ -x %{_bindir}/systemctl ]; then
    %{_bindir}/systemctl daemon-reload >/dev/null  2>&1
fi
if [ -x %{_bindir}/systemctl ] && [ -x %{_sbindir}/rsyslogd ]; then
    %{_bindir}/systemctl restart rsyslog >/dev/null  2>&1
fi

%files urma-example
%defattr(-,root,root)
    %{_bindir}/urma_sample
    %dir %{_docdir}/umdk-examples
    %dir %{_docdir}/umdk-examples/urma_example
    %{_docdir}/umdk-examples/urma_example/README.md
%endif

%if %{build_all} || %{with urpc}
%files urpc-framework
%defattr(-,root,root)
    %{_libdir}/liburpc_framework.so.*
    /etc/rsyslog.d/urpc_framework.conf
    /etc/logrotate.d/urpc_framework

%files urpc-umq
%defattr(-,root,root)
    %{_libdir}/libumq.so.*
    %{_libdir}/libumq_buf.so.*
    %{_libdir}/libumq_ub.so.*
    %{_libdir}/libumq_ipc.so.*
    /etc/rsyslog.d/umq.conf
    /etc/logrotate.d/umq

%files urpc-framework-devel
%defattr(-,root,root)
    %{_libdir}/liburpc_framework.so
    %dir %{_includedir}/ub
    %dir %{_includedir}/ub/umdk
    %dir %{_includedir}/ub/umdk/urpc
    %{_includedir}/ub/umdk/urpc/urpc_framework_api.h
    %{_includedir}/ub/umdk/urpc/urpc_framework_types.h
    %{_includedir}/ub/umdk/urpc/urpc_framework_errno.h

%files urpc-umq-devel
%defattr(-,root,root)
    %{_libdir}/libumq.so
    %{_libdir}/libumq_buf.so
    %{_libdir}/libumq_ub.so
    %{_libdir}/libumq_ipc.so
    %dir %{_includedir}/ub
    %dir %{_includedir}/ub/umdk
    %dir %{_includedir}/ub/umdk/urpc
    %dir %{_includedir}/ub/umdk/urpc/umq
    %{_includedir}/ub/umdk/urpc/umq/umq_api.h
    %{_includedir}/ub/umdk/urpc/umq/umq_errno.h
    %{_includedir}/ub/umdk/urpc/umq/umq_pro_api.h
    %{_includedir}/ub/umdk/urpc/umq/umq_pro_types.h
    %{_includedir}/ub/umdk/urpc/umq/umq_types.h

%files urpc-framework-example
%defattr(-,root,root)
    %{_bindir}/urpc_framework_example
    %dir %{_docdir}/umdk-examples/urpc_example/urpc_framework_example

%files urpc-umq-example
%defattr(-,root,root)
    %{_bindir}/umq_example
    %dir %{_docdir}/umdk-examples/urpc_example/umq_example

%files urpc-framework-tools
%defattr(-,root,root)
    %{_bindir}/urpc_admin
    %{_bindir}/urpc_framework_perftest

%files urpc-umq-tools
%defattr(-,root,root)
    %{_bindir}/umq_perftest
%endif

%if %{build_all} || %{with dlock}
%files dlock-lib
%defattr(-,root,root)
    %{_libdir}/libdlockm.so.*
    %{_libdir}/libdlocks.so.*
    %{_libdir}/libdlockc.so.*

%files dlock-devel
%defattr(-,root,root)
    %{_libdir}/libdlockm.so
    %{_libdir}/libdlocks.so
    %{_libdir}/libdlockc.so
    %dir %{_includedir}/ub
    %dir %{_includedir}/ub/umdk
    %dir %{_includedir}/ub/umdk/ulock
    %dir %{_includedir}/ub/umdk/ulock/dlock
    %{_includedir}/ub/umdk/ulock/dlock/dlock_client_api.h
    %{_includedir}/ub/umdk/ulock/dlock/dlock_types.h
    %{_includedir}/ub/umdk/ulock/dlock/dlock_server_api.h
%endif

%if %{build_all} || %{with ums}
%files ums
%defattr(-,root,root)
    %dir /lib/modules/%{kernel_version}/extra/ums/
    /lib/modules/%{kernel_version}/extra/ums/ums.ko
    /etc/modules-load.d/ums.conf

%post ums
if [ -d /lib/modules/$(uname -r)/kernel/net/smc ]; then
    %{__rm} -rf /lib/modules/$(uname -r)/kernel/net/smc
fi
if [[ %{kernel_version} != $(uname -r) ]]; then
    %dir /lib/modules/$(uname -r)/weak-updates/drivers/ums/
    echo "/lib/modules/%{kernel_version}/extra/ums/ums.ko" | /sbin/weak-modules --add-module --no-initramfs --verbose
fi

echo "omit_drivers+=\" ums \"" > /etc/dracut.conf.d/ums.conf

/sbin/depmod -a $(uname -r)

%postun ums
if [ $1 -eq 0 ]; then
    if [[ %{kernel_version} != $(uname -r) ]]; then
        if [ -d /lib/modules/$(uname -r)/weak-updates/drivers ]; then
                %{__rm} -rf /lib/modules/$(uname -r)/weak-updates/drivers/ums/ums.ko
                %{__rm} -rf /lib/modules/$(uname -r)/weak-updates/drivers/ums/
            else
                %{__rm} -rf /lib/modules/$(uname -r)/weak-updates/ums/ums.ko
                %{__rm} -rf /lib/modules/$(uname -r)/weak-updates/ums/
        fi
    fi
fi
/sbin/depmod -a $(uname -r)

%files ums-tools
%defattr(-,root,root)
    /usr/lib/libums-preload.so
    /usr/bin/ums_run

%post ums-tools

%postun ums-tools
if [ $1 -eq 0 ]; then
    [ -f /usr/lib/libums-preload.so ] && %{__rm} -f /usr/lib/libums-preload.so || :
    [ -f /usr/bin/ums_run ] && %{__rm} -f /usr/bin/ums_run || :
fi
%endif

%changelog
* Tue Dec 30 2025 umdk
-Initial UMDK-25.12.0 rpm spec file.
