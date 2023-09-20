
%if %{defined kernel_version}
    %define kernel_build_path /lib/modules/%{kernel_version}/build
%else
    %define kernel_version %(uname -r)
    %define kernel_build_path /lib/modules/%{kernel_version}/build
%endif
%define kernel_requires_version %(echo %{kernel_version} | awk -F"." 'OFS="."{$NF="";print}' | sed 's/\.$//g')

%if %{undefined rpm_version}
    %define rpm_version 1.3.0
%endif

%if %{undefined rpm_release}
    %define rpm_release B001
%endif

Name          : umdk-urma
Summary       : Unified memory development kit
Version       : %{rpm_version}
Release       : %{rpm_release}
Group         : nStack
License       : Proprietary
Provides      : Huawei Technologies Co., Ltd
Source0       : %{name}-%{version}.tar.gz
BuildRoot     : %{_buildirootdir}/%{name}-%{version}-build
buildArch     : x86_64 aarch64

BuildRequires : rpm-build, make, cmake, gcc, gcc-c++, glibc-devel
BuildRequires : glib2-devel
Requires: glibc, glib2
%if %{with asan}
Requires: libasan
%endif

%description
A new system interconnect architecture

%package lib
Summary:        Basic URMA libraries of UMDK

%description lib
This package contains basic URMA libraries of UMDK, such as liburma.so.

%package devel
Summary:        Include Files and Libraries mandatory for URMA
Requires:       umdk-urma-lib = %{version}
AutoReqProv:    on

%description devel
This package contains all necessary include files and libraries needed
to develop applications that require the provided includes and
libraries.

%prep
%setup -c -n %{name}-%{version}

%build
    cmake ./ -DCMAKE_INSTALL_PREFIX=/usr \
%if %{defined kernel_version}
    -DKERNEL_RELEASE=%{kernel_version} \
    -DKERNEL_PATH=%{kernel_build_path} \
%endif

make %{?_smp_mflags}

%install
%{__rm} -rf %{buildroot}
make install DESTDIR=%{buildroot}

%clean
%{__rm} -rf %{buildroot}

%files lib
%defattr(-,root,root)
    %{_libdir}/liburma.so
    %{_libdir}/liburma.so.0
    %{_libdir}/liburma.so.0.0.1
    %{_libdir}/liburma_common.so
    %{_libdir}/liburma_common.so.0
    %{_libdir}/liburma_common.so.0.0.1
    /etc/rsyslog.d/urma.conf
    /etc/logrotate.d/urma

%post lib
if [ -x %{_bindir}/systemctl ] && [ -x %{_sbindir}/rsyslogd ]; then
    %{_bindir}/systemctl restart rsyslog >/dev/null  2>&1
fi

%files devel
%defattr(-,root,root)
    %dir %{_includedir}/umdk
    %dir %{_includedir}/umdk/common
    %{_includedir}/umdk/urma_*.h
    %{_includedir}/umdk/ub_errno.h
    %{_includedir}/umdk/urma_provider.h
    %{_includedir}/umdk/common/ub_*.h
    %{_includedir}/umdk/common/urma_*.h
    %{_includedir}/umdk/common/compiler.h

%changelog
* Tue Sep 17 2021 huawei
-Change name and version form umdk-0.5 to umdk-1.0.0.

* Tue Jan 12 2021 huawei
-Change name and version form UBus-1.0 to umdk-0.5.

* Thu Nov 12 2020 huawei
-Rectify and reform the name of UBus rpm file.

* Fri Sep 11 2020 huawei
-Initial UBus-0.1 rpm spec file.
