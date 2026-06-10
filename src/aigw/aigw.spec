# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

%if %{undefined rpm_version}
    %define rpm_version 1.0.0
%endif

%if %{undefined rpm_release}
    %define rpm_release B001
%endif

%if %{undefined commit_id}
    %define commit_id (none)
%endif

%define default_user_name aigw
%define default_group_name aigw

Name:aigw
Summary:AIGW package
Version:%{rpm_version}
Release:%{rpm_release}
Group: TongTu
Provides: Huawei Technologies Co., Ltd
Vendor: Huawei Technologies Co., Ltd
License: Proprietary
Source: %{name}-%{version}-%{release}.tar.gz
BuildRoot: %{_buildirootdir}/%{name}-%{version}-%{release}
%description
AIGW is a reasoning gateway that provides multiple scheduling algorithms and high-performance communication capabilities.

BuildRequires: gcc g++ cmake>=3.28.2 make go>=1.24.1 rustc>=1.89.0
Commit_id   : %{commit_id}

%package lib
Summary: AIGW library package
Group: TongTu

%description lib
AIGW shared library and header files for development.

%prep
%setup -c -n %{name}-%{version}-%{release}

%build
chmod a+x build.sh
bash build.sh --notest

%define bin_dir /usr/local/bin
%define log_dir /var/log/aigw
%define conf_root_dir /etc/aigw
%define conf_dir %{conf_root_dir}/conf
%install
rm -rf %{buildroot}
install -p -D -m 550 output/aigw/aigw %{buildroot}/%{bin_dir}/aigw
install -p -D -m 640 configs/aigw.json %{buildroot}/%{conf_dir}/aigw.json
install -p -D -m 550 output/aigw/libaigw.so %{buildroot}/%{_libdir}/libaigw.so
install -p -D -m 640 output/aigw/aigw.h %{buildroot}/%{_includedir}/aigw/aigw.h

%clean
rm -rf %{buildroot}

%pre
if [ -z "$CUSTOM_GROUP" ] || [ -z "$CUSTOM_USER" ]; then
  #add user and group
  getent group %default_group_name > /dev/null
  if [  $? -ne 0 ];then
      /usr/sbin/groupadd %default_group_name > /dev/null
  fi
  getent passwd %default_user_name > /dev/null
  if [  $? -ne 0 ];then
      /usr/sbin/useradd -g %default_group_name -M -s /sbin/nologin %default_user_name 2> /dev/null
      chage -M 99999 %default_user_name
  else
      groups %default_user_name | awk -F ':' '{print $2}' | sed -e 's/^[ ]*//g' | grep %default_group_name > /dev/null
      if [ $? -ne 0 ];then
          echo "user '%default_user_name' must belong to group '%default_group_name'"
          exit 1
      fi
  fi
fi

%post
chmod 750 %{conf_root_dir}
chmod 750 %{conf_dir}
chmod 640 %{conf_dir}/aigw.json
mkdir -p %{log_dir}
chmod 750 %{log_dir}
if [ -z "$CUSTOM_GROUP" ] || [ -z "$CUSTOM_USER" ]; then
  chown %{default_user_name}:%{default_group_name} %{bin_dir}/aigw
  chown -R %{default_user_name}:%{default_group_name} %{conf_root_dir}
  chown -R %{default_user_name}:%{default_group_name} %{log_dir}
else
  chown $CUSTOM_USER:$CUSTOM_GROUP %{bin_dir}/aigw
  chown -R $CUSTOM_USER:$CUSTOM_GROUP %{conf_root_dir}
  chown -R $CUSTOM_USER:$CUSTOM_GROUP %{log_dir}
fi

%post lib
chmod 550 %{_libdir}/libaigw.so
chmod 550 %{_includedir}/aigw
chmod 640 %{_includedir}/aigw/aigw.h
/sbin/ldconfig

%postun lib
/sbin/ldconfig

%files lib
%{_libdir}/libaigw.so
%dir %attr(750, root, root) %{_includedir}/aigw
%{_includedir}/aigw/aigw.h

%files
%attr(550, %{default_user_name}, %{default_group_name}) %{bin_dir}/aigw
%{bin_dir}/*
%config(noreplace) %attr(640, %{default_user_name}, %{default_group_name}) %{conf_dir}/aigw.json