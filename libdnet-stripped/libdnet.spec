Summary:       Simple portable interface to lowlevel networking routines
Name:          libdnet
Version:       1.18.0
Release:       1%{?dist}
License:       BSD
URL:           https://github.com/ofalk/%{name}
Source:        https://github.com/ofalk/%{master}/archive/%{name}-%{version}.tar.gz

BuildRequires: gcc-c++
BuildRequires: make
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: libtool
BuildRequires: python3-Cython

%description
libdnet provides a simplified, portable interface to several
low-level networking routines, including network address
manipulation, kernel arp(4) cache and route(4) table lookup and
manipulation, network firewalling (IP filter, ipfw, ipchains,
pf, ...), network interface lookup and manipulation, raw IP
packet and Ethernet frame, and data transmission.

%package devel
Summary:       Header files for libdnet library
Requires:      %{name}%{?_isa} = %{version}-%{release}

%description devel
%{summary}.

%package progs
Summary:       Sample applications to use with libdnet
Requires:      %{name}%{?_isa} = %{version}-%{release}

%description progs
%{summary}.

%package -n python%{python3_pkgversion}-libdnet
%{?python_provide:%python_provide python%{python3_pkgversion}-libdnet}
# Remove before F30
Provides:      %{name}-python = %{version}-%{release}
Provides:      %{name}-python%{?_isa} = %{version}-%{release}
Obsoletes:     %{name}-python < %{version}-%{release}
Summary:       Python bindings for libdnet
Requires:      %{name}%{?_isa} = %{version}-%{release}
BuildRequires: python%{python3_pkgversion}-devel

%description -n python%{python3_pkgversion}-libdnet
%{summary}.

%prep
%setup -q -n %{name}-%{version}

%build
autoreconf -i
export CFLAGS="$RPM_OPT_FLAGS -fno-strict-aliasing"
%configure --disable-static --with-python
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool
%make_build

%install
export PYTHONPATH=$RPM_BUILD_ROOT/%{python3_sitearch}
%make_install

pushd python
%{__python3} setup.py install --skip-build --root $RPM_BUILD_ROOT
popd

%ldconfig_scriptlets

%files
%license LICENSE
%doc THANKS TODO
%{_libdir}/*.so.*

%files devel
%{_bindir}/*
%{_libdir}/*.so
%{_libdir}/*.la
%{_includedir}/*
%{_mandir}/man3/*.3*

%files progs
%{_sbindir}/*
%{_mandir}/man8/*.8*

%files -n python%{python3_pkgversion}-libdnet
%{python3_sitearch}/*

%changelog
* Tue Feb 27 2024 Oliver Falk <oliver@linux-kernel.at> - 1.18.0-1
- Release 1.18.0

* Thu Oct 12 2023 Oliver Falk <oliver@linux-kernel.at> - 1.17.0-1
- Release 1.17.0

* Fri Apr 07 2023 Oliver Falk <oliver@linux-kernel.at> - 1.16.4-1
- Release 1.16.4

* Wed Jan 11 2023 Oliver Falk <oliver@linux-kernel.at> - 1.16.3-1
- Release 1.16.3

* Tue Jan 03 2023 Oliver Falk <oliver@linux-kernel.at> - 1.16.2-1
- Release 1.16.2

* Mon May 02 2022 Oliver Falk <oliver@linux-kernel.at> - 1.16.1-1
- Release 1.16.1

# vim:ts=4:
