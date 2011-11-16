%define         prerelease    BETA2

Name:           nping
Version:        0.1
Release:        0.1.%{prerelease}%{?dist}
Summary:        Network packet generation, response analysis and response time measurement

Group:          Applications/Internet
License:        GPLv2 with exceptions
URL:            http://nmap.org/nping/
Source0:        http://nmap.org/%{name}/dist/%{name}-%{version}%{prerelease}/%{name}-%{version}%{prerelease}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)


%description
Nping is an open source tool for network packet generation, response analysis
and response time measurement. Nping allows to generate network packets of a
wide range of protocols, letting users to tune virtually any field of the
protocol headers. While Nping can be used as a simple ping utility to detect
active hosts, it can also be used as a raw packet generator for network stack
stress tests, ARP poisoning, Denial of Service attacks, route tracing, etc. 


%prep
%setup -q -n %{name}-%{version}%{prerelease}
sed -i '/\$(STRIP)/d' Makefile.in
# Remove exec bit from source files
find | egrep "*\.[cc,h]" | xargs chmod a-x


%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc CHANGELOG
%{_bindir}/nping
%{_mandir}/man1/nping.1*


%changelog
* Thu Sep 24 2009 Steve 'Ashcrow' Milner <me@stevemilner.org> 0.1-0.1.BETA2
- Initial package
