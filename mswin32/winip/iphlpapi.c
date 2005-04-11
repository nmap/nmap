/*

iphlpapi.c: fools lib into correctly generating iphlpapi.lib
Copyright (C) 2000  Andy Lutomirski

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License, version 2.1, as published by the Free Software
Foundation, with the exception that if this copy of the library
is distributed under the Lesser GNU Public License (as opposed
to the ordinary GPL), you may ignore section 6b, and that all
copies distributed without exercising section 3 must retain this
paragraph in its entirety.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

void __declspec(dllexport) __stdcall GetIpAddrTable(int p1, int p2, int p3) {}
void __declspec(dllexport) __stdcall GetIpForwardTable(int p1, int p2, int p3) {}
void __declspec(dllexport) __stdcall GetIfTable(int p1, int p2, int p3) {}
void __declspec(dllexport) __stdcall GetIpNetTable(int p1, int p2, int p3) {}
void __declspec(dllexport) __stdcall SendARP( int p1, int p2, int p3, int p4) {} 
