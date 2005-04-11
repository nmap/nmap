@echo off

rem iphlpapi.def: fools lib into correctly generating iphlpapi.lib
rem Copyright (C) 2000  Andy Lutomirski

rem This library is free softwarerem  you can redistribute it and/or
rem modify it under the terms of the GNU Lesser General Public
rem License, version 2.1, as published by the Free Software
rem Foundation, with the exception that if this copy of the library
rem is distributed under the Lesser GNU Public License (as opposed
rem to the ordinary GPL), you may ignore section 6b, and that all
rem copies distributed without exercising section 3 must retain this
rem paragraph in its entirety.

rem This library is distributed in the hope that it will be useful,
rem but WITHOUT ANY WARRANTYrem  without even the implied warranty of
rem MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
rem Lesser General Public License for more details.

rem You should have received a copy of the GNU Lesser General Public
rem License along with this libraryrem  if not, write to the Free Software
rem Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

echo Rebuilding iphlpapi.lib...
cl /c /Zl /nologo iphlpapi.c
lib /nologo /def:iphlpapi.def iphlpapi.obj
del iphlpapi.obj iphlpapi.exp

rem Clean up after VC
if exist debug rd debug
if exist release rd release

echo Done.
