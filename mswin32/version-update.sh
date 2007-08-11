#!/bin/sh

#-------------------------------------------#
# Nmap windows build version update script  #
#					    #
# From the version in nmap.h this script    #
# updates both nmap.rc and nmap.nsi which   #
# in turn updates nmap.exe and 		    #
# nmapinstall.exe			    #
#                                           #
#-------------------------------------------#

# Eddie Bell <ejlbell@gmail.com> 2007

NMAP_RC="./nmap.rc"
NMAP_NSIS="./nsis/Nmap.nsi"
NMAP_TMP="./.nmap-version.tmp"

# make sure all the files we need
# are available

if [ -z $1 ] || [ -z $2 ]
 then
	echo "$0 <str-version> <#-version>"
	exit 1
fi

NMAP_VERSION=$1
NMAP_NUM_VERSION=$2

if [ ! -f $NMAP_RC ]
 then
 	echo "Cannot access $NMAP_RC"
	exit 1
fi

if [ ! -f $NMAP_NSIS ]
 then
	echo "Cannot access $NMAP_NSIS"
	exit 1
fi

: > $NMAP_TMP

# make the substitutions for nmap.rc
# Note we have to do it this strange way using head and tail because
# bash's 'read' automatically removes whitespace which messes up the
# files indentation

i=1
max=`wc -l $NMAP_RC | awk '{print $1}'`
echo "$0: updating $NMAP_RC ($max)"

while :
  do
	line=`head -n $i $NMAP_RC | tail -n 1`
	i=`expr $i + 1`

	if [ -n "`echo $line | grep 'VALUE "FileVersion"'`" ]
        then
		echo "            VALUE \"FileVersion\", \"$NMAP_VERSION\\0\"" >> $NMAP_TMP
	elif [ -n "`echo $line | grep 'FILEVERSION'`" ]
	then
		echo "FILEVERSION `echo $NMAP_NUM_VERSION | tr '.' ','`"  >> $NMAP_TMP
	else
		echo "$line" >> $NMAP_TMP
	fi

	if [ $i -gt $max ]  
	then
		break
	fi
done

mv $NMAP_TMP $NMAP_RC
touch $NMAP_TMP


# make the substitutions for Nmap.nsi

i=1
max=`wc -l $NMAP_NSIS | awk '{print $1}'`
echo "$0: updating $NMAP_NSIS ($max)"

while :
  do
	line=`head -n $i $NMAP_NSIS | tail -n 1`
	i=`expr $i + 1`

	if [ -n "`echo $line | grep 'VIProductVersion'`" ]
        then
		echo "  VIProductVersion \"$NMAP_NUM_VERSION\""  >> $NMAP_TMP
	elif [ -n "`echo $line | grep 'VIAddVersionKey /LANG=1033 "FileVersion"'`" ]
	then
		echo "  VIAddVersionKey /LANG=1033 \"FileVersion\" \"$NMAP_VERSION\"" >> $NMAP_TMP
	else
		echo "$line"  >> $NMAP_TMP
	fi

	if [ $i -gt $max ]  
	then
		break
	fi
done

mv $NMAP_TMP $NMAP_NSIS
echo "$0: set nmap.rc and nmap.nsi to $NMAP_VERSION ($NMAP_NUM_VERSION)"
exit 0
