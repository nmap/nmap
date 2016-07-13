#!/bin/sh

export version=$(grep '^\#[ \t]*define[ \t]\+NMAP_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
export title="nmap-${version}"
export disk="/Volumes/${title}"
export backgroundPictureName="nmap.png"
export finalDMGName="${title}.dmg"
export applicationName="${title}.mpkg"
RES="True"

hdiutil attach ${finalDMGName}

echo "\nDisk: ${disk}"
echo "\nChecking positions..."

export MPKG=`echo '
	tell application "Finder"
		set f to POSIX file "'${disk}'/'${applicationName}'" as alias
		get properties of f
	end tell
' | osascript | grep -o 'position:[0-9]*, [0-9]*' | awk -F':' '{ print $2 }'`

export APP_FOLDER=`echo '
	tell application "Finder"
		set f to POSIX file "'${disk}'/Applications" as alias
		get properties of f
	end tell
' | osascript | grep -o 'position:[0-9]*, [0-9]*' | awk -F':' '{ print $2 }'`

export README=`echo '
	tell application "Finder"
		set f to POSIX file "'${disk}'/README.md" as alias
		get properties of f
	end tell
' | osascript | grep -o 'position:[0-9]*, [0-9]*' | awk -F':' '{ print $2 }'`

export COPYING=`echo '
	tell application "Finder"
		set f to POSIX file "'${disk}'/COPYING" as alias
		get properties of f
	end tell
' | osascript | grep -o 'position:[0-9]*, [0-9]*' | awk -F':' '{ print $2 }'`

export LICENSES_3RD=`echo '
	tell application "Finder"
		set f to POSIX file "'${disk}'/3rd-party-licenses.txt" as alias
		get properties of f
	end tell
' | osascript | grep -o 'position:[0-9]*, [0-9]*' | awk -F':' '{ print $2 }'`

export LICENSES=`echo '
	tell application "Finder"
		set f to POSIX file "'${disk}'/licenses" as alias
		get properties of f
	end tell
' | osascript | grep -o 'position:[0-9]*, [0-9]*' | awk -F':' '{ print $2 }'`

if [ "$MPKG" = "110, 170" ]; then 
    echo "${applicationName}: OK"
else
    echo "${applicationName}: Wrong"
    RES="False"
fi;

if [ "$APP_FOLDER" = "70, 40" ]; then 
    echo "Applications: OK"
else
    echo "Applications: Wrong"
    RES="False"
fi;

if [ "$README" = "802, 180" ]; then 
    echo "README.md: OK"
else
    echo "README.md: Wrong"
    RES="False"
fi;

if [ "$COPYING" = "802, 310" ]; then 
    echo "COPYING: OK"
else
    echo "COPYING: Wrong"
    RES="False"
fi;

if [ "$LICENSES_3RD" = "802, 440" ]; then 
    echo "3rd-party-licenses.txt: OK"
else
    echo "3rd-party-licenses.txt: Wrong"
    RES="False"
fi;

if [ "$LICENSES" = "670, 60" ]; then 
    echo "licenses: OK"
else
    echo "licenses: Wrong"
    RES="False"
fi;

export BG=`echo '
	tell application "Finder"
		set f to POSIX file "'${disk}'/.background/'${backgroundPictureName}'" as alias
		if exists file f then
            return true
        else
            return false
        end if
	end tell
' | osascript`

if [ "$BG" = "true" ]; then 
    echo "\nBackground exists: Yes\n"
else
    echo "\nBackground exists: No\n"
    RES="False"
fi;

hdiutil detach ${disk}

if [ "$RES" = "True" ]; then 
    echo "\nTest passed?: Yes\n"
    exit 0
else
    echo "\nTest passed?: No\nThey are some errors that should be corrected\n"
    exit 1
fi;
