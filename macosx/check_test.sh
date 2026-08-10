#!/bin/sh -e

test -n "${NMAP_VERSION}" || exit 1
export title="nmap-${NMAP_VERSION}"
export disk="/Volumes/${title}"
export backgroundPictureName="nmap.png"
export finalDMGName="${title}.dmg"
export applicationName="${title}.mpkg"
RES="True"
NB_FILES=7

hdiutil attach ${finalDMGName}

# Try to list files in the Volume, if we can't, its because its not ready yet
# so we should sleep while its mounted before trying to check if everything is ok
stop=false
while [ "$stop" = false ]; do
    test=`ls -l /Volumes/${title}/ | wc -l`
    if [ "$test" -eq $NB_FILES ]; then
        stop=true
    fi
    sleep 1
done

echo "\nDisk: ${disk}"
echo "Checking positions...\n"

export MPKG=`echo '
    tell application "Finder"
        set f to POSIX file "'${disk}'/'${applicationName}'" as alias
        get properties of f
    end tell
' | osascript | grep -o 'position:[0-9]*, [0-9]*' | awk -F':' '{ print $2 }'`

export README=`echo '
    tell application "Finder"
        set f to POSIX file "'${disk}'/'$1'" as alias
        get properties of f
    end tell
' | osascript | grep -o 'position:[0-9]*, [0-9]*' | awk -F':' '{ print $2 }'`

export LICENSE=`echo '
    tell application "Finder"
        set f to POSIX file "'${disk}'/'$2'" as alias
        get properties of f
    end tell
' | osascript | grep -o 'position:[0-9]*, [0-9]*' | awk -F':' '{ print $2 }'`

export LICENSES_3RD=`echo '
    tell application "Finder"
        set f to POSIX file "'${disk}'/'$3'" as alias
        get properties of f
    end tell
' | osascript | grep -o 'position:[0-9]*, [0-9]*' | awk -F':' '{ print $2 }'`

export LICENSES=`echo '
    tell application "Finder"
        set f to POSIX file "'${disk}'/'$4'" as alias
        get properties of f
    end tell
' | osascript | grep -o 'position:[0-9]*, [0-9]*' | awk -F':' '{ print $2 }'`

if [ "$MPKG" = "$MPKG_POS_X, $MPKG_POS_Y" ]; then 
    echo "${applicationName}: OK"
else
    echo "${applicationName}: Wrong"
    RES="False"
fi;

if [ "$README" = "$README_POS_X, $README_POS_Y" ]; then 
    echo "README.md: OK"
else
    echo "README.md: Wrong"
    RES="False"
fi;

if [ "$LICENSE" = "$LICENSE_POS_X, $LICENSE_POS_Y" ]; then 
    echo "LICENSE: OK"
else
    echo "LICENSE: Wrong"
    RES="False"
fi;

if [ "$LICENSES_3RD" = "$THIRD_P_POS_X, $THIRD_P_POS_Y" ]; then 
    echo "3rd-party-licenses.txt: OK"
else
    echo "3rd-party-licenses.txt: Wrong"
    RES="False"
fi;

if [ "$LICENSES" = "$LICENSES_POS_X, $LICENSES_POS_Y" ]; then 
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
    echo "\nTest passed?: No\nThere are some errors that should be corrected\n"
    exit 1
fi;
