#!/bin/sh

export source=$1
export version=$(grep '^\#[ \t]*define[ \t]\+NMAP_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
export title="nmap-${version}"
export size=50000
export backgroundPictureName="nmap.png"
export finalDMGName="${title}.dmg"
export applicationName="${title}.mpkg"
NB_FILES=7

rm -rf ${source}/.background/${backgroundPictureName}
rm -rf ${source}/.background/
rm -rf pack.temp.dmg
rm -rf ${title}.dmg
rm -rf ${source}/Applications

# Copy the background image to the background of the image disk
mkdir ${source}/.background/
cp ${backgroundPictureName} ${source}/.background/
ln -s /Applications ${source}/

# Ensure that we have no virtual disk currently mounted
hdiutil detach /Volumes/${title}/ 2> /dev/null

hdiutil create -srcfolder "${source}" -volname "${title}" -fs HFS+ -fsargs "-c c=64,a=16,e=16" -ov -format UDRW -size ${size}k pack.temp.dmg

# Mount the disk image and store the device name
export device=$(hdiutil attach -readwrite -noverify -noautoopen "pack.temp.dmg" | egrep '^/dev/' | sed 1q | awk '{print $1}')

# Try to list files in the Volume, if we can't, its because its not ready yet
# so we should sleep while its mounted before trying to design it with Applescript
stop=false
while [ "$stop" = false ]; do
    test=`ls -l /Volumes/${title}/ | wc -l`
    if [ "$test" -eq $NB_FILES ]; then
        stop=true
    fi
    sleep 1
done

# Applescript: design the virtual disk image we just mounted
echo '
	tell application "Finder"
		tell disk "'${title}'"
			open

			set current view of container window to icon view
			set toolbar visible of container window to false
			set statusbar visible of container window to false
			set the bounds of container window to {100, 100, 1000, 660}
			set theViewOptions to the icon view options of container window
			set icon size of theViewOptions to '${ICON_SIZE}'
			set text size of theViewOptions to '${FONT_SIZE}'
			set arrangement of theViewOptions to not arranged
			set background picture of theViewOptions to file ".background:'${backgroundPictureName}'"
			
			set position of item "'${applicationName}'" of container window to {'${MPKG_POS_X}', '${MPKG_POS_Y}'}
			set position of item "Applications" of container window to {'${APPS_POS_X}', '${APPS_POS_Y}'}
			set position of item "'$2'" of container window to {'${README_POS_X}', '${README_POS_Y}'}
			set position of item "'$3'" of container window to {'${COPYING_POS_X}', '${COPYING_POS_Y}'}
			set position of item "'$4'" of container window to {'${THIRD_P_POS_X}', '${THIRD_P_POS_Y}'}
			set position of item "'$5'" of container window to {'${LICENSES_POS_X}', '${LICENSES_POS_Y}'}
			
			update without registering applications

			close
		end tell
	end tell
' | osascript

hdiutil detach ${device}
hdiutil convert "pack.temp.dmg" -format UDZO -imagekey zlib-level=9 -o "${finalDMGName}"
rm -f pack.temp.dmg
