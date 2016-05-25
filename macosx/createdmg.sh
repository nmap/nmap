#!/bin/sh

export source=$1
export version=$(grep '^\#[ \t]*define[ \t]\+NMAP_VERSION' ../nmap.h | sed -e 's/.*"\(.*\)".*/\1/' -e 'q')
export title="nmap-${version}"
export size=30000
export backgroundPictureName="nmap.png"
export finalDMGName="${title}.dmg"
export applicationName="${title}.mpkg"

rm -rf ${source}/.background/${backgroundPictureName}
rm -rf ${source}/.background/
rm -rf pack.temp.dmg
rm -rf ${title}.dmg
rm -rf ${source}/Applications

# Copy the background image to the background of the image disk
mkdir ${source}/.background/
cp ${backgroundPictureName} ${source}/.background/
ln -s /Applications ${source}/

hdiutil create -srcfolder "${source}" -volname "${title}" -fs HFS+ -fsargs "-c c=64,a=16,e=16" -ov -format UDRW -size ${size}k pack.temp.dmg

# Mount the disk image and store the device name
export device=$(hdiutil attach -readwrite -noverify -noautoopen "pack.temp.dmg" | egrep '^/dev/' | sed 1q | awk '{print $1}')

echo '
	tell application "Finder"
		tell disk "'${title}'"
			open

			set current view of container window to icon view
			set toolbar visible of container window to false
			set statusbar visible of container window to false
			set the bounds of container window to {100, 100, 1000, 660}
			set theViewOptions to the icon view options of container window
			set icon size of theViewOptions to 88
			set text size of theViewOptions to 13
			set arrangement of theViewOptions to not arranged
			set background picture of theViewOptions to file ".background:'${backgroundPictureName}'"
			
			set position of item "'${applicationName}'" of container window to {110, 170}
			set position of item "Applications" of container window to {110, 310}
			set position of item "README" of container window to {802, 180}
			set position of item "COPYING" of container window to {802, 310}
			set position of item "3rd-party-licenses.txt" of container window to {802, 440}
			set position of item "licenses" of container window to {670, 60}
			
			update without registering applications

			close
		end tell
	end tell
' | osascript

hdiutil detach ${device}
hdiutil convert "pack.temp.dmg" -format UDZO -imagekey zlib-level=9 -o "${finalDMGName}"
rm -f pack.temp.dmg
