#!/bin/sh

echo "    <background file=\"$2\" mime-type=\"image/jpg\"/>" >> finalDist.xml

nb_lines=$(wc -l distribution.xml)
nb=$(echo $nb_lines | awk '{print $1}')

tail -n $(($nb - 2)) distribution.xml >> finalDist.xml