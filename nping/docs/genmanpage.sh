#!/bin/sh


echo "[+] Generating nping -h output"
if [ -f ../nping ]
then
  ../nping -h > nping-usage.txt
else
  echo "../nping does not exist, using previous version of nping-usage.txt..."
fi


echo "[+] Done!"
echo "[+] Generating man page from nping-man.xml"
collateindex.pl -N -i idx -o genindex.sgm
xsltproc --stringparam doc.class man --xinclude --output ./nping.1 xsl/man.nroff.xsl npingmanhtml.xml
echo "[+] Done!"



