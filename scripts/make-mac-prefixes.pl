#!/usr/bin/perl -w
use POSIX;

# A simple perl script that takes a MAC address database as distribted
# by the IEEE at http://standards.ieee.org/regauth/oui/oui.txt and
# creates an nmap-mac-prefixes file, which is just a bunch of lines
# like this (but without the initial "# ":
#
# 000072 Miniware Technology
# 00012E PC Partner Ltd.
# 080023 Panasonic Communications Co., Ltd.
#

sub usage() {
 print "usage: make-mac-prefixis.pl [infile] [outfile]\n" .
       "where infile is usually oui.txt as distributed from\n" .
       "http://standards.ieee.org/regauth/oui/oui.txt and outfile is usually\n" .
       "nmap-mac-prefixes.  The output file will be overwritten if it already exists.\n";
 exit 1;
}

# Un-capitalize an all-caps company name;
sub decap($) {
    my $oldcomp = shift();
    my $newcomp = "";
    my @words = split /\s/, $oldcomp;
    foreach $word (@words) {
	if (length($word) > 3 && (length($word) > 5 or !($word =~ /[.,\!\$]/))) {
	    $word = "\L$word\E";
	    $word = "\u$word";
	}
	if ($newcomp) { $newcomp .= " $word"; }
	else {$newcomp = $word; }
    }
    
    return $newcomp;
}

# Rules to shorten the names a bit, such as eliminating Inc.
sub shorten($) {
    my $comp = shift();
    $comp =~ s/,.{1,6}$//;
    $comp =~ s/ (Corporation|Inc|Ltd|Corp|S\.A\.|Co\.|llc|pty|l\.l\.c\.|s\.p\.a\.|b\.v\.)(\.|\b)//gi;
    # Fix stupid entries like "DU PONT PIXEL SYSTEMS     ."
    $comp =~ s/\s+.$//;
    return $comp;
}

my $infile = shift() || usage();
my $outfile = shift() || usage();

if (! -f $infile) { print "ERROR: Could not find input file $infile"; usage(); }

open INFILE, "<$infile" or die "Could not open input file $infile";
open OUTFILE, ">$outfile" or die "Could not open output file $outfile";

print OUTFILE "# \$Id" . ": \$ generated with make-mac-prefixes.pl\n";
print OUTFILE "# Original data comes from http://standards.ieee.org/regauth/oui/oui.txt\n";
print OUTFILE "# These values are known as Organizationally Unique Identifiers (OUIs)\n";
print OUTFILE "# See http://standards.ieee.org/faqs/OUI.html\n";

while($ln = <INFILE>) {
    if ($ln =~ /\s*([0-9a-fA-F]{2})-([0-9a-fA-F]{2})-([0-9a-fA-F]{2})\s+\(hex\)\s+(\S.*)$/) { 
	my $prefix = "$1$2$3";
	my $compname= $4;
# This file often over-capitalizes company names
	if (!($compname =~ /[a-z]/) || $compname =~ /\b[A-Z]{4,}/) {
	    $compname = decap($compname);
	}
	$compname = shorten($compname);
	print OUTFILE "$prefix $compname\n";
    }
#    else { print "failed to match: $ln"; }
}
