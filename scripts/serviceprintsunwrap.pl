#!/usr/bin/perl -w

# For now, this script just un-wordwraps all the service fingerprints
# found in a file (or set of files) and prints them out.  It also adds
# an IP element if it obtains that info from the Nmap log file.

sub osprep($) {
    my $ln = shift;
    chomp ($ln);
    $ln =~ s/^\s+//;
    $ln =~ s/\s+$//;
    return $ln;
}

sub finalfpprep($) {
    my $ln = shift;
    $ln =~ s/\\x20/ /g;
    return $ln;
}

my $infp = 0;
my $lineno = 0;
my $currentfp = "";
my $nextline;
my $lastip = "";
while(<>) {
    $nextline = $_;
    $lineno++;
 
    if ($infp) {
	if (!($nextline =~ /^   [^ ]+$/)) {
	    # Yay, just finished reading in an FP
	    print finalfpprep($currentfp) . "\n";
	    $infp = 0;
	    $currentfp = "";
	} else {
	    $nextline = osprep($nextline);
	    $currentfp .= $nextline;
	    if (length($currentfp) > 10000) {
		die "Fingerprint too long on line $lineno of input file(s)";
	    }
	}
    }

    if ($nextline =~ /^Interesting ports on.*\D(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
	$lastip = $1;
    }

    if ($nextline  =~ /^\s*SF-Port\d+-...:/) {
	$nextline = osprep($nextline);
	if ($lastip) {
	    $nextline =~ s/(SF-Port\d+-...:)/$1TIP=$lastip%/;
	}
	$currentfp .= $nextline;
	$infp = 1;
    }
}

if ($infp and $currentfp) {
    print finalfpprep($currentfp) . "\n";
}
