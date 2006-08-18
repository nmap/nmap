#!/usr/bin/perl -w
# For now, this script just un-wordwraps all the OS fingerprints found
# in a file (or set of files, or stdin) and prints them out.  It also
# adds an IP element if it obtains that info from the Nmap log file.

my $lineno = 0;
my $nextline;
my $fp = "";

# First remove the OS: prefix and extra newlines
while(<>) {
    $nextline = $_;
    $lineno++;
    if ($nextline  =~ /^\s*OS:/) {
	chomp($nextline);
	$nextline =~ s/^\s*OS://;
	$nextline =~ s/\s+$//;
	$fp .= $nextline;
    } else {
	if ($fp) {
	    # I've just finished reading in an FP, apparently.  Process and
            # print it out.  First add appropriate line breaks
	    $fp =~ s/\)/\)\n/g;
	    print "New Fingerprint:\n$fp\n";
	    $fp = "";
	}
    }
}

