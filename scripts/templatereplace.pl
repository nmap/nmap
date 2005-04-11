#!/usr/bin/perl -w
my $usage = <<EOUSAGE;
Usage: templatereplace.pl [ops] <templatefile> <subjectfile1> ...

The idea behind this simple script is to replace blocks of text in one
or more files with a standard block provided in a "template file".
This script first reads in the template file, making special note of
the first and last lines.  It then reads in the subject files, one by
one.  If it sees the first template file line in one of the files, it
deletes text in the subject file until it finds the last template
line.  Then it replaces the deleted text with the verbatim contents of
the template file.  Files that don't contain the first template line
are unchanged.

Example usage:
find . -name '*.[ch]' -o -name '*.cc' -o -name COPYING -o -iname '*.in' | xargs scripts/templatereplace.pl -v scripts/nmap.header.tmpl
find . -name '*.[ch]' -o -name '*.cc' -o -name COPYING -o -iname '*.in' | xargs scripts/templatereplace.pl -v scripts/nsock.header.tmpl

EOUSAGE

use Getopt::Std;
use English;

my $verbose = 0;

sub usage() { print $usage; exit(1); }

# This function processes a template file by reading in all the data
# from $tmpldata->{name} and filling in $tmpldata->{firstline},
# $tmpldata->{lastline}, and $tmpldata->{content} (the latter does
# not include firstline and lastline).  This function will give an
# error and exit the program if there are problems.
sub process_tmpl($) {
    my $tdata = shift();
    my $line;
    my $lastline;
    my $lineno = 1;

    if ($verbose) { 
	print "Reading in template file: " . $tdata->{fname} . "\n";
    }

    if (!open TMPL, "<" . $tdata->{fname}) {
	print "FAILED to read in template file: " . $tdata->{fname} . "\n";
	usage();
    }

    $tdata->{content} = "";

    while($line = <TMPL>) {
	if ($lineno == 1) {
	    $tdata->{firstline} = $line;
	} else {
	    if ($lineno != 2) {	$tdata->{content} .= $lastline; }
	}
	$lastline = $line;
	$lineno++;
    }

    if ($lineno < 3) {
	print "Template file " . $tdata->{fname} . " is not long enough!  Muts be at least 3 lines (first, content, and last)\n"; 
    }
    $tdata->{lastline} = $lastline;

    close TMPL;
}

sub process_subj($$) {
    my ($subjectfile, $tmpl) = @_;
    my $newfile = "";
    my $state = 0;
    my $line;


    if (!open SUB, "<$subjectfile") {
	print "FAILED to read in subject file ($subjectfile) - skipping\n";
	return;
    }

# No need to worry about perms since we are overwriting existing file.
#    my $perm = (stat $subjectfile)[2];
#    $perm = $perm & 0777;  # We ONLY want mode (not type too) and no suid bits

    while($line = <SUB>) {
	if ($state == 0) {
	    # Haven't found the match begin yet
	    if ($line eq $tmpl->{firstline}) { $state = 1; }
	    else { $newfile .= $line; }
	} elsif ($state == 1) {
            # Am between the match begin and end
	    if ($line eq $tmpl->{lastline}) {
		$state = 2;
		$newfile .= $tmpl->{firstline};
		$newfile .= $tmpl->{content};
		$newfile .= $tmpl->{lastline};
	    }
            # Otherwise do nothing
	} else {
	    # Already did the match, now we just copy the lines verbatim.
	    $newfile .= $line;
	}
    }
    close SUB;

    if ($state == 0) {
	if ($verbose) { print "$subjectfile -> no replacement\n"; }
    } elsif ($state == 1) {
	print "WARNING:  $subjectfile had begin line but never ended - skipping\n";
    } else {
	# Yeah - we did the replacement so now lets write back the file.
	if (!open SUBWRITE, ">$subjectfile") {
	    print "FAILED to write to subject file ($subjectfile) - $! - skipping\n";
	    return;
	}
	print SUBWRITE $newfile;
	close SUBWRITE;
	if ($verbose) {
	    print "$subjectfile -> replacement succeeded\n";
	}
    }
}

# MAIN
use vars qw($opt_h $opt_v);

if (!getopts("vh")) {
    print STDERR "Invalid arguments\n";
    usage();
}

if ($opt_h) {
    usage();
}

if ($opt_v) {
    $verbose = 1;
}

$tmpldata{fname} = shift();
process_tmpl(\%tmpldata);

if ($verbose) {
    printf "Processed template:" . $tmpldata{fname} . "\nSeeking Start: " . $tmpldata{firstline} . "          End: " . $tmpldata{lastline} . "\n";
}
# Now it is time to handle each subject file, one at a time.

my $subjectfile;
while($subjectfile = shift()) {
    process_subj($subjectfile, \%tmpldata);
}


