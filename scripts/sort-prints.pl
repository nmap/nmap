#!/usr/bin/perl -w

sub usage() {
    print STDERR "Usage: sort-prints.pl <nmap-os-fingerprints file>\n" .
	"Slurps up the given nmap-os-fingerprints file, sorts it appropriately (Class, then name string), then spits it out to stdout.  Some minor canonicalization is done too.\n\n";
    exit(0);
}

sub fprintsort {

    lc($a->{firstClass}) cmp lc($b->{firstClass})
	or 
    lc($a->{name}) cmp lc($b->{name});
}

if ($#ARGV != 0) {
    print STDERR "ERROR: Wrong number of command-line arguments (must be exactly 1)\n";
    usage();
}

my $osfile = shift();

open(OSFILE, "<$osfile") or die "Failed to open purported nmap-os-fingerprints file: $osfile\n";
my $state = "headertxt";
my $lineno = 0;
my $headertxt = "";
my @prints;
my %newFP = ();

while($nxtline = <OSFILE>) {
    $lineno++;

    if ($state eq "headertxt") {
	if ($nxtline =~ /^\#/) {
	    $headertxt .= $nxtline;
	} else {
	    $state = "fprint-comments";
	}
	next;
    } 

    if ($nxtline =~ /^\s*$/) {
# REMEMBER TO COPY ANY TEXT HERE TO THE FINAL PRINT CAPTURE BELOW THIS LOOP
	if ($state eq "fprint-tests") {
	    # A blank line ends a fingerprint
	    my %copy = %newFP;
	    push @prints, \%copy;
#	    print "Read in an FP!  There are now " . ($#prints + 1) . "\n";
	    %newFP = ();
	    $state = "fprint-comments";
	}
	next; 
    }

    if ($state eq "fprint-comments") {
	if ($nxtline =~ /^\#/) {
	    if (!($nxtline =~ /^\# /)) {
		$nxtline =~ s/^\#/\# /;
	    }
	    $newFP{comments} .= $nxtline; 
	    next;
	} else {
	    $state = "fprint-name";
	}
    } 

    if ($state eq "fprint-name") {
	if ($nxtline =~ /^Fingerprint (\S.*\S)\s*$/) {
	    $newFP{name} = $1;
	    $state = "fprint-class";
	    next;
	}
	die "ERROR: Parse error on $osfile:$lineno -- expected Fingerprint directive";
    }

    if ($state eq "fprint-class") {
	if ($nxtline =~ /^Class (\S.*\S)$/) {
	    if (!$newFP{firstClass}) {
		$newFP{firstClass} = $1;
	    }
	    $newFP{data} .= "$nxtline";
	    next;
	} else {
	    if (!$newFP{firstClass}) {
		die "ERROR: Parse error on $osfile:$lineno -- expected Class directive";
	    }
	    $state = "fprint-tests";
	}
    }

    if ($state eq "fprint-tests") {
	if ($nxtline =~ /^(SEQ|OPS|WIN|ECN|T[1-7]|U1|IE)\(.*\)(\s*\#.*)?$/) {
	    $newFP{data} .= "$nxtline";
	    next;
	}
	die "ERROR: Parse error on $osfile:$lineno -- expected a SEQ, OPS, WIN, ECN, T1-T7, U1 or IE test line";
    }
}

# Capture the final print
if ($state eq "fprint-tests") {
    # A blank line ends a fingerprint
    my %copy = %newFP;
    push @prints, \%copy;
#    print "Read final FP!  There are now " . ($#prints + 1) . "\n";
} elsif ($state ne "fprint-comments") {
    die "ERROR: $osfile appears to have ended in mid-fingerprint";
}

# print "Successfully read in " . ($#prints + 1) . " fingerprints from $osfile\n";

my @sortedprints = sort fprintsort @prints;

# print "The first name is $prints[0]->{name} and the second is $prints[1]->{name}\n";
# print "The sorted first name is $sortedprints[0]->{name} and the second is $sortedprints[1]->{name}\n";
print $headertxt;
print "\n";
my $firstline = "true";
foreach $print (@sortedprints) {
    if ($firstline) {
	$firstline = 0;
    } else { print "\n"; }
    if ($print->{comments}) {
	print $print->{comments};
    }
    print "Fingerprint $print->{name}\n";
    print "$print->{data}";
}
