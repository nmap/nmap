#!/usr/local/bin/perl -w

sub usage() {
    print "sign_release.pl <distdir>\n";
    print "Cycles through every file in <distdir>, looking for corresponding gpg detached signature (<distdir>/$file.gpg.txt) and message digest (<distdir>/$file.digest.txt) files.  If either are both are missing for a given $file, they are recreated by calling gpg appropriately.\n\n";
    exit(1);
}

if ($#ARGV != 0) {
    print STDERR "ERROR: Wrong number of command-line arguments (must be exactly 1)\n";
    usage();
}

my $distdir = shift();
if ($distdir =~ m|/$|) { chop $distdir; }

if (! -d $distdir) {
    print STDERR "ERROR: Dist dir ($distdir) doesn't exist\n";
}

if (! -d "$distdir/sigs/" ) {
    print STDERR "ERROR: You must create sig directory ($distdir/sigs) before calling this script\n";
}

# Now go through each file generating sigs if neccessary
opendir DISTDIR, $distdir or die "Could not open distdir: $distdir\n";

foreach $file (readdir DISTDIR) {
    if ($file eq "favicon.ico") { next; }
    if (-f "$distdir/$file") {
	my $sigfile = "$distdir/sigs/$file.gpg.txt";
	my $digfile = "$distdir/sigs/$file.digest.txt";
	if (!-f $sigfile) {
	    my $command = "gpg --detach-sign -u 6B9355D0 --armor -o $sigfile $distdir/$file; chmod 644 $sigfile";
	    print "Running: $command\n";
	    system($command);
	}

	if (!-f $digfile) {
	    my $command = "cd $distdir && gpg --print-mds $file > $digfile; chmod 644 $digfile";
	    print "Running: $command\n";
	    system($command);		
	}
    }
}
