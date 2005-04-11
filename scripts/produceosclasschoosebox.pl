#!/usr/bin/perl -w

if (!$ARGV[0]) { 
    print "Usage: produceosclasschoosebox.pl <nmap-os-fingerprints-filepath>\n\n"; exit; 
}

# Kill leading and trailing whitespace
sub killws($) {
    $str = shift;
    $str =~ s/^\s+//g;
    $str =~ s/\s+$//g;
    return $str;
}

my @optionar;
my %unique_optvals;

while(<>) {
    my %infohash;
    if (/^Class /) {
	s/Class //;
	# Kill leading and trailing whitespace
	my ($vendor, $osfam, $osgen, $type) = split /\|/;
	$vendor = killws($vendor);
	$osfam = killws($osfam);
	$osgen = killws($osgen);
	$type = killws($type);
	$infohash{opval} = "$vendor|$osfam|$osgen|$type";
	if (!$unique_optvals{$infohash{opval}}) {
	    $unique_optvals{$infohash{opval}} = 1;
	    $infohash{vendor} = $vendor;
	    $infohash{osfam} = $osfam;
	    $infohash{osgen} = $osgen;
	    $infohash{type} = $type;

	    if ($osgen) { $osgen = " $osgen"; }
	    if ($vendor eq $osfam) { $vendor = ""; } else {$vendor = "$vendor "; }
	    $infohash{fullname} = "$vendor$osfam$osgen $type";
	    push @optionar, \%infohash;
	}
    }
}

@optionar = sort { lc($a->{fullname}) cmp lc($b->{fullname}) } @optionar;

foreach $opt (@optionar) {
    print qq|<option value="| . $opt->{opval} . qq|">| . $opt->{fullname} . "\n";
}
