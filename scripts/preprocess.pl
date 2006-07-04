#!/usr/bin/perl -w

sub usage() {
    print STDERR "Usage: $0 <nmap os fingerprint submission file>\n" .
	"Slurps up the given nmap-os-fingerprints file, sorts it appropriately (Class, then name string), then spits it out to stdout.  Some minor canonicalization is done too.\n\n";
    exit(0);
}

sub osprep($) {
    my $ln = shift;
    chomp ($ln);
    $ln =~ s/^\s+//;
    $ln =~ s/\s+$//;
    return $ln;
}

sub finalfpprep($) {
    my $ln = shift;
    $ln =~ s/\)/\)\n/g;
    return $ln;
}

sub fprintsort() {
    lc($a->{fpClass}) cmp lc($b->{fpClass})
	or 
    lc($a->{fpName}) cmp lc($b->{fpName})
	or
	$b->{fpGood} <=> $a->{fpGood}
	;
}

if ($#ARGV != 0) {
    print STDERR "ERROR: Wrong number of command-line arguments (must be exactly 1)\n";
    usage();
}

my $osfile = shift();
open(OSFILE, "<$osfile") or die "Failed to open purported os fingerprint submission file: $osfile\n";

my $state = "null";
my $lineno = 0;

my @mails;
my %msg = ();
my $bodylines = -1;

my $fpstate = "null";
my $fpstr = "";
my @fplines;
my %fp;
my $fptestname = "";
my $fptestnum = 0;


while ($line = <OSFILE>) {
	$lineno++;

	if ($state eq "null") {
		if ($line =~ /^\s*$/) {
			next;
		} else {
			$state = "msg_header";
		}
	}
	
	if ($state eq "msg_header") {
		if ($line =~ /^\s*$/) {
			# A blank line ends a mail header
			if ($bodylines == -1) {
				die "ERROR: Parse error on $osfile:$lineno -- expected a Lines field in mail header";
			}
			$state = "msg_body";
		} else {
			if ($line =~ /^lines:\s*([0-9]+)/i) {
				$bodylines = $1;
			}
			$msg{header} .= $line;
		}
		next;
	} elsif ($state eq "msg_body") {
		if ($bodylines > 0) {
			$bodylines--;
			$msg{body} .= $line;

			if ($line =~ /^\s*Fingerprint (\S.*\S)\s*$/) {
				$msg{fpName} = $1;
			}
			if ($line =~ /^\s*Class (\S.*\S)$/) {
				$msg{fpClass} = $1;
			}
			if ($line =~ /^\s*OS:/i) {
				$line = osprep($line);
				$line =~ s/^\s*OS://i;
				$fpstr .= $line;
				$fpstate = "fp";
			} elsif ($fpstate eq "fp") {
				$fpstate = "null";
			}
		}
		if ($bodylines == 0) {
			if (!$msg{fpName}) {
				$msg{fpName} = "NULL";
			}
			if (!$msg{fpClass}) {
				$msg{fpClass} = "NULL";
			}

			$msg{fpGood} = 0;
			
			if ($fpstr) {
				$fpstr = finalfpprep($fpstr);
				# print $fpstr . "\n";
				@fplines = split /\n/, $fpstr;

				$fptestnum = 0;
				foreach $fpline (@fplines) {
					# print $fpline . "\n";
					if ($fpline =~ /^SCAN.*%OT=([0-9]*)%CT=([0-9]*)%CU=([0-9]*)%PV=([YN])(%DS=([0-9]+))?%G=([YN])(%M=([0-9A-F]+))?.*/i) {
						$fptestnum++;
						# $fp_ot = $1;
						# $fp_ct = $2;
						$fp_cu = $3;
						$fp_pv = $4;
 						# if($5) {
 						# 	$fp_ds = $6;
 						# } else {
 						#	$fp_ds = -1;
 						# }
						$fp_good = $7;
						if($8) {
							$fp_mac = $9;
						} else {
							$fp_mac = "";
						}

						if ($fp_cu) {
							$msg{fpGood} += 1;
						}

						if ($fp_pv eq "Y") {
							$msg{fpGood} += 1;
						}
						
						if ($fp_good eq "Y") {
							$msg{fpGood} += 2;
						}

						if ($fp_mac) {
							$msg{fpGood} += 1;
						}
						
					} elsif ($fpline =~ /^((SEQ)|(OPS)|(WIN)|(ECN)|(T[1-7])|(U1)|(IE))/i) {
						$fptestname = $1;
						if (!$fp{$fptestname}) {
							$fptestnum++;
						}
						$fp{$fptestname} .= $line;
					}
				}
				if ($fptestnum == 14) {
					# This submission has all the fp fields
					$msg{fpGood} += 5;
				}
			}
			# print $msg{fpGood} . "\n";
			
			my %copy = %msg;
			push @mails, \%copy;
			
			$state = "null";
			%msg = ();
			$bodylines = -1;

			$fpstate = "null";
			$fpstr = "";
			%fp = ();
		}
		next;
	}
}

my @sortedmails = sort fprintsort @mails;

my $firstline = 1;
my $currentFpClass = "";
foreach $mail (@sortedmails) {
    if ($firstline) {
		$firstline = 0;
    } else { print "\n"; }

	if ($currentFpClass ne $mail->{fpClass}) {
		print 'From anonymous@core.lnxnet.net Mon Jul 04 00:00:01 2006', "\n",
			'To: fyodor@insecure.org', "\n",
			'From: nmap-submission-cgi@core.lnxnet.net', "\n",
			"Subject: ======  $mail->{fpClass}  ======\n",
			"Status: O\n",
			"Lines: 1\n\n";
		print "## Separator ##\n\n";
		$currentFpClass = $mail->{fpClass};
	}
    print "$mail->{header}\n";
    print "$mail->{body}";
}
