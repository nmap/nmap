#!/usr/bin/perl

sub max($$) {
    my ($a, $b) = @_;
    if ($a >= $b) { return $a;}
    return $b;
}

sub min($$) {
    my ($a, $b) = @_;
    if ($a <= $b) { return $a;}
    return $b;
}

sub fpunwrap($) {
    my $fp = shift();
    $fp =~ s/^\s*OS://mg;
    $fp =~ s/\n//g;
    $fp =~ s/\s+$//g;
    $fp =~ s/\)/\)\n/g;
    return $fp;
}

# first read in the fingerprint
my $printbuf = "";
my $wrapped = 0;

while(<>) {
    chomp;
    $line = $_;

    if (($line eq "." || $line eq "")) { 
	if ($printbuf) { last; }
    } else { $printbuf .= "$line\n"; }
    if ($line =~ /^\s*OS:/) { $wrapped = 1; }
}

if ($wrapped) {
    $printbuf = fpunwrap($printbuf);
    print "Unwrapped fingerprint:\n$printbuf\n";
}

# At this point I have an unwrapped FP in $printbuf
foreach $line (split /\n/, $printbuf) {
    chomp($line);
    
    # Itemize the lines we know how to deal with
    if (!$line =~ /(Fingerprint\s+\S)|(Class\s+\S)|(^SEQ)|(^OPS)|(^WIN)|(^ECN)|(^T[1-7])|(^U1)|(^IE)|(^Contributed by)/i) { next; }
    
    # If this is coming from the submission form, there may already be a Contributor attached
    if ($line =~ /Contributed by (.*)/) {
	if (!$fp{contrib}) {
	    $fp{contrib} = $1;
	} else { $fp{contrib} .= ", $1"; }
    }
    
    # We also get a Fingerprint line describing what this system (supposedly) is if it is coming from
    # the submission CGI.
    elsif ($line =~ /Fingerprint\s+(.*)/i) {
	$fp{os} = $1;
    }
    
    # If the submitter gave a classification, we have a Class line
    elsif ($line =~ /Class\s+(.*)/i) {
	if (!$fp{class} or !($fp{class} =~ /\Q$line\E/)) {
	    $fp{class} .= $line . "\n";
	}
    }
    
    # OK, time for the first real fingerprint line!  The SEQ line
    elsif ($line =~ /SEQ\(SP=([^%]+)%GCD=([^%\)]+)%ISR=([^%\)]+)(%TI=([^%\)]+))?(%II=([^%\)]+))?(%SS=([^%\)]+))?(%TS=([^%\)]+))?\)/) {
	# SEQ
	$sp = $1;
	$gcd = hex($2);
	$isr = $3;
        $ti = $5;
	$ii = $7;
	$ss = $9;
        $ts = $11;

	if ($fp{seq}{gcd} =~ /<([0-9A-F]+)/) {
	    $oldgcd = hex($1);
	} else { $oldgcd = 3; }
	
	$newgcd = max($oldgcd, $gcd * 2 + 3);
	$fp{seq}{gcd} = sprintf ("<%X", $newgcd);
	
	$newhighlim = $newlowlim = -1;
	if ($sp =~ /([0-9A-F]+)-([0-9A-F]+)/) {
	    $newlowlim = hex($1);
	    $newhighlim = hex($2);
	} elsif ($sp =~ /<([0-9A-F]+)/) {
	    $newhighlim = hex($1);
	}
	
	# print "newhighlim: $newhighlim newlowlim: $newlowlim\n";
	
	$oldhighlim = $oldlowlim = 0;
	if ($fp{seq}{sp} =~ /([0-9A-F]+)-([0-9A-F]+)/) {
	    $oldlowlim = hex($1);
	    $oldhighlim = hex($2);
	} elsif ($fp{seq}{sp} =~ /<([0-9A-F]+)/) {
	    $oldhighlim = hex($1);
	} elsif ($fp{seq}{sp} =~ /^([0-9A-F]+)/) {
	    $oldhighlim = $oldlowlim = hex($1);
	}
	
        # print "oldhighlim: $oldhighlim oldlowlim: $oldlowlim\n";
	
	if ($oldlowlim) {
	    if ($newlowlim != -1) { $newlowlim = max(0, min($oldlowlim, $newlowlim)); } 
	    else { $newlowlim = max(0, min($oldlowlim, hex($sp))); }
	} else {
	    if ($newlowlim == -1) { $newlowlim = max(0, hex($sp)); }
	}
	
	if ($newhighlim == -1) { 
	    $newhighlim = max($oldhighlim, hex($sp));
	} else {
	    $newhighlim = max($oldhighlim, $newhighlim);
	}
	
	# print "oldhighlim: $oldhighlim oldlowlim: $oldlowlim newhighlim: $newhighlim newlowlim: $newlowlim oldsp: $fp{seq}{sp}";
	
	if ($newlowlim eq $newhighlim) {
	    $fp{seq}{sp} = sprintf("%X", $newhighlim);
	} elsif ($newlowlim > 0) {
	    $fp{seq}{sp} = sprintf("%X-%X", $newlowlim, $newhighlim);
	} else {
	    $fp{seq}{sp} = sprintf("<%X", $newhighlim);
	}
	
	# print " newsp: $fp{seq}{sp}\n";
	
	
	if (!($fp{seq}{isr} =~ /(^|\|)$isr($|\|)/)) {
            if ($fp{seq}{isr}) {
                $fp{seq}{isr} = $fp{seq}{isr} . qq^|$isr^;
            } else {
                $fp{seq}{isr} = $isr;
            }
        }

	if (!($fp{seq}{ti} =~ /(^|\|)$ti($|\|)/)) {
            if ($fp{seq}{ti}) {
                $fp{seq}{ti} = $fp{seq}{ti} . qq^|$ti^;
            } else {
                $fp{seq}{ti} = $ti;
            }
        }
	
	if (!($fp{seq}{ii} =~ /(^|\|)$ii($|\|)/)) {
            if ($fp{seq}{ii}) {
                $fp{seq}{ii} = $fp{seq}{ii} . qq^|$ii^;
            } else {
                $fp{seq}{ii} = $ii;
            }
        }
	
	if (!($fp{seq}{ss} =~ /(^|\|)$ss($|\|)/)) {
            if ($fp{seq}{ss}) {
                $fp{seq}{ss} = $fp{seq}{ss} . qq^|$ss^;
            } else {
                $fp{seq}{ss} = $ss;
            }
        }
	
	if (!($fp{seq}{ts} =~ /(^|\|)$ts($|\|)/)) {
            if ($fp{seq}{ts}) {
                $fp{seq}{ts} = $fp{seq}{ts} . qq^|$ts^;
            } else {
                $fp{seq}{ts} = $ts;
            }
        }
	
    } elsif ($line =~ /^OPS/) {
	# Time for the second test line -- Ops (Options)
	foreach $num (1 .. 6) {
	    $o = "";
	    $oi = "o$num";
	    if ($line =~ /[\(%]O$num=([0-9A-Z|]*)/) {
		$o = $1;
		if (!$o) { $o = "NULL"; }
	    }
	    
	    if (!($fp{ops}{$oi} =~ /(^|\|)$o($|\|)/)) {
		if ($fp{ops}{$oi}) {
		    $fp{ops}{$oi} = $fp{ops}{$oi} . qq^|$o^;
		} else {
		    $fp{ops}{$oi} = $o;
		}
	    }
	}
    }  elsif ($line =~ /^WIN/) {
	# WIN - Window values
	foreach $num (1 .. 6) {
	    $w = "";
	    $wi = "w$num";
	    if ($line =~ /[\(%]W$num=([0-9A-F|]*)/) {
		$w = $1;
		if (!$w) { $w = "NULL"; }
	    }
	    
	    if (!($fp{win}{$wi} =~ /(^|\|)$w($|\|)/)) {
		if ($fp{win}{$wi}) {
		    $fp{win}{$wi} = $fp{win}{$wi} . qq^|$w^;
		} else {
		    $fp{win}{$wi} = $w;
		}
	    }
	}
    }  elsif ($line =~ /^ECN/) {
	# ECN - Explicit Congestion Notification probe response
	$resp = $df = $ttl = $win = $ops = $cc = $quirk = "";
	
	if ($line =~ /R=([NY])/) {
	    $resp = $1;
	}
	if ($line =~ /[\(%]DF=([NY])/) {
	    $df = $1;
	}
	if ($line =~ /[\(%]TG?=([0-9A-F]+)/) {
	    $ttl = $1;
	    if (!$ttl) { $ttl = "NULL"; }
	}
	if ($line =~ /[\(%]W=([0-9A-F|]*)/) {
	    $win = $1;
	    if (!$win) { $win = "NULL"; }
	}
	if ($line =~ /[\(%]O=([0-9A-Z|]*)/) {
	    $ops = $1;
	    if (!$ops) { $ops = "NULL"; }
	}
	if ($line =~ /[\(%]CC=([NY])/) {
	    $cc = $1;
	}
	if ($line =~ /[\(%]Q=(R?U?)/) {
	    $quirk = $1;
	    if (!$quirk) { $quirk = "NULL"; }
	}

	if ($resp eq "Y" or !$resp) {
	    $fp{ecn}{resp} = "Y";
	    if ($df and !($fp{ecn}{df} =~ /(^|\|)$df($|\|)/)) {
		if ($fp{ecn}{df}) {
		    $fp{ecn}{df} .= qq^|$df^;
		} else {
		    $fp{ecn}{df} = $df;
		}
	    }

	    if (!($fp{ecn}{ttl} =~ /(^|\|)$ttl($|\|)/)) {
		if ($fp{ecn}{ttl}) {
		    $fp{ecn}{ttl} = $fp{ecn}{ttl} . qq^|$ttl^;
		} else {
		    $fp{ecn}{ttl} = $ttl;
		}
	    }

	    if (!($fp{ecn}{win} =~ /(^|\|)$win($|\|)/)) {
		if ($fp{ecn}{win}) {
		    $fp{ecn}{win} = $fp{ecn}{win} . qq^|$win^;
		} else {
		    $fp{ecn}{win} = $win;
		}
	    }

	    if (!($fp{ecn}{ops} =~ /(^|\|)$ops($|\|)/)) {
		if ($fp{ecn}{ops}) {
		    $fp{ecn}{ops} = $fp{ecn}{ops} . qq^|$ops^;
		} else {
		    $fp{ecn}{ops} = $ops;
		}
	    }

	    if ($cc and !($fp{ecn}{cc} =~ /(^|\|)$cc($|\|)/)) {
		if ($fp{ecn}{cc}) {
		    $fp{ecn}{cc} .= qq^|$cc^;
		} else {
		    $fp{ecn}{cc} = $cc;
		}
	    }

	    if (!($fp{ecn}{quirk} =~ /(^|\|)$quirk($|\|)/)) {
		if ($fp{ecn}{quirk}) {
		    $fp{ecn}{quirk} .= qq^|$quirk^;
		} else {
		    $fp{ecn}{quirk} = $quirk;
		}
	    }

	} elsif ($fp{ecn}{resp} ne "Y") {
	    $fp{ecn}{resp} = "N";
	}
    } elsif ($line =~ /^T([1-7])/) {
	$num = $1;
	$test = "T$num";
	$resp = $df = $ttl = $win = $seq = $ack = $flags = $ops = $rd = $quirk = "";

	if ($line =~ /R=([NY])/) {
	    $resp = $1;
	}
	if ($line =~ /[\(%]DF=([NY])/) {
	    $df = $1;
	}
	if ($line =~ /[\(%]TG?=([0-9A-F]+)/) {
	    $ttl = $1;
	    if (!$ttl) { $ttl = "NULL"; }
	}
	if ($num != 1 and $line =~ /[\(%]W=([0-9A-F|]*)/) {		
	    $win = $1;
	    if (!$win) { $win = "NULL"; }
	}
	if ($line =~ /[\(%]S=([^%]+)/) {
	    $seq = $1;
	}
	if ($line =~ /[\(%]A=([^%]+)/) {
	    $ack = $1;
	}
	if ($line =~ /[\(%]F=([^%]*)/) {
	    $flags = $1;
	    if (!$flags) { $flags = "NULL"; }
	}
	if ($num != 1 and $line =~ /[\(%]O=([0-9A-Z|]*)/) {		
	    $ops = $1;
	    if (!$ops) { $ops = "NULL"; }
	}
	if ($line =~ /[\(%]RD=([0-9A-F]*)/) {
	    $rd = $1;
	    if (!$rd) { $rd = "NULL"; }
	}
	if ($line =~ /[\(%]Q=(R?U?)/) {
	    $quirk = $1;
	    if (!$quirk) { $quirk = "NULL"; }
	}

	if ($resp eq "Y" or !$resp) {
	    $fp{$test}{resp} = "Y";
	    if ($df and !($fp{$test}{df} =~ /(^|\|)$df($|\|)/)) {
		if ($fp{$test}{df}) {
		    $fp{$test}{df} .= qq^|$df^;
		} else {
		    $fp{$test}{df} = $df;
		}
	    }

	    if (!($fp{$test}{ttl} =~ /(^|\|)$ttl($|\|)/)) {
		if ($fp{$test}{ttl}) {
		    $fp{$test}{ttl} = $fp{$test}{ttl} . qq^|$ttl^;
		} else {
		    $fp{$test}{ttl} = $ttl;
		}
	    }

	    if ($num != 1 and !($fp{$test}{win} =~ /(^|\|)$win($|\|)/)) {
		if ($fp{$test}{win}) {
		    $fp{$test}{win} = $fp{$test}{win} . qq^|$win^;
		} else {
		    $fp{$test}{win} = $win;
		}
	    }

	    if ($seq and !($fp{$test}{seq} =~ /(^|\|)$seq($|\|)/)) {
		if ($fp{$test}{seq}) {
		    $fp{$test}{seq} .= qq^|$seq^;
		} else {
		    $fp{$test}{seq} = $seq;
		}
	    }

	    if ($ack and !($fp{$test}{ack} =~ /(^|\|)$ack($|\|)/)) {
		if ($fp{$test}{ack}) {
		    $fp{$test}{ack} .= qq^|$ack^;
		} else {
		    $fp{$test}{ack} = $ack;
		}
	    }

	    if (!($fp{$test}{flags} =~ /(^|\|)$flags($|\|)/)) {
		if ($fp{$test}{flags}) {
		    $fp{$test}{flags} = $fp{$test}{flags} . qq^|$flags^;
		} else {
		    $fp{$test}{flags} = $flags;
		}
	    }

	    if ($num != 1 and !($fp{$test}{ops} =~ /(^|\|)$ops($|\|)/)) {
		if ($fp{$test}{ops}) {
		    $fp{$test}{ops} = $fp{$test}{ops} . qq^|$ops^;
		} else {
		    $fp{$test}{ops} = $ops;
		}
	    }

	    if (!($fp{$test}{rd} =~ /(^|\|)$rd($|\|)/)) {
		if ($fp{$test}{rd}) {
		    $fp{$test}{rd} = $fp{$test}{rd} . qq^|$rd^;
		} else {
		    $fp{$test}{rd} = $rd;
		}
	    }

	    if (!($fp{$test}{quirk} =~ /(^|\|)$quirk($|\|)/)) {
		if ($fp{$test}{quirk}) {
		    $fp{$test}{quirk} .= qq^|$quirk^;
		} else {
		    $fp{$test}{quirk} = $quirk;
		}
	    }

	} elsif ($fp{$test}{resp} ne "Y") {
	    $fp{$test}{resp} = "N";
	}
    } elsif ($line =~ /^U1/) {
	$resp = $df = $ttl = $tos = $ipl = $un = $ripl = $rid = $ripck = $ruck = $rul = $rud = "";

	if ($line =~ /R=([NY])/) {
	    $resp = $1;
	}
	if ($line =~ /[\(%]DF=([NY])/) {
	    $df = $1;
	}
	if ($line =~ /[\(%]TG?=([0-9A-F]+)/) {
	    $ttl = $1;
	    if (!$ttl) { $ttl = "NULL"; }
	}
	if ($line =~ /[\(%]TOS=([^%]+)/) {
	    $tos = $1;
	    if (!$tos) { $tos = "NULL"; }
	}
	if ($line =~ /[\(%]IPL=([^%]+)/) {
	    $ipl = $1;
	}
	if ($line =~ /[\(%]UN=([0-9A-F]*)/) {
	    $un = $1;
	    if (!$un) { $un = "NULL"; }
	}
	if ($line =~ /[\(%]RIPL=([^%]+)/) {
	    $ripl = $1;
	}
	if ($line =~ /[\(%]RID=([^%]+)/) {
	    $rid = $1;
	}
	if ($line =~ /[\(%]RIPCK=([^%]+)/) {
	    $ripck = $1;
	    if (!$ripck) { $ripck = "NULL"; }
	}
	if ($line =~ /[\(%]RUCK=([^%]+)/) {
	    $ruck = $1;
	    if (!$ruck) { $ruck = "NULL"; }
	}
	if ($line =~ /[\(%]RUL=([^%]+)/) {
	    $rul = $1;
	}
	if ($line =~ /[\(%]RUD=([A-Z|]+)/) {
	    $rud = $1;
	}

	if ($resp eq "Y" or !$resp) {
	    $fp{u1}{resp} = "Y";

	    if ($df and index($fp{u1}{df}, $df) == -1) {
		if ($fp{u1}{df}) {
		    $fp{u1}{df} = $fp{u1}{df} . qq^|$df^;
		} else {
		    $fp{u1}{df} = $df;
		}
	    }

	    if (!($fp{u1}{ttl} =~ /(^|\|)$ttl($|\|)/)) {
		if ($fp{u1}{ttl}) {
		    $fp{u1}{ttl} = $fp{u1}{ttl} . qq^|$ttl^;
		} else {
		    $fp{u1}{ttl} = $ttl;
		}
	    }

	    if ($tos and index($fp{u1}{tos}, $tos) == -1) {
		if ($fp{u1}{tos}) {
		    $fp{u1}{tos} = $fp{u1}{tos} . qq^|$tos^;
		} else {
		    $fp{u1}{tos} = $tos;
		}
	    }

	    if ($ipl and index($fp{u1}{ipl}, $ipl) == -1) {
		if ($fp{u1}{ipl}) {
		    $fp{u1}{ipl} = $fp{u1}{ipl} . qq^|$ipl^;
		} else {
		    $fp{u1}{ipl} = $ipl;
		}
	    }

	    if ($un and index($fp{u1}{un}, $un) == -1) {
		if ($fp{u1}{un}) {
		    $fp{u1}{un} = $fp{u1}{un} . qq^|$un^;
		} else {
		    $fp{u1}{un} = $un;
		}
	    }

	    if ($ripl and index($fp{u1}{ripl}, $ripl) == -1) {
		if ($fp{u1}{ripl}) {
		    $fp{u1}{ripl} = $fp{u1}{ripl} . qq^|$ripl^;
		} else {
		    $fp{u1}{ripl} = $ripl;
		}
	    }

	    if ($rid and index($fp{u1}{rid}, $rid) == -1) {
		if ($fp{u1}{rid}) {
		    $fp{u1}{rid} = $fp{u1}{rid} . qq^|$rid^;
		} else {
		    $fp{u1}{rid} = $rid;
		}
	    }

	    if ($ripck and index($fp{u1}{ripck}, $ripck) == -1) {
		if ($fp{u1}{ripck}) {
		    $fp{u1}{ripck} = $fp{u1}{ripck} . qq^|$ripck^;
		} else {
		    $fp{u1}{ripck} = $ripck;
		}
	    }

	    if ($ruck and index($fp{u1}{ruck}, $ruck) == -1) {
		if ($fp{u1}{ruck}) {
		    $fp{u1}{ruck} = $fp{u1}{ruck} . qq^|$ruck^;
		} else {
		    $fp{u1}{ruck} = $ruck;
		}
	    }

	    if ($rul and index($fp{u1}{rul}, $rul) == -1) {
		if ($fp{u1}{rul}) {
		    $fp{u1}{rul} = $fp{u1}{rul} . qq^|$rul^;
		} else {
		    $fp{u1}{rul} = $rul;
		}
	    }

	    if ($rud and index($fp{u1}{rud}, $rud) == -1) {
		if ($fp{u1}{rud}) {
		    $fp{u1}{rud} = $fp{u1}{rud} . qq^|$rud^;
		} else {
		    $fp{u1}{rud} = $rud;
		}
	    }

	} elsif ($fp{u1}{resp} ne "Y") {
	    $fp{u1}{resp} = "N";
	}
    } elsif ($line =~ /^IE/) {
	$resp = $dfi = $ttl = $tosi = $cd = $si = $dli = "";

	if ($line =~ /R=([NY])/) {
	    $resp = $1;
	}
	if ($line =~ /[\(%]DFI=([^%]+)/) {
	    $dfi = $1;
	}
	if ($line =~ /[\(%]TG?=([0-9A-F]+)/) {
	    $ttl = $1;
	    if (!$ttl) { $ttl = "NULL"; }
	}
	if ($line =~ /[\(%]TOSI=([^%]+)/) {
	    $tosi = $1;
	    if (!$tosi) { $tosi = "NULL"; }
	}
	if ($line =~ /[\(%]CD=([^%]+)/) {
	    $cd = $1;
	}
	if ($line =~ /[\(%]SI=([^%]+)/) {
	    $si = $1;
	}
	if ($line =~ /[\(%]DLI=([A-Z|]+)/) {
	    $dli = $1;
	}

	if ($resp eq "Y" or !$resp) {
	    $fp{ie}{resp} = "Y";

	    if ($dfi and index($fp{ie}{dfi}, $dfi) == -1) {
		if ($fp{ie}{dfi}) {
		    $fp{ie}{dfi} = $fp{ie}{dfi} . qq^|$dfi^;
		} else {
		    $fp{ie}{dfi} = $dfi;
		}
	    }

	    if (!($fp{ie}{ttl} =~ /(^|\|)$ttl($|\|)/)) {
		if ($fp{ie}{ttl}) {
		    $fp{ie}{ttl} = $fp{ie}{ttl} . qq^|$ttl^;
		} else {
		    $fp{ie}{ttl} = $ttl;
		}
	    }

	    if ($tosi and index($fp{ie}{tosi}, $tosi) == -1) {
		if ($fp{ie}{tosi}) {
		    $fp{ie}{tosi} = $fp{ie}{tosi} . qq^|$tosi^;
		} else {
		    $fp{ie}{tosi} = $tosi;
		}
	    }

	    if ($cd and index($fp{ie}{cd}, $cd) == -1) {
		if ($fp{ie}{cd}) {
		    $fp{ie}{cd} = $fp{ie}{cd} . qq^|$cd^;
		} else {
		    $fp{ie}{cd} = $cd;
		}
	    }

	    if ($si and index($fp{ie}{si}, $si) == -1) {
		if ($fp{ie}{si}) {
		    $fp{ie}{si} = $fp{ie}{si} . qq^|$si^;
		} else {
		    $fp{ie}{si} = $si;
		}
	    }

	    if ($dli and index($fp{ie}{dli}, $dli) == -1) {
		if ($fp{ie}{dli}) {
		    $fp{ie}{dli} = $fp{ie}{dli} . qq^|$dli^;
		} else {
		    $fp{ie}{dli} = $dli;
		}
	    }

	} elsif ($fp{ie}{resp} ne "Y") {
	    $fp{ie}{resp} = "N";
	}
    }
}

# OK, now it is time to print out the merged Fprint ...

# Printing contributed by line was like a magnet for spammers and took
# up a substantial amount of space in the file.
# if ($fp{contrib}) { print "# Contributed by $fp{contrib}\n"; }

print "ADJUSTED FINGERPRINT:\n";
print "Fingerprint $fp{os}\n";
if ($fp{class}) { print $fp{class}; }
else { print "Class \n"; }

# SEQ
if ($fp{seq}{sp}) {
    print("SEQ(SP=$fp{seq}{sp}");
    if ($fp{seq}{gcd}) {
	print "%GCD=$fp{seq}{gcd}";
    }

    if ($fp{seq}{isr}) { print "%ISR=$fp{seq}{isr}"; }
    if ($fp{seq}{ti}) { print "%TI=$fp{seq}{ti}"; }
    if ($fp{seq}{ii}) { print "%II=$fp{seq}{ii}"; }
    if ($fp{seq}{ss}) { print "%SS=$fp{seq}{ss}"; }
    if ($fp{seq}{ts}) { print "%TS=$fp{seq}{ts}"; }
    print ")\n";
} 

# OPS
if ($fp{ops}{o1}) {
    $fp{ops}{o1} =~ s/NULL//;
    print "OPS(O1=$fp{ops}{o1}";
    foreach $num (2 .. 6) {
	$oi = "o$num";
	$fp{ops}{$oi} =~ s/NULL//;
	print "%O$num=$fp{ops}{$oi}";
    }
    print ")\n";
}

# WIN
if ($fp{win}{w1}) {
    $fp{win}{w1} =~ s/NULL/0/;
    print "WIN(W1=$fp{win}{w1}";
    foreach $num (2 .. 6) {
	$wi = "w$num";
	$fp{win}{$wi} =~ s/NULL/0/;
	print "%W$num=$fp{win}{$wi}";
    }
    print ")\n";
}

# ECN
if ($fp{ecn}{resp} eq "Y") {
    print "ECN(R=Y%";
    $fp{ecn}{ttl} =~ s/NULL/0/;
    $fp{ecn}{win} =~ s/NULL/0/;
    $fp{ops}{win} =~ s/NULL//;
    $fp{ecn}{quirk} =~ s/NULL//;
    print "DF=$fp{ecn}{df}%T=$fp{ecn}{ttl}%TG=$fp{ecn}{ttl}%W=$fp{ecn}{win}%O=$fp{ecn}{ops}%CC=$fp{ecn}{cc}%Q=$fp{ecn}{quirk})\n";
} else {
    print "ECN(R=N)\n";
}

# T1-T7
foreach $t (1 .. 7) {
    $test = "T$t";
    if ($fp{$test}{resp} eq "Y") {
	print "$test(R=Y%";
	$fp{$test}{ttl} =~ s/NULL/0/;
	$fp{$test}{win} =~ s/NULL/0/;
	$fp{$test}{flags} =~ s/NULL//;
	$fp{$test}{ops} =~ s/NULL//;
	$fp{$test}{rd} =~ s/NULL/0/;
	$fp{$test}{quirk} =~ s/NULL//;
	if ($t == 1) {
	    print "DF=$fp{$test}{df}%T=$fp{$test}{ttl}%TG=$fp{$test}{ttl}%S=$fp{$test}{seq}%A=$fp{$test}{ack}%F=$fp{$test}{flags}%RD=$fp{$test}{rd}%Q=$fp{$test}{quirk})\n";
	} else {
	    print "DF=$fp{$test}{df}%T=$fp{$test}{ttl}%TG=$fp{$test}{ttl}%W=$fp{$test}{win}%S=$fp{$test}{seq}%A=$fp{$test}{ack}%F=$fp{$test}{flags}%O=$fp{$test}{ops}%RD=$fp{$test}{rd}%Q=$fp{$test}{quirk})\n";
	}
    } else {
	print "$test(R=N)\n";
    }
}

# U1
if ($fp{u1}{resp} eq "Y") {
    print "U1(";
    $fp{u1}{ttl} =~ s/NULL/0/;
    $fp{u1}{tos} =~ s/NULL/0/;
    $fp{u1}{uck} =~ s/NULL/0/;
    $fp{u1}{un} =~ s/NULL/0/;
    $fp{u1}{ripck} =~ s/NULL/0/;
    $fp{u1}{ruck} =~ s/NULL/0/;
    if ($fp{u1}{rid}) {
	$rid = "RID=$fp{u1}{rid}\%";
    } else { $ridwarning = 1; $rid = "RID=G\%"; }
    print "DF=$fp{u1}{df}%T=$fp{u1}{ttl}%TG=$fp{u1}{ttl}%TOS=$fp{u1}{tos}%IPL=$fp{u1}{ipl}%UN=$fp{u1}{un}%RIPL=$fp{u1}{ripl}%${rid}RIPCK=$fp{u1}{ripck}%RUCK=$fp{u1}{ruck}%RUL=$fp{u1}{rul}%RUD=$fp{u1}{rud})\n";
} else {
    print "U1(R=N)\n";    
}

# IE
if ($fp{ie}{resp} eq "Y") {
    print "IE(";
    $fp{ie}{ttl} =~ s/NULL/0/;
    $fp{ie}{tosi} =~ s/NULL/0/;
    print "DFI=$fp{ie}{dfi}%T=$fp{ie}{ttl}%TG=$fp{ie}{ttl}%TOSI=$fp{ie}{tosi}%CD=$fp{ie}{cd}%SI=$fp{ie}{si}%DLI=$fp{ie}{dli})\n";
} else {
    print "IE(R=N)\n";    
}

if ($ridwarning == 1) {
    $ridwarning = 0;
    print "*******************************************************\n" .
	  "* WARNING: Missing U1 RID value -- this is normal for *\n" .
	  "* hosts submitted by Solaris or Windows boxes.  You   *\n" .
	  "* may want to get RID from similar fingerprints       *\n" .
	  "*******************************************************\n";
}
