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

while(<>) {
    chomp;
    $line = $_;

    if ($line eq "." || $line eq "") { last; }
    if (!$line =~ /(Fingerprint\s+\S)|(Class\s+\S)|(^SEQ)|(^OPS)|(^WIN)|(^ECN)|(^T[1-7])|(^U1)|(^IE)|(^Contributed by)/i) { next; }

    if ($line =~ /Contributed by (.*)/) {
		if (!$fp{contrib}) {
			$fp{contrib} = $1;
		} else { $fp{contrib} .= ", $1"; }
    }

    elsif ($line =~ /Fingerprint\s+(.*)/i) {
		$fp{os} = $1;
    }

	elsif ($line =~ /Class\s+(.*)/i) {
		if (!$fp{class} or !($fp{class} =~ /\Q$line\E/)) {
			$fp{class} .= $line . "\n";
		}
    }

    elsif ($line =~ /SEQ\(CL=([^%\)]+)(%SP=([^%]+)%GCD=([^%\)]+))?(%Val=([A-F0-9]+))?(%IPID=([^%\)]+))?(%TS=([^%\)]+))?\)/) {
        $cls = $1;
		if ($cls ne "C") {
			$si = $3;
			$gcd = hex($4);
		} else { $cval=$6; }
        $ipid = $8;
        $ts = $10;
		if (index($fp{tseq}{cls}, $cls) == -1) {
			if ($fp{tseq}{cls}) {
				$fp{tseq}{cls} = $fp{tseq}{cls} . qq^|$cls^;
			} else {
				$fp{tseq}{cls} = $cls;
			}
		}

		if ($cls eq "C") {
			print "*******************************************************\n" .
				"* WARNING: CONSTANT ISN type -- check if value changes*\n" .
				"*******************************************************\n";
			if (index($fp{tseq}{cval}, $cval) == -1) {
				if ($fp{tseq}{cval}) {
					$fp{tseq}{cval} = $fp{tseq}{cval} . qq^|$cval^;
				} else {
					$fp{tseq}{cval} = $cval;
				}
			}
		} else {
			if ($fp{tseq}{gcd} =~ /<([0-9A-F]+)/) {
				$oldgcd = hex($1);
			} else { $oldgcd = 6; }
			
			$newgcd = max($oldgcd, $gcd * 2 + 4);
			$fp{tseq}{gcd} = sprintf ("<%X", $newgcd);
			
			$newhighlim = $newlowlim = -1;
			if ($si =~ /<([0-9A-Fa-f]+)/) { $newhighlim = hex($1); }
			if ($si =~ />([0-9A-Fa-f]+)/) { $newlowlim = hex($1); }
			
			if ($fp{tseq}{si} =~ /<([0-9A-F]+)/) {
				$oldhighlim = hex($1);
			} else { $oldhighlim = 0; }

			if ($fp{tseq}{si} =~ />([0-9A-F]+)/) {
				$oldlowlim = hex($1);
			} else { $oldlowlim = 0; }

			if ($fp{tseq}{si} =~ /^([0-9A-F]+)/) {
				$oldhighlim = $oldlowlim = hex($1);
			}

			if ($oldlowlim) {
				
				if ($newlowlim != -1) { $newlowlim = max(0, min($oldlowlim, $newlowlim)); } 
				else { $newlowlim = max(0, min($oldlowlim, hex($si) / 10 - 20)); }
			} else { if ($newlowlim == -1) { $newlowlim = max(0, hex($si) / 10 - 20); } }
			
			if ($newhighlim == -1) { 
				$newhighlim = max($oldhighlim, hex($si) * 10 + 20);
			} else { $newhighlim = max($oldhighlim, $newhighlim); }
			
#        print "oldhighlim: $oldhighlim oldlowlim: $oldlowlim newhighlim: $newhighlim newlowlim: $newlowlim oldsi: $fp{tseq}{si}";
			if ($newlowlim > 0) {
				$fp{tseq}{si} = sprintf("%X-%X", $newhighlim, $newlowlim);
			} else {
				$fp{tseq}{si} = sprintf("<%X", $newhighlim);
			}
			
#        print " newsi: $fp{tseq}{si}\n";
		}

        if (index($fp{tseq}{ipid}, $ipid) == -1) {
            if ($fp{tseq}{ipid}) {
                $fp{tseq}{ipid} = $fp{tseq}{ipid} . qq^|$ipid^;
            } else {
                $fp{tseq}{ipid} = $ipid;
            }
        }

        if (index($fp{tseq}{ts}, $ts) == -1) {
            if ($fp{tseq}{ts}) {
                $fp{tseq}{ts} = $fp{tseq}{ts} . qq^|$ts^;
            } else {
                $fp{tseq}{ts} = $ts;
            }
        }

    } elsif ($line =~ /^OPS/) {
		$o1 = $o2 = $o3 = $o4 = $o5= $o6 = "";
		if ($line =~ /O1=([0-9A-Z]*)/) {
			$o1 = $1;
			if (!$o1) { $o1 = "NULL"; }
		}
		if ($line =~ /O2=([0-9A-Z]*)/) {
			$o2 = $1;
			if (!$o2) { $o2 = "NULL"; }
		}
		if ($line =~ /O3=([0-9A-Z]*)/) {
			$o3 = $1;
			if (!$o3) { $o3 = "NULL"; }
		}
		if ($line =~ /O4=([0-9A-Z]*)/) {
			$o4 = $1;
			if (!$o4) { $o4 = "NULL"; }
		}
		if ($line =~ /O5=([0-9A-Z]*)/) {
			$o5 = $1;
			if (!$o5) { $o5 = "NULL"; }
		}
		if ($line =~ /O6=([0-9A-Z]*)/) {
			$o6 = $1;
			if (!$o6) { $o6 = "NULL"; }
		}
	} elsif ($line =~ /^WIN/) {
		$w1 = $w2 = $w3 = $w4 = $w5= $w6 = "";
		if ($line =~ /W1=([0-9A-F]+)/) {
			$w1 = $1;
			if (!$w1) { $w1 = "NULL"; }
		}
		if ($line =~ /W2=([0-9A-F]+)/) {
			$w2 = $1;
			if (!$w2) { $w2 = "NULL"; }
		}
		if ($line =~ /W3=([0-9A-F]+)/) {
			$w3 = $1;
			if (!$w3) { $w3 = "NULL"; }
		}
		if ($line =~ /W4=([0-9A-F]+)/) {
			$w4 = $1;
			if (!$w4) { $w4 = "NULL"; }
		}
		if ($line =~ /W5=([0-9A-F]+)/) {
			$w5 = $1;
			if (!$w5) { $w5 = "NULL"; }
		}
		if ($line =~ /W6=([0-9A-F]+)/) {
			$w6 = $1;
			if (!$w6) { $w6 = "NULL"; }
		}
	} elsif ($line =~ /^ECN/) {
		$resp = $df = $ttl = $cc = $quirk = "";

		if ($line =~ /R=([NY])/) {
			$resp = $1;
		}
		if ($line =~ /[(%]DF=([NY])/) {
			$df = $1;
		}
		if ($line =~ /[(%]TG+=([0-9A-F]+)/) {
			$ttl = $1;
		}
		if ($line =~ /[(%]CC=([NY])/) {
			$cc = $1;
		}
		if ($line =~ /[(%]Q=([RU]*)/) {
			$quirk = $1;
		}		
	} elsif ($line =~ /^T1)/) {
		$test = "T1";
		$resp = $df = $ttl = $seq = $ack = $flags = $rd = $quirk = "";

		if ($line =~ /Resp=([NY])/) {
			$resp = $1;
		}
		if ($line =~ /[(%]DF=([NY])/) {
			$df = $1;
		}
		if ($line =~ /[(%]W=([^%]+)/) {
			$w = $1;
			if (!$w) { $w = "NULL"; }
		}
		if ($line =~ /[(%]ACK=([^%]+)/) {
			$ack = $1;
		}
		if ($line =~ /[(%]Flags=([^%]*)/) {
			$flags = $1;
			if (!$flags) { $flags = "NULL"; }
		}
		if ($line =~ /Ops=([A-Z|]*)/) {
			$ops = $1;
			if (!$ops) { $ops = "NULL"; }
		}

		if ($resp eq "Y" or !$resp) {
			$fp{$test}{resp} = "Y";
			if ($df and index($fp{$test}{df}, $df) == -1) {
				if ($fp{$test}{df}) {
					$fp{$test}{df} .= qq^|$df^;
				} else {
					$fp{$test}{df} = $df;
				}
			}

			if (index($fp{$test}{w}, $w) == -1) {
				if ($fp{$test}{w}) {
					$fp{$test}{w} = $fp{$test}{w} . qq^|$w^;
				} else {
					$fp{$test}{w} = $w;
				}
			}

			if ($ack and index($fp{$test}{ack}, $ack) == -1) {
				if ($fp{$test}{ack}) {
					$fp{$test}{ack} = $fp{$test}{ack} . qq^|$ack^;
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

			if (!($fp{$test}{ops} =~ /(^|\|)$ops($|\|)/)) {
				if ($fp{$test}{ops}) {
					$fp{$test}{ops} = $fp{$test}{ops} . qq^|$ops^;
				} else {
					$fp{$test}{ops} = $ops;
				}
			}	    
		} elsif ($fp{$test}{resp} ne "Y") {
			$fp{$test}{resp} = "N";
		}
    } elsif ($line =~ /^T([2-7])/) {
		$num = $1;
		$test = "T$num";
		$resp = $df = $w = $ack = $flags = $ops = "";

		if ($line =~ /Resp=([NY])/) {
			$resp = $1;
		}
		if ($line =~ /[(%]DF=([NY])/) {
			$df = $1;
		}
		if ($line =~ /[(%]W=([^%]+)/) {
			$w = $1;
			if (!$w) { $w = "NULL"; }
		}
		if ($line =~ /[(%]ACK=([^%]+)/) {
			$ack = $1;
		}
		if ($line =~ /[(%]Flags=([^%]*)/) {
			$flags = $1;
			if (!$flags) { $flags = "NULL"; }
		}
		if ($line =~ /Ops=([A-Z|]*)/) {
			$ops = $1;
			if (!$ops) { $ops = "NULL"; }
		}

		if ($resp eq "Y" or !$resp) {
			$fp{$test}{resp} = "Y";
			if ($df and index($fp{$test}{df}, $df) == -1) {
				if ($fp{$test}{df}) {
					$fp{$test}{df} .= qq^|$df^;
				} else {
					$fp{$test}{df} = $df;
				}
			}

			if (index($fp{$test}{w}, $w) == -1) {
				if ($fp{$test}{w}) {
					$fp{$test}{w} = $fp{$test}{w} . qq^|$w^;
				} else {
					$fp{$test}{w} = $w;
				}
			}

			if ($ack and index($fp{$test}{ack}, $ack) == -1) {
				if ($fp{$test}{ack}) {
					$fp{$test}{ack} = $fp{$test}{ack} . qq^|$ack^;
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

			if (!($fp{$test}{ops} =~ /(^|\|)$ops($|\|)/)) {
				if ($fp{$test}{ops}) {
					$fp{$test}{ops} = $fp{$test}{ops} . qq^|$ops^;
				} else {
					$fp{$test}{ops} = $ops;
				}
			}	    
		} elsif ($fp{$test}{resp} ne "Y") {
			$fp{$test}{resp} = "N";
		}
    } elsif ($line =~ /^PU/) {
		$resp = $df = $tos = $iplen = $riptl = $rid = $ripck = $uck = $ulen = $dat = "";

		if ($line =~ /Resp=([NY])/) {
			$resp = $1;
		}
		if ($line =~ /[(%]DF=([NY])/) {
			$df = $1;
		}
		if ($line =~ /[(%]TOS=([^%]+)/) {
			$tos = $1;
			if (!$tos) { $tos = "NULL"; }
		}
		if ($line =~ /[(%]IPLEN=([^%]+)/) {
			$iplen = $1;
		}
		if ($line =~ /[(%]RIPTL=([^%]+)/) {
			$riptl = $1;
		}
		if ($line =~ /[(%]RID=([^%]+)/) {
			$rid = $1;
		}
		if ($line =~ /[(%]RIPCK=([^%]+)/) {
			$ripck = $1;
			if (!$ripck) { $ripck = "NULL"; }
		}
		if ($line =~ /[(%]UCK=([^%]+)/) {
			$uck = $1;
			if (!$uck) { $uck = "NULL"; }
		}
		if ($line =~ /[(%]ULEN=([^%]+)/) {
			$ulen = $1;
		}
		if ($line =~ /[(%]DAT=([A-Z|]+)/) {
			$dat = $1;
		}

		if ($resp eq "Y" or !$resp) {
			$fp{pu}{resp} = "Y";

			if ($df and index($fp{pu}{df}, $df) == -1) {
				if ($fp{pu}{df}) {
					$fp{pu}{df} = $fp{pu}{df} . qq^|$df^;
				} else {
					$fp{pu}{df} = $df;
				}
			}

			if ($tos and index($fp{pu}{tos}, $tos) == -1) {
				if ($fp{pu}{tos}) {
					$fp{pu}{tos} = $fp{pu}{tos} . qq^|$tos^;
				} else {
					$fp{pu}{tos} = $tos;
				}
			}

			if ($iplen and index($fp{pu}{iplen}, $iplen) == -1) {
				if ($fp{pu}{iplen}) {
					$fp{pu}{iplen} = $fp{pu}{iplen} . qq^|$iplen^;
				} else {
					$fp{pu}{iplen} = $iplen;
				}
			}


			if ($riptl and index($fp{pu}{riptl}, $riptl) == -1) {
				if ($fp{pu}{riptl}) {
					$fp{pu}{riptl} = $fp{pu}{riptl} . qq^|$riptl^;
				} else {
					$fp{pu}{riptl} = $riptl;
				}
			}

			if ($rid and index($fp{pu}{rid}, $rid) == -1) {
				if ($fp{pu}{rid}) {
					$fp{pu}{rid} = $fp{pu}{rid} . qq^|$rid^;
				} else {
					$fp{pu}{rid} = $rid;
				}
			}


			if ($ripck and index($fp{pu}{ripck}, $ripck) == -1) {
				if ($fp{pu}{ripck}) {
					$fp{pu}{ripck} = $fp{pu}{ripck} . qq^|$ripck^;
				} else {
					$fp{pu}{ripck} = $ripck;
				}
			}


			if ($uck and index($fp{pu}{uck}, $uck) == -1) {
				if ($fp{pu}{uck}) {
					$fp{pu}{uck} = $fp{pu}{uck} . qq^|$uck^;
				} else {
					$fp{pu}{uck} = $uck;
				}
			}

			if ($ulen and index($fp{pu}{ulen}, $ulen) == -1) {
				if ($fp{pu}{ulen}) {
					$fp{pu}{ulen} = $fp{pu}{ulen} . qq^|$ulen^;
				} else {
					$fp{pu}{ulen} = $ulen;
				}
			}


			if ($dat and index($fp{pu}{dat}, $dat) == -1) {
				if ($fp{pu}{dat}) {
					$fp{pu}{dat} = $fp{pu}{dat} . qq^|$dat^;
				} else {
					$fp{pu}{dat} = $dat;
				}
			}

		} elsif ($fp{pu}{resp} ne "Y") {
			$fp{pu}{resp} = "N";
		}
    }       
}


# OK, now it is time to print out the merged Fprint ...

# Printing contributed by line was like a magnet for spammers and took
# up a substantial amount of space in the file.  Plus may make
# licensees nervous.
# if ($fp{contrib}) { print "# Contributed by $fp{contrib}\n"; }
print "Fingerprint $fp{os}\n";
if ($fp{class}) { print $fp{class}; }
else { print "Class \n"; }

if ($fp{tseq}{cls}) {
    print("TSeq(Class=$fp{tseq}{cls}");
    if ($fp{tseq}{cls} ne "64K" and $fp{tseq}{cls} ne "i800" 
		and $fp{tseq}{cls} ne "C") {
		if ($fp{tseq}{gcd}) {
			print "%gcd=$fp{tseq}{gcd}";
		}
		if ($fp{tseq}{cls} ne "TR") {
			if ($fp{tseq}{si}) {
				print "%SI=$fp{tseq}{si}";
			}
		}
    }
    if ($fp{tseq}{cval}) {print "%Val=$fp{tseq}{cval}"; }
    if ($fp{tseq}{ipid}) { print "%IPID=$fp{tseq}{ipid}"; }
    if ($fp{tseq}{ts}) { print "%TS=$fp{tseq}{ts}"; }
    print ")\n";
}

foreach $t (1 .. 7) {
    $test = "T$t";
    if ($fp{$test}{resp} eq "Y") {
		print "$test(";
		if ($t == 2 or $t == 3) {
			print "Resp=Y%";
		}
		$fp{$test}{flags} =~ s/NULL//;
		$fp{$test}{ops} =~ s/NULL//;
		$fp{$test}{w} =~ s/NULL/0/;
		print "DF=$fp{$test}{df}%W=$fp{$test}{w}%ACK=$fp{$test}{ack}%Flags=$fp{$test}{flags}%Ops=$fp{$test}{ops})\n";
    } else {
		print "$test(Resp=N)\n";
    }
}

if ($fp{pu}{resp} eq "Y") {
    print "PU(";
    $fp{pu}{tos} =~ s/NULL/0/;
    $fp{pu}{uck} =~ s/NULL/0/;
    $fp{pu}{ripck} =~ s/NULL/0/;
    if ($fp{pu}{rid}) {
		$rid = "RID=$fp{pu}{rid}\%";
    } else { $ridwarning = 1; $rid = "RID=G\%"; }
    print "DF=$fp{pu}{df}%TOS=$fp{pu}{tos}%IPLEN=$fp{pu}{iplen}%RIPTL=$fp{pu}{riptl}%${rid}RIPCK=$fp{pu}{ripck}%UCK=$fp{pu}{uck}%ULEN=$fp{pu}{ulen}%DAT=$fp{pu}{dat})\n";
} else {
    print "PU(Resp=N)\n";    
}

if ($ridwarning == 1) {
    $ridwarning = 0;
    print "*******************************************************\n" .
		"* WARNING: Missing PU RID value -- this is normal for *\n" .
		"* hosts submitted by Solaris or Windows boxes.  You   *\n" .
		"* may want to get RID from similar fingerprints       *\n" .
		"*******************************************************\n";
}
