#!/usr/bin/perl -w

# This file contains tests of the external behavior of Ncat.

require HTTP::Response;
require HTTP::Request;

use MIME::Base64;
use File::Temp qw/ tempfile /;
use URI::Escape;
use Data::Dumper;
use Socket;
use Socket6;
use Digest::MD5 qw/md5_hex/;
use POSIX ":sys_wait_h";
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);

use IPC::Open3;
use strict;

$| = 1;

my $HOST = "127.0.0.1";
my $IPV6_ADDR = "::1";
my $PORT = 40000;
my $PROXY_PORT = 40001;
my $UNIXSOCK = "ncat.unixsock";
my $UNIXSOCK_TMP = "ncat.unixsock_tmp";

my $WIN32 = $^O eq "MSWin32" || $^O eq "cygwin";

my $NCAT;
if ($WIN32) {
	$NCAT = "../Debug/ncat.exe";
} else {
	$NCAT = "../ncat";
}

my $HAVE_SCTP = !$WIN32;
my $HAVE_UNIXSOCK = !$WIN32;

my $BUFSIZ = 1024;

my $num_tests = 0;
my $num_failures = 0;
my $num_expected_failures = 0;
my $num_unexpected_passes = 0;

# If true during a test, failure is expected (XFAIL).
our $xfail = 0;

# Run $NCAT with the given arguments.
sub ncat {
	my $pid;
	local *IN;
	local *OUT;
	local *ERR;
	# print join(" ", ($NCAT, @_)) . "\n";
	$pid = open3(*IN, *OUT, *ERR, $NCAT, @_);
	if (!defined $pid) {
		die "open3 failed";
	}
	binmode *IN;
	binmode *OUT;
	binmode *ERR;
	return ($pid, *OUT, *IN, *ERR);
}

sub wait_listen {
	my $fh = shift;
	my $timeout = shift || 0.3;
	my $rd = "";
	vec($rd, fileno($fh), 1) = 1;
	my $partial = "";
	for (;;) {
		my ($n, $frag);
		($n, $timeout) = select($rd, undef, undef, $timeout);
		last if $n == 0;
		$n = sysread($fh, $frag, $BUFSIZ);
		last if (not defined($n)) || $n == 0;
		$partial = $partial . $frag;
		while ($partial =~ /^(.*?)\n(.*)$/s) {
			my $line = $1;
			$partial = $2;
			if ($line =~ /^NCAT TEST: LISTEN/) {
				return;
			}
		}
	}
}

sub ncat_server {
	my @ret = ncat($PORT, "--test", "-l", @_);
	wait_listen($ret[3]);
	return @ret;
}

sub host_for_args {
	if (grep(/^-[^-]*6/, @_)) {
		return "::1";
	} else {
		return "127.0.0.1";
	}
}

sub ncat_client {
	my $host;
	my @ret = ncat(host_for_args(@_), $PORT, @_);
	# Give it a moment to connect.
	select(undef, undef, undef, 0.1);
	return @ret;
}

# Kill all child processes.
sub kill_children {
	local $SIG{TERM} = "IGNORE";
	kill "TERM", -$$;
	while (waitpid(-1, 0) > 0) {
	}
}

# Read until a timeout occurs. Return undef on EOF or "" on timeout.
sub timeout_read {
	my $fh = shift;
	my $timeout = 0.50;
	if (scalar(@_) > 0) {
		$timeout = shift;
	}
	my $result = "";
	my $rd = "";
	my $frag;
	vec($rd, fileno($fh), 1) = 1;
	# Here we rely on $timeout being decremented after select returns,
	# which may not be supported on all systems.
	while (select($rd, undef, undef, $timeout) != 0) {
		return ($result or undef) if sysread($fh, $frag, $BUFSIZ) == 0;
		$result .= $frag;
	}
	return $result;
}

$Data::Dumper::Terse = 1;
$Data::Dumper::Useqq = 1;
$Data::Dumper::Indent = 0;
sub d {
	return Dumper(@_);
}

# Run the code reference received as an argument. Count it as a pass if the
# evaluation is successful, a failure otherwise.
sub test {
	my $desc = shift;
	my $code = shift;
	$num_tests++;
	if (eval { &$code() }) {
		if ($xfail) {
			print "UNEXPECTED PASS $desc\n";
			$num_unexpected_passes++;
		} else {
			print "PASS $desc\n";
		}
	} else {
		if ($xfail) {
			print "XFAIL $desc\n";
			$num_expected_failures++;
		} else {
			$num_failures++;
			print "FAIL $desc\n";
			print "     $@";
		}
	}
}

my ($s_pid, $s_out, $s_in, $c_pid, $c_out, $c_in, $p_pid, $p_out, $p_in);

# Handle a common test situation. Start up a server and client with the given
# arguments and call test on a code block. Within the code block the server's
# PID, output filehandle, and input filehandle are accessible through
#   $s_pid, $s_out, and $s_in
# and likewise for the client:
#   $c_pid, $c_out, and $c_in.
sub server_client_test {
	my $desc = shift;
	my $server_args = shift;
	my $client_args = shift;
	my $code = shift;
	($s_pid, $s_out, $s_in) = ncat_server(@$server_args);
	($c_pid, $c_out, $c_in) = ncat_client(@$client_args);
	test($desc, $code);
	kill_children;
}

sub server_client_test_multi {
	my $specs = shift;
	my $desc = shift;
	my $server_args_ref = shift;
	my $client_args_ref = shift;
	my $code = shift;
	my $outer_xfail = $xfail;

	for my $spec (@$specs) {
		my @server_args = @$server_args_ref;
		my @client_args = @$client_args_ref;

		local $xfail = $outer_xfail;
		for my $proto (split(/ /, $spec)) {
			if ($proto eq "tcp") {
				# Nothing needed.
			} elsif ($proto eq "udp") {
				push @server_args, ("--udp");
				push @client_args, ("--udp");
			} elsif ($proto eq "sctp") {
				push @server_args, ("--sctp");
				push @client_args, ("--sctp");
				$xfail = 1 if !$HAVE_SCTP;
			} elsif ($proto eq "ssl") {
				push @server_args, ("--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem");
				push @client_args, ("--ssl");
			} elsif ($proto eq "xfail") {
				$xfail = 1;
			} else {
				die "Unknown protocol $proto";
			}
		}
		server_client_test("$desc ($spec)", [@server_args], [@client_args], $code);
	}
}

# Like server_client_test, but run the test once each for each mix of TCP, UDP,
# SCTP, and SSL.
sub server_client_test_all {
	server_client_test_multi(["tcp", "udp", "sctp", "tcp ssl", "sctp ssl"], @_);
}

sub server_client_test_tcp_sctp_ssl {
	server_client_test_multi(["tcp", "sctp", "tcp ssl", "sctp ssl"], @_);
}

sub server_client_test_tcp_ssl {
	server_client_test_multi(["tcp", "tcp ssl"], @_);
}

sub server_client_test_sctp_ssl {
	server_client_test_multi(["sctp", "sctp ssl"], @_);
}

# Set up a proxy running on $PROXY_PORT. Start a server on $PORT and connect a
# client to the server through the proxy. The proxy is controlled through the
# variables
#   $p_pid, $p_out, and $p_in.
sub proxy_test {
	my $desc = shift;
	my $proxy_args = shift;
	my $server_args = shift;
	my $client_args = shift;
	my $code = shift;
	($p_pid, $p_out, $p_in) = ncat(host_for_args(@$proxy_args), ($PROXY_PORT, "-l", "--proxy-type", "http"), @$proxy_args);
	($s_pid, $s_out, $s_in) = ncat(host_for_args(@$server_args), ($PORT, "-l"), @$server_args);
	($c_pid, $c_out, $c_in) = ncat(host_for_args(@$client_args), ($PORT, "--proxy", "$HOST:$PROXY_PORT"), @$client_args);
	test($desc, $code);
	kill_children;
}

# Like proxy_test, but connect the client directly to the proxy so you can
# control the proxy interaction.
sub proxy_test_raw {
	my $desc = shift;
	my $proxy_args = shift;
	my $server_args = shift;
	my $client_args = shift;
	my $code = shift;
	($p_pid, $p_out, $p_in) = ncat(host_for_args(@$proxy_args), ($PROXY_PORT, "-l", "--proxy-type", "http"), @$proxy_args);
	($s_pid, $s_out, $s_in) = ncat(host_for_args(@$server_args), ($PORT, "-l"), @$server_args);
	($c_pid, $c_out, $c_in) = ncat(host_for_args(@$client_args), ($PROXY_PORT), @$client_args);
	test($desc, $code);
	kill_children;
}

sub proxy_test_multi {
	my $specs = shift;
	my $desc = shift;
	my $proxy_args_ref = shift;
	my $server_args_ref = shift;
	my $client_args_ref = shift;
	my $code = shift;
	my $outer_xfail = $xfail;
	local $xfail;

	for my $spec (@$specs) {
		my @proxy_args = @$proxy_args_ref;
		my @server_args = @$server_args_ref;
		my @client_args = @$client_args_ref;

		$xfail = $outer_xfail;
		for my $proto (split(/ /, $spec)) {
			if ($proto eq "tcp") {
				# Nothing needed.
			} elsif ($proto eq "udp") {
				push @server_args, ("--udp");
				push @client_args, ("--udp");
			} elsif ($proto eq "sctp") {
				push @server_args, ("--sctp");
				push @client_args, ("--sctp");
			} elsif ($proto eq "ssl") {
				push @server_args, ("--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem");
				push @client_args, ("--ssl");
			} elsif ($proto eq "xfail") {
				$xfail = 1;
			} else {
				die "Unknown protocol $proto";
			}
		}
		proxy_test("$desc ($spec)", [@proxy_args], [@server_args], [@client_args], $code);
	}
}

sub max_conns_test {
	my $desc = shift;
	my $server_args = shift;
	my $client_args = shift;
	my $count = shift;
	my @client_pids;
	my @client_outs;
	my @client_ins;

	($s_pid, $s_out, $s_in) = ncat_server(@$server_args, ("--max-conns", $count));
	test $desc, sub {
		my ($i, $resp);

		# Fill the connection limit exactly.
		for ($i = 0; $i < $count; $i++) {
			my @tmp;
			($c_pid, $c_out, $c_in) = ncat_client(@$client_args);
			push @client_pids, $c_pid;
			push @client_outs, $c_out;
			push @client_ins, $c_in;
			syswrite($c_in, "abc\n");
			$resp = timeout_read($s_out, 2.0);
			if (!$resp) {
				syswrite($s_in, "abc\n");
				$resp = timeout_read($c_out);
			}
			$resp = "" if not defined($resp);
			$resp eq "abc\n" or die "--max-conns $count server did not accept client #" . ($i + 1);
		}
		# Try a few more times. Should be rejected.
		for (; $i < $count + 2; $i++) {
			($c_pid, $c_out, $c_in) = ncat_client(@$client_args);
			push @client_pids, $c_pid;
			push @client_outs, $c_out;
			push @client_ins, $c_in;
			syswrite($c_in, "abc\n");
			$resp = timeout_read($s_out, 2.0);
			if (!$resp) {
				syswrite($s_in, "abc\n");
				$resp = timeout_read($c_out);
			}
			!$resp or die "--max-conns $count server accepted client #" . ($i + 1);
		}
		# Kill one of the connected clients, which should open up a
		# space.
		{
			kill "TERM", $client_pids[0];
			while (waitpid($client_pids[0], 0) > 0) {
			}
			shift @client_pids;
			shift @client_outs;
			sleep 2;
		}
		if ($count > 0) {
			($c_pid, $c_out, $c_in) = ncat_client(@$client_args);
			push @client_pids, $c_pid;
			push @client_outs, $c_out;
			push @client_ins, $c_in;
			syswrite($c_in, "abc\n");
			$resp = timeout_read($s_out, 2.0);
			if (!$resp) {
				syswrite($s_in, "abc\n");
				$resp = timeout_read($c_out);
			}
			$resp = "" if not defined($resp);
			$resp eq "abc\n" or die "--max-conns $count server did not accept client #$count after freeing one space";
		}
		return 1;
	};
	kill_children;
}

sub max_conns_test_multi {
	my $specs = shift;
	my $desc = shift;
	my $server_args_ref = shift;
	my $client_args_ref = shift;
	my $count = shift;
	my $outer_xfail = $xfail;
	local $xfail;

	for my $spec (@$specs) {
		my @server_args = @$server_args_ref;
		my @client_args = @$client_args_ref;

		$xfail = $outer_xfail;
		for my $proto (split(/ /, $spec)) {
			if ($proto eq "tcp") {
				# Nothing needed.
			} elsif ($proto eq "udp") {
				push @server_args, ("--udp");
				push @client_args, ("--udp");
			} elsif ($proto eq "sctp") {
				push @server_args, ("--sctp");
				push @client_args, ("--sctp");
			} elsif ($proto eq "ssl") {
				push @server_args, ("--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem");
				push @client_args, ("--ssl");
			} elsif ($proto eq "xfail") {
				$xfail = 1;
			} else {
				die "Unknown protocol $proto";
			}
		}
		max_conns_test("$desc ($spec)", [@server_args], [@client_args], $count);
	}
}

sub max_conns_test_all {
	max_conns_test_multi(["tcp", "udp", "sctp", "tcp ssl", "sctp ssl"], @_);
}

sub max_conns_test_tcp_sctp_ssl {
	max_conns_test_multi(["tcp", "sctp", "tcp ssl", "sctp ssl"], @_);
}

sub max_conns_test_tcp_ssl {
	max_conns_test_multi(["tcp", "tcp ssl"], @_);
}

sub match_ncat_environment {
	$_ = shift;
	return /NCAT_REMOTE_ADDR=.+\n
			NCAT_REMOTE_PORT=.+\n
			NCAT_LOCAL_ADDR=.+\n
			NCAT_LOCAL_PORT=.+\n
			NCAT_PROTO=.+
	/x;
}

# Ignore broken pipe signals that result when trying to read from a terminated
# client.
$SIG{PIPE} = "IGNORE";
# Don't have to wait on children.
$SIG{CHLD} = "IGNORE";

# Individual tests begin here.

# Test server with no hostname or port.
($s_pid, $s_out, $s_in) = ncat("-lk");
test "Server default listen address and port",
sub {
	my $resp;

	my ($c_pid, $c_out, $c_in) = ncat("127.0.0.1");
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";

	my ($c_pid2, $c_out2, $c_in2) = ncat("-6", "::1");
	syswrite($c_in2, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat("-4", "-lk");
test "Server -4 default listen address and port",
sub {
	my $resp;

	my ($c_pid, $c_out, $c_in) = ncat("127.0.0.1");
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat("-6", "-lk");
test "Server -6 default listen address and port",
sub {
	my $resp;

	my ($c_pid, $c_out, $c_in) = ncat("-6", $IPV6_ADDR);
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;

# Test server with no hostname.
($s_pid, $s_out, $s_in) = ncat("-l", $HOST);
test "Server default port",
sub {
	my $resp;

	my ($c_pid, $c_out, $c_in) = ncat($HOST);
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;

# Test server with no port.
($s_pid, $s_out, $s_in) = ncat("-l", $PORT);
test "Server default listen address",
sub {
	my $resp;

	my ($c_pid, $c_out, $c_in) = ncat($HOST, $PORT);
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;

# Test server with UDP.
($s_pid, $s_out, $s_in) = ncat("-l", "--udp");
test "Server default listen address --udp IPV4",
sub {
	my $resp;

	my ($c_pid, $c_out, $c_in) = ncat("localhost", "--udp");
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\" from localhost";

};
kill_children;

($s_pid, $s_out, $s_in) = ncat("-l", "--udp");
test "Server default listen address --udp IPV6",
sub {
	my $resp;

	my ($c_pid1, $c_out1, $c_in1) = ncat("::1", "--udp");
	syswrite($c_in1, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\" from ::1";
};
kill_children;

{
local $xfail = 1;
($s_pid, $s_out, $s_in) = ncat("-l", "--udp");
test "Server default listen address --udp IPV4 + IPV6",
sub {
	my $resp;

	my ($c_pid, $c_out, $c_in) = ncat("localhost", "--udp");
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\" from localhost";

	my ($c_pid1, $c_out1, $c_in1) = ncat("::1", "--udp");
	syswrite($c_in1, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\" from ::1";
};
kill_children;
};

($s_pid, $s_out, $s_in) = ncat("-l", "-6", "--udp");
test "Server default listen address -6 --udp",
sub {
	my $resp;

	my ($c_pid, $c_out, $c_in) = ncat("127.0.0.1", "--udp");
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server got \"$resp\", not \"\" from 127.0.0.1";

	my ($c_pid1, $c_out1, $c_in1) = ncat("::1", "--udp");
	syswrite($c_in1, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\" from ::1";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat("-l", "-4", "--udp");
test "Server default listen address -4 --udp",
sub {
	my $resp;

	my ($c_pid, $c_out, $c_in) = ncat("127.0.0.1", "--udp");
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\" from 127.0.0.1";

	my ($c_pid1, $c_out1, $c_in1) = ncat("::1", "--udp");
	syswrite($c_in1, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server got \"$resp\", not \"\" from ::1";
};
kill_children;

# Test UNIX domain sockets listening
{
local $xfail = 1 if !$HAVE_UNIXSOCK;
($s_pid, $s_out, $s_in) = ncat("-l", "-U", $UNIXSOCK);
test "Server UNIX socket listen on $UNIXSOCK (STREAM)",
sub {
	my $resp;

	unlink($UNIXSOCK);
	my ($c_pid, $c_out, $c_in) = ncat("-U", $UNIXSOCK);
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\" from client";
};
kill_children;
unlink($UNIXSOCK);
}

{
local $xfail = 1 if !$HAVE_UNIXSOCK;
($s_pid, $s_out, $s_in) = ncat("-l", "-U", "--udp", $UNIXSOCK);
test "Server UNIX socket listen on $UNIXSOCK --udp (DGRAM)",
sub {
	my $resp;

	unlink($UNIXSOCK);
	my ($c_pid, $c_out, $c_in) = ncat("-U", "--udp", $UNIXSOCK);
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\" from client";
};
kill_children;
unlink($UNIXSOCK);
}

server_client_test "Connect success exit code",
[], ["--send-only"], sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };

	syswrite($c_in, "abc\n");
	close($c_in);
	do {
		$pid = waitpid($c_pid, 0);
	} while ($pid > 0 && $pid != $c_pid);
	$pid == $c_pid or die;
	$code = $? >> 8;
	$code == 0 or die "Exit code was $code, not 0";
};
kill_children;

test "Connect connection refused exit code",
sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };

	my ($c_pid, $c_out, $c_in) = ncat($HOST, $PORT, "--send-only");
	syswrite($c_in, "abc\n");
	close($c_in);
	do {
		$pid = waitpid($c_pid, 0);
	} while ($pid > 0 && $pid != $c_pid);
	$pid == $c_pid or die;
	$code = $? >> 8;
	$code == 1 or die "Exit code was $code, not 1";
};
kill_children;

test "Connect connection interrupted exit code",
sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };
	local *SOCK;
	local *S;

	socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die;
	setsockopt(SOCK, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or die;
	bind(SOCK, sockaddr_in($PORT, INADDR_ANY)) or die;
	listen(SOCK, 1) or die;

	my ($c_pid, $c_out, $c_in) = ncat($HOST, $PORT);

	accept(S, SOCK) or die;
	# Shut down the socket with a RST.
	setsockopt(S, SOL_SOCKET, SO_LINGER, pack("II", 1, 0)) or die;
	close(S) or die;

	do {
		$pid = waitpid($c_pid, 0);
	} while ($pid > 0 && $pid != $c_pid);
	$pid == $c_pid or die;
	$code = $? >> 8;
	$code == 1 or die "Exit code was $code, not 1";
};
kill_children;

server_client_test "Listen success exit code",
[], ["--send-only"], sub {
	my ($resp, $pid, $code);
	local $SIG{CHLD} = sub { };

	syswrite($c_in, "abc\n");
	close($c_in);
	do {
		$pid = waitpid($s_pid, 0);
	} while ($pid > 0 && $pid != $s_pid);
	$pid == $s_pid or die "$pid != $s_pid";
	$code = $? >> 8;
	$code == 0 or die "Exit code was $code, not 0";
};
kill_children;

test "Listen connection interrupted exit code",
sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };
	local *SOCK;

	my ($s_pid, $s_out, $s_in) = ncat_server();

	socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die;
	my $addr = gethostbyname($HOST);
	connect(SOCK, sockaddr_in($PORT, $addr)) or die;
	# Shut down the socket with a RST.
	setsockopt(SOCK, SOL_SOCKET, SO_LINGER, pack("II", 1, 0)) or die;
	close(SOCK) or die;

	do {
		$pid = waitpid($s_pid, 0);
	} while ($pid > 0 && $pid != $s_pid);
	$pid == $s_pid or die;
	$code = $? >> 8;
	$code == 1 or die "Exit code was $code, not 1";
};
kill_children;

test "Program error exit code",
sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };

	my ($c_pid, $c_out, $c_in) = ncat($HOST, $PORT, "--baffle");
	do {
		$pid = waitpid($c_pid, 0);
	} while ($pid > 0 && $pid != $c_pid);
	$pid == $c_pid or die;
	$code = $? >> 8;
	$code == 2 or die "Exit code was $code, not 2";

	my ($s_pid, $s_out, $s_in) = ncat("-l", "--baffle");
	do {
		$pid = waitpid($s_pid, 0);
	} while ($pid > 0 && $pid != $s_pid);
	$pid == $s_pid or die;
	$code = $? >> 8;
	$code == 2 or die "Exit code was $code, not 2";
};
kill_children;

server_client_test_all "Messages are logged to output file",
["--output", "server.log"], ["--output", "client.log"], sub {

	syswrite($c_in, "abc\n");
	sleep 1;
	syswrite($s_in, "def\n");
	sleep 1;
	close($c_in);
	open(FH, "server.log");
	binmode FH;
	my $contents = join("", <FH>);
	close(FH);
	$contents eq "abc\ndef\n" or die "Server logged " . d($contents);
	open(FH, "client.log");
	binmode FH;
	$contents = join("", <FH>);
	close(FH);
	$contents eq "abc\ndef\n" or die "Client logged " . d($contents);
};
unlink "server.log";
unlink "client.log";
kill_children;

server_client_test_tcp_sctp_ssl "Debug messages go to stderr",
["-vvv"], ["-vvv"], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;

{
local $xfail = 1;
server_client_test_tcp_ssl "Client closes socket write and keeps running after stdin EOF",
[], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";

	close($c_in);

	$resp = timeout_read($s_out);
	!defined($resp) or die "Server didn't get EOF (got \"$resp\")";
	sleep 1;
	waitpid($c_pid, WNOHANG) != -1 or die "Client stopped running";
};
kill_children;
}

server_client_test_tcp_ssl "--send-only client closes socket write and stops running after stdin EOF",
[], ["--send-only"], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";

	close($c_in);

	$resp = timeout_read($s_out);
	!defined($resp) or die "Server didn't get EOF (got \"$resp\")";
	sleep 1;
	waitpid($c_pid, WNOHANG) == -1 or die "Client still running";
};
kill_children;

server_client_test_tcp_ssl "Server closes socket write and keeps running after stdin EOF",
[], [], sub {
	my $resp;

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "abc\n" or die "Client got \"$resp\", not \"abc\\n\"";

	close($s_in);

	$resp = timeout_read($c_out);
	!defined($resp) or die "Client didn't get EOF (got \"$resp\")";
	sleep 1;
	waitpid($s_pid, WNOHANG) != -1 or die "Server stopped running";
};
kill_children;

server_client_test_tcp_ssl "--send-only server closes socket write and stops running after stdin EOF",
["--send-only"], [], sub {
	my $resp;

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "abc\n" or die "Client got \"$resp\", not \"abc\\n\"";

	close($s_in);

	$resp = timeout_read($c_out);
	!defined($resp) or die "Client didn't get EOF (got \"$resp\")";
	sleep 1;
	waitpid($s_pid, WNOHANG) == -1 or die "Server still running";
};
kill_children;

server_client_test_tcp_ssl "Client closes stdout and keeps running after socket EOF",
[], [], sub {
	my $resp;

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "abc\n" or die "Client got \"$resp\", not \"abc\\n\"";

	close($s_in);

	$resp = timeout_read($c_out);
	!defined($resp) or die "Client didn't get EOF and didn't exit (got \"$resp\")";
	sleep 1;
	waitpid($c_pid, WNOHANG) != -1 or die "Client stopped running";
};
kill_children;

# SCTP doesn't have half-open sockets, so the program should exit.
# http://seclists.org/nmap-dev/2013/q1/203
server_client_test_sctp_ssl "Client closes stdout and stops running after socket EOF",
[], [], sub {
	my $resp;

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "abc\n" or die "Client got \"$resp\", not \"abc\\n\"";

	close($s_in);

	$resp = timeout_read($c_out);
	!defined($resp) or die "Client didn't get EOF and didn't exit (got \"$resp\")";
	sleep 1;
	waitpid($c_pid, WNOHANG) == -1 or die "Client still running";
};
kill_children;

server_client_test_tcp_sctp_ssl "--recv-only client closes stdout and stops running after socket EOF",
[], ["--recv-only"], sub {
	my $resp;

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "abc\n" or die "Client got \"$resp\", not \"abc\\n\"";

	close($s_in);

	$resp = timeout_read($c_out);
	!defined($resp) or die "Client didn't get EOF and didn't exit (got \"$resp\")";
	sleep 1;
	waitpid($c_pid, WNOHANG) == -1 or die "Client still running";
};
kill_children;

# Test that the server closes its output stream after a client disconnects.
# This is for uses like
#   ncat -l | tar xzvf -
#   tar czf - <files> | ncat localhost --send-only
# where tar on the listening side could be any program that potentially buffers
# its input. The listener must close its standard output so the program knows
# to stop reading and process what remains in its buffer.
{
# XFAIL because of http://seclists.org/nmap-dev/2013/q1/227. The "close stdout"
# part works, but not the "server keeps running" part.
local $xfail = 1;
server_client_test_tcp_ssl "Server closes stdout and keeps running after socket EOF",
[], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";

	close($c_in);

	$resp = timeout_read($s_out);
	!defined($resp) or die "Server didn't send EOF";
	sleep 1;
	waitpid($s_pid, WNOHANG) != -1 or die "Server stopped running";
};
kill_children;
}

server_client_test_sctp_ssl "Server closes stdout and stops running after socket EOF",
[], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";

	close($c_in);

	$resp = timeout_read($s_out);
	!defined($resp) or die "Server didn't send EOF";
	sleep 1;
	waitpid($s_pid, WNOHANG) == -1 or die "Server still running";
};
kill_children;

server_client_test_tcp_sctp_ssl "--recv-only server closes stdout and stops running after socket EOF",
["--recv-only"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";

	close($c_in);

	$resp = timeout_read($s_out);
	!defined($resp) or die "Server didn't send EOF";
	sleep 1;
	waitpid($s_pid, WNOHANG) == -1 or die "Server still running";
};
kill_children;

# Tests to check that server defaults to non-persistent without --keep-open.

# Server immediately quits after the first connection closed without --keep-open
($s_pid, $s_out, $s_in) = ncat_server();
test "Server quits without --keep-open",
sub {
	my $resp;

	my ($c_pid, $c_out, $c_in) = ncat_client();
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
	kill "TERM", $c_pid;
	while (waitpid($c_pid, 0) > 0) {
	}
	sleep 1;
	# -1 because children are automatically reaped; 0 means it's still running.
	waitpid($s_pid, WNOHANG) == -1 or die "Server still running";
};
kill_children;

# Server with --exec immediately quits after the first connection closed without --keep-open
($s_pid, $s_out, $s_in) = ncat_server("--exec", "/bin/cat");
test "Server with --exec quits without --keep-open",
sub {
	my $resp;

	my ($c_pid, $c_out, $c_in) = ncat_client();
	syswrite($c_in, "abc\n");
	$resp = timeout_read($c_out);
	$resp eq "abc\n" or die "Client got back \"$resp\", not \"abc\\n\"";
	kill "TERM", $c_pid;
	while (waitpid($c_pid, 0) > 0) {
	}
	sleep 1;
	waitpid($s_pid, WNOHANG) == -1 or die "Server still running";
};
kill_children;

# Server immediately quits after the first connection ssl negotiation fails without --keep-open
{
($s_pid, $s_out, $s_in) = ncat_server("--ssl");
test "Server quits after a failed ssl negotiation without --keep-open",
sub {
	my $resp;

	# Let's sleep for one second here, since in some cases the server might not
	# get the chance to start listening before the client tries to connect.
	sleep 1;

	my ($c_pid, $c_out, $c_in) = ncat_client();
	syswrite($c_in, "abc\n");

	kill "TERM", $c_pid;
	while (waitpid($c_pid, 0) > 0) {
	}
	sleep 1;
	# -1 because children are automatically reaped; 0 means it's still running.
	waitpid($s_pid, WNOHANG) == -1 or die "Server still running";
};
kill_children;
}

# Server does not accept multiple connections without --keep-open
($s_pid, $s_out, $s_in) = ncat_server();
test "Server does not accept multiple conns. without --keep-open",
sub {
	my ($c1_pid, $c1_out, $c1_in) = ncat_client();
	my ($c2_pid, $c2_out, $c2_in) = ncat_client();

	sleep 1;

	waitpid($c2_pid, WNOHANG) == -1 or die "A second client could connect to the server";

};
kill_children;

# Test server persistence with --keep-open.

($s_pid, $s_out, $s_in) = ncat_server("--keep-open");
test "--keep-open",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client();
	syswrite($c1_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";

	my ($c2_pid, $c2_out, $c2_in) = ncat_client();
	syswrite($c2_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--keep-open", "--exec", "/bin/cat");
test "--keep-open --exec",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client();
	syswrite($c1_in, "abc\n");
	$resp = timeout_read($c1_out);
	$resp eq "abc\n" or die "Client 1 got back \"$resp\", not \"abc\\n\"";

	my ($c2_pid, $c2_out, $c2_in) = ncat_client();
	syswrite($c2_in, "abc\n");
	$resp = timeout_read($c2_out);
	$resp eq "abc\n" or die "Client 2 got back \"$resp\", not \"abc\\n\"";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--keep-open", "--udp", "--exec", "/bin/cat");
test "--keep-open --exec (udp)",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client("--udp");
	syswrite($c1_in, "abc\n");
	$resp = timeout_read($c1_out);
	$resp eq "abc\n" or die "Client 1 got back \"$resp\", not \"abc\\n\"";

	my ($c2_pid, $c2_out, $c2_in) = ncat_client("--udp");
	syswrite($c2_in, "abc\n");
	$resp = timeout_read($c2_out);
	$resp eq "abc\n" or die "Client 2 got back \"$resp\", not \"abc\\n\"";
};
kill_children;

# Test --exec, --sh-exec and --lua-exec.

server_client_test_all "--exec",
["--exec", "/usr/bin/perl -e \$|=1;while(<>){tr/a-z/A-Z/;print}"], [], sub {
	syswrite($c_in, "abc\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "ABC\n" or die "Client received " . d($resp) . ", not " . d("ABC\n");
};

server_client_test_all "--sh-exec",
["--sh-exec", "perl -e '\$|=1;while(<>){tr/a-z/A-Z/;print}'"], [], sub {
	syswrite($c_in, "abc\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "ABC\n" or die "Client received " . d($resp) . ", not " . d("ABC\n");
};

server_client_test_all "--exec, quits instantly",
["--exec", "/bin/echo abc"], [], sub {
	syswrite($c_in, "test\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "abc\n" or die "Client received " . d($resp) . ", not " . d("abc\n");
};

server_client_test_all "--sh-exec with -C",
["--sh-exec", "/usr/bin/perl -e '\$|=1;while(<>){tr/a-z/A-Z/;print}'", "-C"], [], sub {
	syswrite($c_in, "abc\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "ABC\r\n" or die "Client received " . d($resp) . ", not " . d("ABC\r\n");
};

proxy_test "--exec through proxy",
[], [], ["--exec", "/bin/echo abc"], sub {
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp eq "abc\n" or die "Server received " . d($resp) . ", not " . d("abc\n");
};

server_client_test_all "--lua-exec",
["--lua-exec", "toupper.lua"], [], sub {
	syswrite($c_in, "abc\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "ABC\n" or die "Client received " . d($resp) . ", not " . d("ABC\n");
};

# Test environment variables being set for --exec, --sh-exec and --lua-exec.

server_client_test_all "--exec, environment variables",
["--exec", "/bin/sh test-environment.sh"], [], sub {
	syswrite($c_in, "abc\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	match_ncat_environment($resp) or die "Client received " . d($resp) . ".";
};

server_client_test_all "--sh-exec, environment variables",
["--sh-exec", "sh test-environment.sh"], [], sub {
	syswrite($c_in, "abc\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	match_ncat_environment($resp) or die "Client received " . d($resp) . ".";
};

proxy_test "--exec through proxy, environment variables",
[], [], ["--exec", "/bin/sh test-environment.sh"], sub {
	my $resp = timeout_read($s_out) or die "Read timeout";
	match_ncat_environment($resp) or die "Client received " . d($resp) . ".";
};

server_client_test_all "--lua-exec, environment variables",
["--lua-exec", "test-environment.lua"], [], sub {
	syswrite($c_in, "abc\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	match_ncat_environment($resp) or die "Client received " . d($resp) . ".";
};

# Do a syswrite and then a delay to force separate reads in the subprocess.
sub delaywrite {
	my ($handle, $data) = @_;
	my $delay = 0.1;
	syswrite($handle, $data);
	select(undef, undef, undef, $delay);
}

server_client_test_all "-C translation on input",
["-C"], ["-C"], sub {
	my $resp;
	my $expected = "\r\na\r\nb\r\n---\r\nc\r\nd\r\n---e\r\n\r\nf\r\n---\r\n";

	delaywrite($c_in, "\na\nb\n");
	delaywrite($c_in, "---");
	delaywrite($c_in, "\r\nc\r\nd\r\n");
	delaywrite($c_in, "---");
	delaywrite($c_in, "e\n\nf\n");
	delaywrite($c_in, "---\r");
	delaywrite($c_in, "\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	$resp eq $expected or die "Server received " . d($resp) . ", not " . d($expected);

	delaywrite($s_in, "\na\nb\n");
	delaywrite($s_in, "---");
	delaywrite($s_in, "\r\nc\r\nd\r\n");
	delaywrite($s_in, "---");
	delaywrite($s_in, "e\n\nf\n");
	delaywrite($s_in, "---\r");
	delaywrite($s_in, "\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	$resp eq $expected or die "Client received " . d($resp) . ", not " . d($expected);
};
kill_children;

server_client_test_all "-C server no translation on output",
["-C"], [], sub {
	my $resp;
	my $expected = "\na\nb\n---\r\nc\r\nd\r\n";

	delaywrite($c_in, "\na\nb\n");
	delaywrite($c_in, "---");
	delaywrite($c_in, "\r\nc\r\nd\r\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	$resp eq $expected or die "Server received " . d($resp) . ", not " . d($expected);
};
kill_children;

server_client_test_tcp_sctp_ssl "-C client no translation on output",
[], ["-C"], sub {
	my $resp;
	my $expected = "\na\nb\n---\r\nc\r\nd\r\n";

	delaywrite($s_in, "\na\nb\n");
	delaywrite($s_in, "---");
	delaywrite($s_in, "\r\nc\r\nd\r\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	$resp eq $expected or die "Client received " . d($resp) . ", not " . d($expected);
};
kill_children;

# Test that both reads and writes reset the idle counter, and that the client
# properly exits after the timeout expires.
server_client_test_all "idle timeout (connect mode)",
[], ["-i", "3000ms"], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	sleep 2;
	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	sleep 2;
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	sleep 4;
	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out);
	!$resp or die "Client received \"$resp\" after delay of 4000 ms with idle timeout of 3000 ms."
};

# Test that both reads and writes reset the idle counter, and that the server
# properly exits after the timeout expires.
server_client_test_tcp_sctp_ssl "idle timeout (listen mode)",
["-i", "3000ms"], [], sub {
	my $resp;

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	sleep 2;
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	sleep 2;
	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	sleep 4;
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server received \"$resp\" after delay of 4000 ms with idle timeout of 3000 ms."
};

server_client_test_multi ["udp"], "idle timeout (listen mode)",
["-i", "3000ms"], [], sub {
	my $resp;

	# when using UDP client must at least write something to the server
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out) or die "Server didn't receive the message";

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	sleep 2;
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	sleep 2;
	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	sleep 4;
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server received \"$resp\" after delay of 4000 ms with idle timeout of 3000 ms."
};

# --send-only tests.

server_client_test_all "--send-only client",
[], ["--send-only"], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out);
	!$resp or die "Client received \"$resp\" in --send-only mode";
};

server_client_test_all "--send-only server",
["--send-only"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server received \"$resp\" in --send-only mode";

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Client got \"$resp\", not \"abc\\n\"";
};

($s_pid, $s_out, $s_in) = ncat_server("--broker", "--send-only");
test "--send-only broker",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client();
	my ($c2_pid, $c2_out, $c2_in) = ncat_client();

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c1_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Client got \"$resp\", not \"abc\\n\"";
	$resp = timeout_read($c2_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Client got \"$resp\", not \"abc\\n\"";

	syswrite($c1_in, "abc\n");
	$resp = timeout_read($c2_out);
	!$resp or die "--send-only broker relayed \"$resp\"";
};
kill_children;

# --recv-only tests.

# Note this test excludes UDP. The --recv-only UDP client never sends anything
# to the server, so the server never knows to start sending its data.
server_client_test_tcp_sctp_ssl "--recv-only client",
[], ["--recv-only"], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server received \"$resp\" from --recv-only client";

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Client got \"$resp\", not \"abc\\n\"";
};

server_client_test_all "--recv-only server",
["--recv-only"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out);
	!$resp or die "Client received \"$resp\" from --recv-only server";
};

($s_pid, $s_out, $s_in) = ncat_server("--broker", "--recv-only");
test "--recv-only broker",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client();
	my ($c2_pid, $c2_out, $c2_in) = ncat_client();

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c1_out);
	!$resp or die "Client received \"$resp\" from --recv-only broker";
	$resp = timeout_read($c2_out);
	!$resp or die "Client received \"$resp\" from --recv-only broker";

	syswrite($c1_in, "abc\n");
	$resp = timeout_read($c2_out);
	!$resp or die "Client received \"$resp\" from --recv-only broker";
};
kill_children;

#Broker Tests
($s_pid, $s_out, $s_in) = ncat_server("--broker");
test "--broker mode (tcp)",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client();
	my ($c2_pid, $c2_out, $c2_in) = ncat_client();

	syswrite($c2_in, "abc\n");
	$resp = timeout_read($c1_out);
	$resp eq "abc\n" or die "Client 1 received \"$resp\", not abc";

	syswrite($c1_in, "abc\n");
	$resp = timeout_read($c2_out);
	$resp eq "abc\n" or die "Client 2 received \"$resp\", not abc";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--broker", "--sctp");
test "--broker mode (sctp)",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client("--sctp");
	my ($c2_pid, $c2_out, $c2_in) = ncat_client("--sctp");

	syswrite($c2_in, "abc\n");
	$resp = timeout_read($c1_out);
	$resp eq "abc\n" or die "Client 1 received \"$resp\", not abc";

	syswrite($c1_in, "abc\n");
	$resp = timeout_read($c2_out);
	$resp eq "abc\n" or die "Client 2 received \"$resp\", not abc";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--broker", "--ssl");
test "--broker mode (tcp ssl)",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client("--ssl");
	my ($c2_pid, $c2_out, $c2_in) = ncat_client("--ssl");

	syswrite($c2_in, "abc\n");
	$resp = timeout_read($c1_out);
	$resp eq "abc\n" or die "Client 1 received \"$resp\", not abc";

	syswrite($c1_in, "abc\n");
	$resp = timeout_read($c2_out);
	$resp eq "abc\n" or die "Client 2 received \"$resp\", not abc";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--broker", "--sctp", "--ssl");
test "--broker mode (sctp ssl)",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client("--sctp", "--ssl");
	my ($c2_pid, $c2_out, $c2_in) = ncat_client("--sctp", "--ssl");

	syswrite($c2_in, "abc\n");
	$resp = timeout_read($c1_out);
	$resp eq "abc\n" or die "Client 1 received \"$resp\", not abc";

	syswrite($c1_in, "abc\n");
	$resp = timeout_read($c2_out);
	$resp eq "abc\n" or die "Client 2 received \"$resp\", not abc";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat("--broker");
test "IPV4 and IPV6 clients can talk to each other in broker mode",
sub {
	my $resp;
	sleep 1;
	my ($c1_pid, $c1_out, $c1_in) = ncat("-6","::1");
	my ($c2_pid, $c2_out, $c2_in) = ncat("localhost");

	syswrite($c2_in, "abc\n");
	$resp = timeout_read($c1_out, 2);
	$resp eq "abc\n" or die "IPV6 Client received \"$resp\", not abc";

	syswrite($c1_in, "abc\n");
	$resp = timeout_read($c2_out, 2);
	$resp eq "abc\n" or die "IPV4 Client received \"$resp\", not abc";
};
kill_children;


# Source address tests.

test "Connect with -p",
sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };
	local *SOCK;
	local *S;

	socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die;
	setsockopt(SOCK, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or die;
	bind(SOCK, sockaddr_in($PORT, INADDR_ANY)) or die;
	listen(SOCK, 1) or die;

	my ($c_pid, $c_out, $c_in) = ncat("-p", "1234", $HOST, $PORT);

	accept(S, SOCK) or die;
	my ($port, $addr) = sockaddr_in(getpeername(S));
	$port == 1234 or die "Client connected to proxy with source port $port, not 1234";
	close(S);
};
kill_children;

test "Connect through HTTP proxy with -p",
sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };
	local *SOCK;
	local *S;

	socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die;
	setsockopt(SOCK, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or die;
	bind(SOCK, sockaddr_in($PROXY_PORT, INADDR_ANY)) or die;
	listen(SOCK, 1) or die;

	my ($c_pid, $c_out, $c_in) = ncat("--proxy-type", "http", "--proxy", "$HOST:$PROXY_PORT", "-p", "1234", $HOST, $PORT);

	accept(S, SOCK) or die;
	my ($port, $addr) = sockaddr_in(getpeername(S));
	$port == 1234 or die "Client connected to proxy with source port $port, not 1234";
	close(S);
};
kill_children;

test "Connect through SOCKS4 proxy with -p",
sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };
	local *SOCK;
	local *S;

	socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die;
	setsockopt(SOCK, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or die;
	bind(SOCK, sockaddr_in($PROXY_PORT, INADDR_ANY)) or die;
	listen(SOCK, 1) or die;

	my ($c_pid, $c_out, $c_in) = ncat("--proxy-type", "socks4", "--proxy", "$HOST:$PROXY_PORT", "-p", "1234", $HOST, $PORT);

	accept(S, SOCK) or die;
	my ($port, $addr) = sockaddr_in(getpeername(S));
	$port == 1234 or die "Client connected to proxy with source port $port, not 1234";
	close(S);
};
kill_children;

# Test connecting to UNIX datagram socket with -s
test "Connect to UNIX datagram socket with -s",
sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };
	local *SOCK;
	my $buff;

	unlink($UNIXSOCK);
	unlink($UNIXSOCK_TMP);

	socket(SOCK, AF_UNIX, SOCK_DGRAM, 0) or die;
	bind(SOCK, sockaddr_un($UNIXSOCK)) or die;

	my ($c_pid, $c_out, $c_in) = ncat("-U", "--udp", "-s", $UNIXSOCK_TMP, $UNIXSOCK);
	syswrite($c_in, "abc\n");
	close($c_in);

	my $peeraddr = recv(SOCK, $buff, 4, 0) or die;
	my ($path) = sockaddr_un($peeraddr);
	$path eq $UNIXSOCK_TMP or die "Client connected to proxy with source socket path $path, not $UNIXSOCK_TMP";
};
kill_children;
unlink($UNIXSOCK);
unlink($UNIXSOCK_TMP);


# HTTP proxy tests.

sub http_request {
	my ($method, $uri) = @_;
	return "$method $uri HTTP/1.0\r\n\r\n";
};

server_client_test "HTTP proxy bad request",
["--proxy-type", "http"], [], sub {
	syswrite($c_in, "bad\r\n\r\n");
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 400 or die "Expected response code 400, got $code";
};

server_client_test "HTTP CONNECT no port number",
["--proxy-type", "http"], [], sub {
	# Supposed to have a port number.
	my $req = http_request("CONNECT", "$HOST");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 400 or die "Expected response code 400, got $code";
};

server_client_test "HTTP CONNECT no port number",
["--proxy-type", "http"], [], sub {
	# Supposed to have a port number.
	my $req = http_request("CONNECT", "$HOST:");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 400 or die "Expected response code 400, got $code";
};

server_client_test "HTTP CONNECT good request",
["--proxy-type", "http"], [], sub {
	my $req = http_request("CONNECT", "$HOST:$PORT");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 200 or die "Expected response code 200, got $code";
};

server_client_test "HTTP CONNECT IPv6 address, no port number",
["--proxy-type", "http", "-6"], ["-6"], sub {
	# Supposed to have a port number.
	my $req = http_request("CONNECT", "[$IPV6_ADDR]");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 400 or die "Expected response code 400, got $code";
};

server_client_test "HTTP CONNECT IPv6 address, no port number",
["--proxy-type", "http", "-6"], ["-6"], sub {
	# Supposed to have a port number.
	my $req = http_request("CONNECT", "[$IPV6_ADDR]:");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 400 or die "Expected response code 400, got $code";
};

server_client_test "HTTP CONNECT IPv6 address, good request",
["--proxy-type", "http", "-6"], ["-6"], sub {
	my $req = http_request("CONNECT", "[$IPV6_ADDR]:$PORT");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 200 or die "Expected response code 200, got $code";
};

# Try accessing an IPv6 server with a proxy that uses -4, should fail.
proxy_test_raw "HTTP CONNECT IPv4-only proxy",
["-4"], ["-6"], ["-4"], sub {
	my $req = http_request("CONNECT", "[$IPV6_ADDR]:$PORT");
	syswrite($c_in, $req);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 504 or die "Expected response code 504, got $code";
};

# Try accessing an IPv4 server with a proxy that uses -6, should fail.
proxy_test_raw "HTTP CONNECT IPv6-only proxy",
["-6"], ["-4"], ["-6"], sub {
	my $req = http_request("CONNECT", "$HOST:$PORT");
	syswrite($c_in, $req);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 504 or die "Expected response code 504, got $code";
};

{
local $xfail = 1;
proxy_test_raw "HTTP CONNECT IPv4 client, IPv6 server",
[], ["-6"], ["-4"], sub {
	my $req = http_request("CONNECT", "[$IPV6_ADDR]:$PORT");
	syswrite($c_in, $req);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 200 or die "Expected response code 200, got $code";
};
}

# HTTP Digest functions.
sub H {
	return md5_hex(shift);
}
sub KD {
	my ($s, $d) = @_;
	return H("$s:$d");
}
sub digest_response {
	# Assume MD5 algorithm.
	my ($user, $pass, $realm, $method, $uri, $nonce, $qop, $nc, $cnonce) = @_;
	my $A1 = "$user:$realm:$pass";
	my $A2 = "$method:$uri";
	if ($qop) {
		return KD(H($A1), "$nonce:$nc:$cnonce:$qop:" . H($A2));
	} else {
		return KD(H($A1), "$nonce:" . H($A2));
	}
}
# Parse Proxy-Authenticate or Proxy-Authorization. Return ($scheme, %attrs).
sub parse_proxy_header {
	my $s = shift;
	my $scheme;
	my %attrs;

	if ($s =~ m/^\s*(\w+)/) {
		$scheme = $1;
	}
	while ($s =~ m/(\w+)\s*=\s*(?:"([^"]*)"|(\w+))/g) {
		$attrs{$1} = $2 || $3;
	}

	return ($scheme, %attrs);
}

server_client_test "HTTP proxy client prefers Digest auth",
["-k"], ["--proxy", "$HOST:$PORT", "--proxy-auth", "user:pass", "--proxy-type", "http"],
sub {
	my $nonce = "0123456789abcdef";
	my $realm = "realm";
	my $req = timeout_read($s_out);
	$req or die "No initial request from client";
	syswrite($s_in, "HTTP/1.0 407 Authentication Required\r\
Proxy-Authenticate: Basic realm=\"$realm\"\r\
Proxy-Authenticate: Digest realm=\"$realm\", nonce=\"$nonce\", qop=\"auth\"\r\n\r\n");
	$req = timeout_read($s_out);
	$req or die "No followup request from client";
	$req = HTTP::Request->parse($req);
	foreach my $hdr ($req->header("Proxy-Authorization")) {
		my ($scheme, %attrs) = parse_proxy_header($hdr);
		if ($scheme eq "Basic") {
			die "Client used Basic auth when Digest was available";
		}
	}
	return 1;
};

server_client_test "HTTP proxy client prefers Digest auth, comma-separated",
["-k"], ["--proxy", "$HOST:$PORT", "--proxy-auth", "user:pass", "--proxy-type", "http"],
sub {
	my $nonce = "0123456789abcdef";
	my $realm = "realm";
	my $req = timeout_read($s_out);
	$req or die "No initial request from client";
	syswrite($s_in, "HTTP/1.0 407 Authentication Required\r\
Proxy-Authenticate: Basic realm=\"$realm\", Digest realm=\"$realm\", nonce=\"$nonce\", qop=\"auth\"\r\n\r\n");
	$req = timeout_read($s_out);
	$req or die "No followup request from client";
	$req = HTTP::Request->parse($req);
	foreach my $hdr ($req->header("Proxy-Authorization")) {
		my ($scheme, %attrs) = parse_proxy_header($hdr);
		if ($scheme eq "Basic") {
			die "Client used Basic auth when Digest was available";
		}
	}
	return 1;
};

server_client_test "HTTP proxy Digest client auth",
["-k"], ["--proxy", "$HOST:$PORT", "--proxy-auth", "user:pass", "--proxy-type", "http"],
sub {
	my $nonce = "0123456789abcdef";
	my $realm = "realm";
	my $req = timeout_read($s_out);
	$req or die "No initial request from client";
	syswrite($s_in, "HTTP/1.0 407 Authentication Required\r\
Proxy-Authenticate: Digest realm=\"$realm\", nonce=\"$nonce\", qop=\"auth\", opaque=\"abcd\"\r\n\r\n");
	$req = timeout_read($s_out);
	$req or die "No followup request from client";
	$req = HTTP::Request->parse($req);
	foreach my $hdr ($req->header("Proxy-Authorization")) {
		my ($scheme, %attrs) = parse_proxy_header($hdr);
		next if $scheme ne "Digest";
		die "no qop" if not $attrs{"qop"};
		die "no nonce" if not $attrs{"nonce"};
		die "no uri" if not $attrs{"uri"};
		die "no nc" if not $attrs{"nc"};
		die "no cnonce" if not $attrs{"cnonce"};
		die "no response" if not $attrs{"response"};
		die "no opaque" if not $attrs{"opaque"};
		die "qop mismatch" if $attrs{"qop"} ne "auth";
		die "nonce mismatch" if $attrs{"nonce"} ne $nonce;
		die "opaque mismatch" if $attrs{"opaque"} ne "abcd";
		my $expected = digest_response("user", "pass", $realm, "CONNECT", $attrs{"uri"}, $nonce, "auth", $attrs{"nc"}, $attrs{"cnonce"});
		die "auth mismatch: $attrs{response} but expected $expected" if $attrs{"response"} ne $expected;
		return 1;
	}
	die "No Proxy-Authorization: Digest in client request";
};

server_client_test "HTTP proxy Digest client auth, no qop",
["-k"], ["--proxy", "$HOST:$PORT", "--proxy-auth", "user:pass", "--proxy-type", "http"],
sub {
	my $nonce = "0123456789abcdef";
	my $realm = "realm";
	my $req = timeout_read($s_out);
	$req or die "No initial request from client";
	syswrite($s_in, "HTTP/1.0 407 Authentication Required\r\
Proxy-Authenticate: Digest realm=\"$realm\", nonce=\"$nonce\", opaque=\"abcd\"\r\n\r\n");
	$req = timeout_read($s_out);
	$req or die "No followup request from client";
	$req = HTTP::Request->parse($req);
	foreach my $hdr ($req->header("Proxy-Authorization")) {
		my ($scheme, %attrs) = parse_proxy_header($hdr);
		next if $scheme ne "Digest";
		die "no nonce" if not $attrs{"nonce"};
		die "no uri" if not $attrs{"uri"};
		die "no response" if not $attrs{"response"};
		die "no opaque" if not $attrs{"opaque"};
		die "nonce mismatch" if $attrs{"nonce"} ne $nonce;
		die "opaque mismatch" if $attrs{"opaque"} ne "abcd";
		die "nc present" if $attrs{"nc"};
		die "cnonce present" if $attrs{"cnonce"};
		my $expected = digest_response("user", "pass", $realm, "CONNECT", $attrs{"uri"}, $nonce, undef, undef, undef);
		die "auth mismatch: $attrs{response} but expected $expected" if $attrs{"response"} ne $expected;
		return 1;
	}
	die "No Proxy-Authorization: Digest in client request";
};

# This violates RFC 2617 section 1.2, which requires at least one auth-param.
# But NTLM and Negotiate don't use any.
server_client_test "HTTP proxy client handles scheme without auth-params",
["-k"], ["--proxy", "$HOST:$PORT", "--proxy-auth", "user:pass", "--proxy-type", "http"],
sub {
	my $nonce = "0123456789abcdef";
	my $realm = "realm";
	my $req = timeout_read($s_out);
	$req or die "No initial request from client";
	syswrite($s_in, "HTTP/1.0 407 Authentication Required\r\
Proxy-Authenticate: Basic realm=\"$realm\"\r\
Proxy-Authenticate: NTLM\r\
Proxy-Authenticate: Digest realm=\"$realm\", nonce=\"$nonce\", qop=\"auth\"\r\n\r\n");
	$req = timeout_read($s_out);
	$req or die "No followup request from client";
	$req = HTTP::Request->parse($req);
	$req->header("Proxy-Authorization") or die "Client didn't sent Proxy-Authorization";
};

server_client_test "HTTP proxy client handles scheme without auth-params, comma-separated",
["-k"], ["--proxy", "$HOST:$PORT", "--proxy-auth", "user:pass", "--proxy-type", "http"],
sub {
	my $nonce = "0123456789abcdef";
	my $realm = "realm";
	my $req = timeout_read($s_out);
	$req or die "No initial request from client";
	syswrite($s_in, "HTTP/1.0 407 Authentication Required\r\
Proxy-Authenticate: Basic realm=\"$realm\", NTLM, Digest realm=\"$realm\", nonce=\"$nonce\", qop=\"auth\"\r\n\r\n");
	$req = timeout_read($s_out);
	$req or die "No followup request from client";
	$req = HTTP::Request->parse($req);
	$req->header("Proxy-Authorization") or die "Client didn't sent Proxy-Authorization";
};

# Check that the proxy relays in both directions.
proxy_test "HTTP CONNECT proxy relays",
[], [], [], sub {
	syswrite($c_in, "abc\n");
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp eq "abc\n" or die "Proxy relayed \"$resp\", not \"abc\\n\"";
	syswrite($s_in, "def\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "def\n" or die "Proxy relayed \"$resp\", not \"def\\n\"";
};

# Proxy client shouldn't see the status line returned by the proxy server.
server_client_test "HTTP CONNECT client hides proxy server response",
["--proxy-type", "http"], ["--proxy", "$HOST:$PORT", "--proxy-type", "http"], sub {
	my $resp = timeout_read($c_out);
	!$resp or die "Proxy client sent " . d($resp) . " to the user stream";
};

server_client_test "HTTP CONNECT client, different Status-Line",
[], ["--proxy", "$HOST:$PORT", "--proxy-type", "http"], sub {
	my $resp;
	syswrite($s_in, "HTTP/1.1 200 Go ahead\r\n\r\nabc\n");
	$resp = timeout_read($c_out);
	if (!defined($resp)) {
		die "Client didn't recognize connection";
	} elsif ($resp ne "abc\n") {
		die "Proxy client sent " . d($resp) . " to the user stream";
	}
	return 1;
};

server_client_test "HTTP CONNECT client, server sends header",
[], ["--proxy", "$HOST:$PORT", "--proxy-type", "http"], sub {
	my $resp;
	syswrite($s_in, "HTTP/1.0 200 OK\r\nServer: ncat-test 1.2.3\r\n\r\nabc\n");
	$resp = timeout_read($c_out);
	if (!defined($resp)) {
		die "Client didn't recognize connection";
	} elsif ($resp ne "abc\n") {
		die "Proxy client sent " . d($resp) . " to the user stream";
	}
	return 1;
};

# Check that the proxy doesn't consume anything following the request when
# request and body are combined in one send. Section 3.3 of the CONNECT spec
# explicitly allows the client to send data before the connection is
# established.
proxy_test_raw "HTTP CONNECT server doesn't consume anything after request",
[], [], [], sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\nUser-Agent: ncat-test\r\n\r\nabc\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 200 or die "Expected response code 200, got $code";

	$resp = timeout_read($s_out) or die "Read timeout";
	$resp eq "abc\n" or die "Proxy relayed \"$resp\", not \"abc\\n\"";
};

server_client_test "HTTP CONNECT overlong Request-Line",
["--proxy-type", "http"], [], sub {
	syswrite($c_in, "CONNECT " . ("A" x 24000) . ":$PORT HTTP/1.0\r\n\r\n");
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 413 or $code == 414 or die "Expected response code 413 or 414, got $code";
};

server_client_test "HTTP CONNECT overlong header",
["--proxy-type", "http"], [], sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	for (my $i = 0; $i < 10000; $i++) {
		syswrite($c_in, "Header: Value\r\n");
	}
	syswrite($c_in, "\r\n");
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 413 or die "Expected response code 413, got $code";
};

server_client_test "HTTP GET hostname only",
["--proxy-type", "http"], [], sub {
	my $req = http_request("GET", "$HOST");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 400 or die "Expected response code 400, got $code";
};

server_client_test "HTTP GET path only",
["--proxy-type", "http"], [], sub {
	my $req = http_request("GET", "/");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 400 or die "Expected response code 400, got $code";
};

proxy_test_raw "HTTP GET absolute URI",
[], [], [], sub {
	my $req = http_request("GET", "http://$HOST:$PORT/");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp =~ /^GET \/ HTTP\/1\./ or die "Proxy sent \"$resp\"";
};

proxy_test_raw "HTTP GET absolute URI, no path",
[], [], [], sub {
	my $req = http_request("GET", "http://$HOST:$PORT");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp =~ /^GET \/ HTTP\/1\./ or die "Proxy sent \"$resp\"";
};

proxy_test_raw "HTTP GET percent escape",
[], [], [], sub {
	my $req = http_request("GET", "http://$HOST:$PORT/%41");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	uri_unescape($resp) =~ /^GET \/A HTTP\/1\./ or die "Proxy sent \"$resp\"";
};

proxy_test_raw "HTTP GET remove Connection header fields",
[], [], [], sub {
	my $req = "GET http://$HOST:$PORT/ HTTP/1.0\r\nKeep-Alive: 300\r\nOne: 1\r\nConnection: keep-alive, two, close\r\nTwo: 2\r\nThree: 3\r\n\r\n";
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp = HTTP::Request->parse($resp);
	!defined($resp->header("Keep-Alive")) or die "Proxy did not remove Keep-Alive header field";
	!defined($resp->header("Two")) or die "Proxy did not remove Two header field";
	$resp->header("One") eq "1" or die "Proxy modified One header field";
	$resp->header("Three") eq "3" or die "Proxy modified Three header field";
};

proxy_test_raw "HTTP GET combine multiple headers with the same name",
[], [], [], sub {
	my $req = "GET http://$HOST:$PORT/ HTTP/1.0\r\nConnection: keep-alive\r\nKeep-Alive: 300\r\nConnection: two\r\nOne: 1\r\nConnection: close\r\nTwo: 2\r\nThree: 3\r\n\r\n";
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp = HTTP::Request->parse($resp);
	!defined($resp->header("Keep-Alive")) or die "Proxy did not remove Keep-Alive header field";
	!defined($resp->header("Two")) or die "Proxy did not remove Keep-Alive header field";
	$resp->header("One") eq "1" or die "Proxy modified One header field";
	$resp->header("Three") eq "3" or die "Proxy modified Three header field";
};

# RFC 2616 section 5.1.2: "In order to avoid request loops, a proxy MUST be able
# to recognize all of its server names, including any aliases, local variations,
# and the numeric IP address."
server_client_test "HTTP GET request loop",
["--proxy-type", "http"], [], sub {
	my $req = http_request("GET", "http://$HOST:$PORT/");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 403 or die "Expected response code 403, got $code";
};

server_client_test "HTTP GET IPv6 request loop",
["-6", "--proxy-type", "http"], ["-6"], sub {
	my $req = http_request("GET", "http://[$IPV6_ADDR]:$PORT/");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 403 or die "Expected response code 403, got $code";
};

proxy_test_raw "HTTP HEAD absolute URI",
[], [], [], sub {
	my $req = http_request("HEAD", "http://$HOST:$PORT/");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp = HTTP::Request->parse($resp);
	$resp->method eq "HEAD" or die "Proxy sent \"" . $resp->method . "\"";
};

proxy_test_raw "HTTP POST",
[], [], [], sub {
	my $req = "POST http://$HOST:$PORT/ HTTP/1.0\r\nContent-Length: 4\r\n\r\nabc\n";
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp = HTTP::Request->parse($resp);
	$resp->method eq "POST" or die "Proxy sent \"" . $resp->method . "\"";
	$resp->content eq "abc\n" or die "Proxy sent \"" . $resp->content . "\"";
};

proxy_test_raw "HTTP POST Content-Length: 0",
[], [], [], sub {
	my $req = "POST http://$HOST:$PORT/ HTTP/1.0\r\nContent-Length: 0\r\n\r\n";
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp = HTTP::Request->parse($resp);
	$resp->method eq "POST" or die "Proxy sent \"" . $resp->method . "\"";
	$resp->content eq "" or die "Proxy sent \"" . $resp->content . "\"";
};

proxy_test_raw "HTTP POST short Content-Length",
[], [], [], sub {
	my $req = "POST http://$HOST:$PORT/ HTTP/1.0\r\nContent-Length: 2\r\n\r\nabc\n";
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp = HTTP::Request->parse($resp);
	$resp->method eq "POST" or die "Proxy sent \"" . $resp->method . "\"";
	$resp->content eq "ab" or die "Proxy sent \"" . $resp->content . "\"";
};

proxy_test_raw "HTTP POST long Content-Length",
[], [], [], sub {
	my $req = "POST http://$HOST:$PORT/ HTTP/1.0\r\nContent-Length: 10\r\n\r\nabc\n";
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp = HTTP::Request->parse($resp);
	$resp->method eq "POST" or die "Proxy sent \"" . $resp->method . "\"";
	$resp->content eq "abc\n" or die "Proxy sent \"" . $resp->content . "\"";
};

proxy_test_raw "HTTP POST chunked transfer encoding",
[], [], [], sub {
	my $req = "POST http://$HOST:$PORT/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabc\n0\r\n";
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out);
	# We expect the proxy to relay the request or else die with an error
	# saying it can't do it.
	if ($resp) {
		$resp = HTTP::Request->parse($resp);
		$resp->method eq "POST" or die "Proxy sent \"" . $resp->method . "\"";
		$resp->content eq "abc\n" or die "Proxy sent \"" . $resp->content . "\"";
	} else {
		$resp = timeout_read($c_out) or die "Read timeout";
		$resp = HTTP::Response->parse($resp);
		$resp->code == 400 or $resp->code == 411 or die "Proxy returned code " . $resp->code;
	}
};

proxy_test_raw "HTTP POST chunked transfer encoding, no data",
[], [], [], sub {
	my $req = "POST http://$HOST:$PORT/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n";
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out);
	if ($resp) {
		$resp = HTTP::Request->parse($resp);
		$resp->method eq "POST" or die "Proxy sent \"" . $resp->method . "\"";
		$resp->content eq "" or die "Proxy sent \"" . $resp->content . "\"";
	} else {
		$resp = timeout_read($c_out) or die "Read timeout";
		$resp = HTTP::Response->parse($resp);
		$resp->code == 400 or $resp->code == 411 or die "Proxy returned code " . $resp->code;
	}
};

server_client_test "HTTP proxy unknown method",
["--proxy-type", "http"], [], sub {
	# Supposed to have a port number.
	my $req = http_request("NOTHING", "http://$HOST:$PORT/");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 405 or die "Expected response code 405, got $code";
};

# Check that proxy auth is base64 encoded properly. 's' and '~' are 0x77 and
# 0x7E respectively, printing characters with many bits set.
for my $auth ("", "a", "a:", ":a", "user:sss", "user:ssss", "user:sssss", "user:~~~", "user:~~~~", "user:~~~~~") {
server_client_test "HTTP proxy auth base64 encoding: \"$auth\"",
["-k"], ["--proxy", "$HOST:$PORT", "--proxy-type", "http", "--proxy-auth", $auth], sub {
	my $resp = timeout_read($s_out) or die "Read timeout";
	syswrite($s_in, "HTTP/1.0 407 Auth\r\nProxy-Authenticate: Basic realm=\"Ncat\"\r\n\r\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	my $auth_header = HTTP::Response->parse($resp)->header("Proxy-Authorization") or die "Proxy client didn't send Proxy-Authorization header field";
	my ($b64_auth) = ($auth_header =~ /^Basic (.*)/) or die "No auth data in \"$auth_header\"";
	my $dec_auth = decode_base64($b64_auth);
	$auth eq $dec_auth or die "Proxy client sent \"$b64_auth\" for \"$auth\", decodes to \"$dec_auth\"";
};
}

server_client_test_multi ["tcp", "tcp ssl"], "HTTP proxy server auth challenge",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code == 407 or die "Expected response code 407, got $code";
	my $auth = $resp->header("Proxy-Authenticate");
	$auth or die "Proxy server didn't send Proxy-Authenticate header field";
};

server_client_test_multi ["tcp", "tcp ssl"], "HTTP proxy server correct auth",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization: Basic " . encode_base64("user:pass") . "\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code == 200 or die "Expected response code 200, got $code";
};

server_client_test_multi ["tcp", "tcp ssl"], "HTTP proxy Basic wrong user",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization: Basic " . encode_base64("nobody:pass") . "\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code == 407 or die "Expected response code 407, got $code";
};

server_client_test_multi ["tcp", "tcp ssl"], "HTTP proxy Basic wrong pass",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization: Basic " . encode_base64("user:word") . "\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code == 407 or die "Expected response code 407, got $code";
};

server_client_test_multi ["tcp", "tcp ssl"], "HTTP proxy Basic correct auth, different case",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "pROXY-aUTHORIZATION: BASIC " . encode_base64("user:pass") . "\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code == 200 or die "Expected response code 200, got $code";
};


($s_pid, $s_out, $s_in) = ncat_server("--proxy-type", "http", "--proxy-auth", "user:pass");
test "HTTP proxy Digest wrong user",
sub {
	my ($c_pid, $c_out, $c_in) = ncat_client();
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n\r\n");
	my $resp = timeout_read($c_out);
	$resp or die "No response from server";
	$resp = HTTP::Response->parse($resp);
	foreach my $hdr ($resp->header("Proxy-Authenticate")) {
		my ($scheme, %attrs) = parse_proxy_header($hdr);
		next if $scheme ne "Digest";
		die "no nonce" if not $attrs{"nonce"};
		die "no realm" if not $attrs{"realm"};
		my ($c_pid, $c_out, $c_in) = ncat_client();
		my $response = digest_response("xxx", "pass", $attrs{"realm"}, "CONNECT", "$HOST:$PORT", $attrs{"nonce"}, undef, undef, undef);
		syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\
Proxy-Authorization: Digest username=\"xxx\", realm=\"$attrs{realm}\", nonce=\"$attrs{nonce}\", uri=\"$HOST:$PORT\", response=\"$response\"\r\n\r\n");
		$resp = timeout_read($c_out);
		$resp or die "No response from server";
		$resp = HTTP::Response->parse($resp);
		my $code = $resp->code;
		$resp->code == 407 or die "Expected response code 407, got $code";
		return 1;
	}
	die "No Proxy-Authenticate: Digest in server response";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--proxy-type", "http", "--proxy-auth", "user:pass");
test "HTTP proxy Digest wrong pass",
sub {
	my ($c_pid, $c_out, $c_in) = ncat_client();
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n\r\n");
	my $resp = timeout_read($c_out);
	$resp or die "No response from server";
	$resp = HTTP::Response->parse($resp);
	foreach my $hdr ($resp->header("Proxy-Authenticate")) {
		my ($scheme, %attrs) = parse_proxy_header($hdr);
		next if $scheme ne "Digest";
		die "no nonce" if not $attrs{"nonce"};
		die "no realm" if not $attrs{"realm"};
		my ($c_pid, $c_out, $c_in) = ncat_client();
		my $response = digest_response("user", "xxx", $attrs{"realm"}, "CONNECT", "$HOST:$PORT", $attrs{"nonce"}, undef, undef, undef);
		syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\
Proxy-Authorization: Digest username=\"user\", realm=\"$attrs{realm}\", nonce=\"$attrs{nonce}\", uri=\"$HOST:$PORT\", response=\"$response\"\r\n\r\n");
		$resp = timeout_read($c_out);
		$resp or die "No response from server";
		$resp = HTTP::Response->parse($resp);
		my $code = $resp->code;
		$resp->code == 407 or die "Expected response code 407, got $code";
		return 1;
	}
	die "No Proxy-Authenticate: Digest in server response";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--proxy-type", "http", "--proxy-auth", "user:pass");
test "HTTP proxy Digest correct auth",
sub {
	my ($c_pid, $c_out, $c_in) = ncat_client();
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n\r\n");
	my $resp = timeout_read($c_out);
	$resp or die "No response from server";
	$resp = HTTP::Response->parse($resp);
	foreach my $hdr ($resp->header("Proxy-Authenticate")) {
		my ($scheme, %attrs) = parse_proxy_header($hdr);
		next if $scheme ne "Digest";
		die "no nonce" if not $attrs{"nonce"};
		die "no realm" if not $attrs{"realm"};
		my ($c_pid, $c_out, $c_in) = ncat_client();
		my $response = digest_response("user", "pass", $attrs{"realm"}, "CONNECT", "$HOST:$PORT", $attrs{"nonce"}, "auth", "00000001", "abcdefg");
		syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\
Proxy-Authorization: Digest username=\"user\", realm=\"$attrs{realm}\", nonce=\"$attrs{nonce}\", uri=\"$HOST:$PORT\", qop=\"auth\", nc=\"00000001\", cnonce=\"abcdefg\", response=\"$response\"\r\n\r\n");
		$resp = timeout_read($c_out);
		$resp or die "No response from server";
		$resp = HTTP::Response->parse($resp);
		my $code = $resp->code;
		$resp->code == 200 or die "Expected response code 200, got $code";
		return 1;
	}
	die "No Proxy-Authenticate: Digest in server response";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--proxy-type", "http", "--proxy-auth", "user:pass");
test "HTTP proxy Digest correct auth, no qop",
sub {
	my ($c_pid, $c_out, $c_in) = ncat_client();
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n\r\n");
	my $resp = timeout_read($c_out);
	$resp or die "No response from server";
	$resp = HTTP::Response->parse($resp);
	foreach my $hdr ($resp->header("Proxy-Authenticate")) {
		my ($scheme, %attrs) = parse_proxy_header($hdr);
		next if $scheme ne "Digest";
		die "no nonce" if not $attrs{"nonce"};
		die "no realm" if not $attrs{"realm"};
		my ($c_pid, $c_out, $c_in) = ncat_client();
		my $response = digest_response("user", "pass", $attrs{"realm"}, "CONNECT", "$HOST:$PORT", $attrs{"nonce"}, undef, undef, undef);
		syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\
Proxy-Authorization: Digest username=\"user\", realm=\"$attrs{realm}\", nonce=\"$attrs{nonce}\", uri=\"$HOST:$PORT\", response=\"$response\"\r\n\r\n");
		$resp = timeout_read($c_out);
		$resp or die "No response from server";
		$resp = HTTP::Response->parse($resp);
		my $code = $resp->code;
		$resp->code == 200 or die "Expected response code 200, got $code";
		return 1;
	}
	die "No Proxy-Authenticate: Digest in server response";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--proxy-type", "http", "--proxy-auth", "user:pass");
test "HTTP proxy Digest missing fields",
sub {
	my ($c_pid, $c_out, $c_in) = ncat_client();
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n\r\n");
	my $resp = timeout_read($c_out);
	$resp or die "No response from server";
	$resp = HTTP::Response->parse($resp);
	foreach my $hdr ($resp->header("Proxy-Authenticate")) {
		my ($scheme, %attrs) = parse_proxy_header($hdr);
		next if $scheme ne "Digest";
		my ($c_pid, $c_out, $c_in) = ncat_client();
		my $response = digest_response("user", "pass", $attrs{"realm"}, "CONNECT", "$HOST:$PORT", $attrs{"nonce"}, undef, undef, undef);
		syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\
Proxy-Authorization: Digest username=\"user\", nonce=\"$attrs{nonce}\", response=\"$response\"\r\n\r\n");
		$resp = timeout_read($c_out);
		$resp or die "No response from server";
		$resp = HTTP::Response->parse($resp);
		my $code = $resp->code;
		$resp->code == 407 or die "Expected response code 407, got $code";
		return 1;
	}
	die "No Proxy-Authenticate: Digest in server response";
};
kill_children;

{
local $xfail = 1;
($s_pid, $s_out, $s_in) = ncat_server("--proxy-type", "http", "--proxy-auth", "user:pass");
test "HTTP proxy Digest prevents replay",
sub {
	my ($c_pid, $c_out, $c_in) = ncat_client();
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n\r\n");
	my $resp = timeout_read($c_out);
	$resp or die "No response from server";
	$resp = HTTP::Response->parse($resp);
	foreach my $hdr ($resp->header("Proxy-Authenticate")) {
		my ($scheme, %attrs) = parse_proxy_header($hdr);
		next if $scheme ne "Digest";
		die "no nonce" if not $attrs{"nonce"};
		die "no realm" if not $attrs{"realm"};
		my ($c_pid, $c_out, $c_in) = ncat_client();
		my $response = digest_response("user", "pass", $attrs{"realm"}, "CONNECT", "$HOST:$PORT", $attrs{"nonce"}, "auth", "00000001", "abcdefg");
		my $req = "CONNECT $HOST:$PORT HTTP/1.0\r\
Proxy-Authorization: Digest username=\"user\", realm=\"$attrs{realm}\", nonce=\"$attrs{nonce}\", uri=\"$HOST:$PORT\", qop=\"auth\", nc=\"00000001\", cnonce=\"abcdefg\", response=\"$response\"\r\n\r\n";
		syswrite($c_in, $req);
		$resp = timeout_read($c_out);
		$resp or die "No response from server";
		$resp = HTTP::Response->parse($resp);
		my $code = $resp->code;
		$resp->code == 200 or die "Expected response code 200, got $code";
		syswrite($c_in, $req);
		$resp = timeout_read($c_out);
		if ($resp) {
			$resp = HTTP::Response->parse($resp);
			$code = $resp->code;
			$resp->code == 407 or die "Expected response code 407, got $code";
		}
		return 1;
	}
	die "No Proxy-Authenticate: Digest in server response";
};
kill_children;
}

# Test that header field values can be split across lines with LWS.
server_client_test_multi ["tcp", "tcp ssl"], "HTTP proxy server LWS",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization:\t  Basic  \r\n\t  \n dXNlcjpwYXNz\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code == 200 or die "Expected response code 200, got $code";
};

server_client_test_multi ["tcp", "tcp ssl"], "HTTP proxy server LWS",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization: Basic\r\n dXNlcjpwYXNz\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code == 200 or die "Expected response code 200, got $code";
};

server_client_test_multi ["tcp", "tcp ssl"], "HTTP proxy server no auth",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization: \r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code != 200 or die "Got unexpected 200 response";
};

server_client_test_multi ["tcp", "tcp ssl"], "HTTP proxy server broken auth",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization: French fries\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code != 200 or die "Got unexpected 200 response";
};

server_client_test_multi ["tcp", "tcp ssl"], "HTTP proxy server extra auth",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization: Basic " . encode_base64("user:pass") . " extra\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code != 200 or die "Got unexpected 200 response";
};

# Allow and deny list tests.

server_client_test_all "Allow localhost (IPv4 address)",
["--allow", "127.0.0.1"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};

server_client_test_all "Allow localhost (host name)",
["--allow", "localhost"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};

# Anyone not allowed is denied.
server_client_test_all "Allow non-localhost",
["--allow", "1.2.3.4"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server did not reject host not in allow list";
};

# --allow options should accumulate.
server_client_test_all "--allow options accumulate",
["--allow", "127.0.0.1", "--allow", "1.2.3.4"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};

server_client_test_all "Deny localhost (IPv4 address)",
["--deny", "127.0.0.1"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server did not reject host in deny list";
};

server_client_test_all "Deny localhost (host name)",
["--deny", "localhost"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server did not reject host in deny list";
};

# Anyone not denied is allowed.
server_client_test_all "Deny non-localhost",
["--deny", "1.2.3.4"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};

# --deny options should accumulate.
server_client_test_all "--deny options accumulate",
["--deny", "127.0.0.1", "--deny", "1.2.3.4"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server did not reject host in deny list";
};

# If a host is both allowed and denied, denial takes precedence.
server_client_test_all "Allow and deny",
["--allow", "127.0.0.1", "--deny", "127.0.0.1"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server did not reject host in deny list";
};

# Test that --allowfile and --denyfile handle blank lines and more than one
# specification per line.
for my $contents (
"1.2.3.4

localhost",
"1.2.3.4 localhost"
) {
my ($fh, $filename) = tempfile("ncat-test-XXXXX", SUFFIX => ".txt");
print $fh $contents;
server_client_test_all "--allowfile",
["--allowfile", $filename], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
server_client_test_all "--denyfile",
["--denyfile", $filename], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server did not reject host in --denyfile list";
};
unlink $filename;
}

# Test --ssl sending.
server_client_test "SSL server relays",
["--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem"], ["--ssl"], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Client got \"$resp\", not \"abc\\n\"";
};

# Test that an SSL server gracefully handles non-SSL connections.
($s_pid, $s_out, $s_in) = ncat_server("--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem", "--keep-open");
test "SSL server handles non-SSL connections",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client();
	syswrite($c1_in, "abc\n");
	kill "TERM", $c1_pid;
	waitpid $c1_pid, 0;

	my ($c2_pid, $c2_out, $c2_in) = ncat_client("--ssl");
	syswrite($c2_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
	kill "TERM", $c2_pid;
	waitpid $c2_pid, 0;
};
kill_children;

{
($s_pid, $s_out, $s_in) = ncat_server("--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem");
test "SSL server doesn't block during handshake",
sub {
	my $resp;

	# Connect without SSL so the handshake isn't completed.
	my ($c1_pid, $c1_out, $c1_in) = ncat_client();

	my ($c2_pid, $c2_out, $c2_in) = ncat_client("--ssl");
	syswrite($c2_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server is still accepting connections.";
};
kill_children;
}

{
($s_pid, $s_out, $s_in) = ncat_server("--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem",  "--keep-open");
test "SSL server doesn't block during handshake(--keep-open)",
sub {
	my $resp;

	# Connect without SSL so the handshake isn't completed.
	my ($c1_pid, $c1_out, $c1_in) = ncat_client();

	my ($c2_pid, $c2_out, $c2_in) = ncat_client("--ssl");
	syswrite($c2_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;
}
{
($s_pid, $s_out, $s_in) = ncat_server("--ssl", "--exec","/usr/bin/perl -e \$|=1;while(<>){tr/a-z/A-Z/;print}", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem", "--keep-open");
test "SSL --exec server doesn't block during handshake",
sub {
	my $resp;

	# Connect without SSL so the handshake isn't completed.
	my ($c1_pid, $c1_out, $c1_in) = ncat_client();

	my ($c2_pid, $c2_out, $c2_in) = ncat_client("--ssl");
	syswrite($c2_in, "abc\n");

	$resp = timeout_read($c2_out);
	$resp eq "ABC\n" or die "Client2 got \"$resp\", not \"ABC\\n\"";
};
kill_children;
}

($s_pid, $s_out, $s_in) = ncat_server("--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem");
test "SSL verification, correct domain name",
sub {
	my $resp;

	($c_pid, $c_out, $c_in) = ncat("localhost", $PORT, "--ssl-verify", "--ssl-trustfile", "test-cert.pem");
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem");
test "SSL verification, wrong domain name",
sub {
	my $resp;

	# Use the IPv6 address as an alternate name that doesn't match the one
	# on the certificate.
	($c_pid, $c_out, $c_in) = ncat($IPV6_ADDR, $PORT, "-6", "--ssl-verify", "--ssl-trustfile", "test-cert.pem");
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server got \"$resp\" when verification should have failed";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--ssl");
test "SSL verification, no server cert",
sub {
	my $resp;

	($c_pid, $c_out, $c_in) = ncat("localhost", $PORT, "--ssl-verify", "--ssl-trustfile", "test-cert.pem");
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server got \"$resp\" when verification should have failed";
};
kill_children;

# Test --max-conns.
($s_pid, $s_out, $s_in) = ncat_server("--keep-open", "--max-conns", "1");
test "--keep-open server keeps connection count properly.",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client();
	kill "TERM", $c1_pid;
	waitpid $c1_pid, 0;

	my ($c2_pid, $c2_out, $c2_in) = ncat_client();
	syswrite($c2_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--broker", "--max-conns", "1");
test "--broker server keeps connection count properly.",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client();
	kill "TERM", $c1_pid;
	waitpid $c1_pid, 0;

	my ($c2_pid, $c2_out, $c2_in) = ncat_client();
	syswrite($s_in, "abc\n");
	$resp = timeout_read($c2_out);
	$resp eq "abc\n" or die "Second client got \"$resp\", not \"abc\\n\"";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem", "--keep-open", "--max-conns", "1");
test "SSL --keep-open server keeps connection count properly.",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client();
	kill "TERM", $c1_pid;
	waitpid $c1_pid, 0;

	my ($c2_pid, $c2_out, $c2_in) = ncat_client("--ssl");
	syswrite($c2_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem", "--broker", "--max-conns", "1");
test "SSL --broker server keeps connection count properly.",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client();
	syswrite($c1_in, "abc\n");
	kill "TERM", $c1_pid;
	waitpid $c1_pid, 0;

	my ($c2_pid, $c2_out, $c2_in) = ncat_client("--ssl");
	syswrite($s_in, "abc\n");
	$resp = timeout_read($c2_out);
	$resp eq "abc\n" or die "Second client got \"$resp\", not \"abc\\n\"";
};
kill_children;

# expand IPv6
sub ipv6_expand {
    local($_) = shift;
    s/^:/0:/;
    s/:$/:0/;
    s/(^|:)([^:]{1,3})(?=:|$)/$1.substr("0000$2", -4)/ge;
    my $c = tr/:/:/;
    s/::/":".("0000:" x (8-$c))/e;
    return $_;
}
sub socks5_auth {
    my ($pid,$code);
    my $buf="";
    my @Barray;
    my $auth_data = shift;
    my $ipvx = shift;
    my $dest_addr = shift;
    my $passed = 0;

    my $username= "";
    my $passwd= "";
    my $recv_addr = "";
    my $recv_port;

    my ($pf,$s_addr);

    local $SIG{CHLD} = sub { };
    local *SOCK;
    local *S;

    if ($ipvx eq -4) {
      $pf = PF_INET;
      $s_addr = sockaddr_in($PROXY_PORT, INADDR_ANY);
    } else {
      $pf = PF_INET6;
      $s_addr = sockaddr_in6($PROXY_PORT, inet_pton(PF_INET6, "::1"));
    }


    socket(SOCK, $pf, SOCK_STREAM, getprotobyname("tcp")) or die;
    setsockopt(SOCK, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or die;
    bind(SOCK, $s_addr) or die;
    listen(SOCK, 1) or die;

    my ($c_pid, $c_out, $c_in) = ncat("--proxy-type", "socks5", "--proxy", "localhost:$PROXY_PORT", @$auth_data, $ipvx, $dest_addr, $PORT);

    accept(S, SOCK) or die "Client not connected";
    binmode(S);
    sysread(S, $buf, 10) or die "Connection closed";

    @Barray = map hex($_), unpack("H*", $buf) =~ /(..)/g;
    die "wrong request format" if scalar(@Barray) < 3;
    die "wrong protocol version" if $Barray[0] != 5;

    if(scalar(@$auth_data) > 0) {
        # subnegotiation for authentication
        for(my $i=2; $i < scalar(@Barray); $i++) {
            if($Barray[$i] == 2) {
                $passed = 1;
            }
        }

        die "Client did not sent required authentication method x02" if $passed == 0;


        send(S, "\x05\x02",0) or die "Send: Connection closed";
        sysread(S, $buf, $BUFSIZ) or die "Read: Connection closed";

        @Barray = map hex($_), unpack("H*", $buf) =~ /(..)/g;
        die "wrong request format - small length" if scalar(@Barray) < 5;
        die "wrong request format - wrong version" if $Barray[0] != 1;
        die "wrong request format - username legth longer then packet size"
            if $Barray[1] >= scalar(@Barray);

        # get username
        for (my $i=2; $i < $Barray[1]+2; $i++) {
            $username .= chr($Barray[$i]);
        }

        #get password
        for (my $i=3+$Barray[1]; $i < scalar(@Barray); $i++) {
            $passwd .= chr($Barray[$i]);
        }

        if ($username ne "vasek" or $passwd ne "admin") {
            send(S, "\x01\x11", 0);
            # do not close connection - we can check if client try continue
        } else {
            send(S, "\x01\x00",0);
        }
    } else {
        # no authentication
        send(S, "\x05\x00",0) or die "Send: Connection closed";

    }

    sysread(S, $buf, $BUFSIZ) or die "Read: connection closed";

    @Barray = map hex($_), unpack("H*", $buf) =~ /(..)/g;
    die "wrong request length format" if scalar(@Barray) < 10;
    die "wrong protocol version after success authentication" if $Barray[0] != 5;
    die "expected connect cmd" if $Barray[1] != 1;

    if($Barray[3] == 1) {
        # IPv4

        $recv_addr = $Barray[4] .".". $Barray[5] .".". $Barray[6] .".". $Barray[7];
        die "received wrong destination IPv4" if $recv_addr ne $dest_addr;
    }  elsif ($Barray[3] == 4) {
        #IPv6

        for(my $i=4; $i<20;$i++) {
            if($i > 4 and $i % 2 == 0) {
              $recv_addr .= ":";
            }
            $recv_addr .= sprintf("%02X",$Barray[$i]);
        }

        die "received wrong destination IPv6" if $recv_addr ne ipv6_expand($dest_addr);
    } elsif ($Barray[3] == 3) {
        # domaint name

        for my $i (@Barray[5..(scalar(@Barray)-3)]) {
            $recv_addr .= chr($i);
        }
        die "received wrong destination domain name" if $recv_addr ne $dest_addr;
        die "received wrong length of domain name" if length($recv_addr) != $Barray[4];
    } else {
      die "unknown ATYP: $Barray[3]";
    }

    $recv_port = $Barray[-2]*256 + $Barray[-1];
    die "received wrong destination port" if $recv_port ne $PORT;

    send(S, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 0);

    # check if connection is still open
    syswrite($c_in, "abc\n");
    sysread(S, $buf, 10) or die "Connection closed";


    close(S);
    close(SOCK);
};


test "SOCKS5 client, server require auth username/password (access allowed), IPv4",
    sub { socks5_auth(["--proxy-auth","vasek:admin"], "-4", "127.0.0.1"); };
kill_children;

test "SOCKS5 client, server require auth username/password (access allowed), IPv6",
    sub { socks5_auth(["--proxy-auth","vasek:admin"], "-6", "::1"); };
kill_children;

test "SOCKS5 client, server require auth username/password (access allowed), domain",
    sub { socks5_auth(["--proxy-auth","vasek:admin"], "-4", "www.seznam.cz"); };
kill_children;

test "SOCKS5 client, server allows connection - no auth",
    sub { socks5_auth([], "-4", "127.0.0.1")};
kill_children;
{
local $xfail = 1;
    test "SOCKS5 client, server require auth username/password (access denied)",
        sub { socks5_auth(["--proxy-auth","klara:admin"], "-4", "127.0.0.1"); };
    kill_children;

    test "SOCKS5 client, server require auth username/password (too long login)",
        sub { socks5_auth(["--proxy-auth",'monika' x 100 . ':admindd'], "-4", "127.0.0.1");};
    kill_children;
}

{
local $xfail = 1;
test "SOCKS5 client, server sends short response",
sub {
    my ($pid,$code);
    my $buf="";
    local $SIG{CHLD} = sub { };
    local *SOCK;
    local *S;

    socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die;
    setsockopt(SOCK, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or die;
    bind(SOCK, sockaddr_in($PROXY_PORT, INADDR_ANY)) or die;
    listen(SOCK, 1) or die;

    my ($c_pid, $c_out, $c_in) = ncat("-4","--proxy-type", "socks5", "--proxy", "$HOST:$PROXY_PORT", "127.0.0.1", $PORT);

    accept(S, SOCK) or die "Client not connected";
    binmode(S);
    sysread(S, $buf, 10) or die "Connection closed";
    # not important received data now,
    #  when we know that's ok from test above

    # we need O_NONBLOCK for read/write actions else
    # client block us until we kill process manually
    fcntl(S, F_SETFL, O_NONBLOCK) or
        die "Can't set flags for the socket: $!\n";
    send(S, "\x05", 0) or die "Send: Connection closed";

    sysread(S, $buf, $BUFSIZ) or die "Connection closed";

    close(S);
    close(SOCK);
};
kill_children;
}

{
local $xfail = 1;
test "SOCKS5 client, server sends no acceptable auth method",
sub {
    my ($pid,$code);
    my $buf="";
    my ($my_addr,$recv_addr,$recv_port);

    local $SIG{CHLD} = sub { };
    local *SOCK;
    local *S;

    socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die;
    setsockopt(SOCK, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or die;
    bind(SOCK, sockaddr_in($PROXY_PORT, INADDR_ANY)) or die;
    listen(SOCK, 1) or die;

    my ($c_pid, $c_out, $c_in) = ncat("-4","--proxy-type", "socks5", "--proxy", "$HOST:$PROXY_PORT", "127.0.0.1", $PORT);

    accept(S, SOCK) or die "Client not connected";
    binmode(S);
    sysread(S, $buf, 10) or die "Connection closed";

    send(S, "\x05\xFF",0) or die "Send: Connection closed";
    sysread(S, $buf, $BUFSIZ) or die "Connection closed";

    close(S);
    close(SOCK);
};
kill_children;
}

{
   local $xfail = 1;
test "SOCKS5 client, server sends unkown code",
    sub {
        my ($pid,$code);
        my $buf="";
        my ($my_addr,$recv_addr,$recv_port);

        local $SIG{CHLD} = sub { };
        local *SOCK;
        local *S;

        socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die;
        setsockopt(SOCK, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or die;
        bind(SOCK, sockaddr_in($PROXY_PORT, INADDR_ANY)) or die;
        listen(SOCK, 1) or die;

        my ($c_pid, $c_out, $c_in) = ncat("-4","--proxy-type", "socks5", "--proxy", "$HOST:$PROXY_PORT", "127.0.0.1", $PORT);

        accept(S, SOCK) or die "Client not connected";
        binmode(S);
        sysread(S, $buf, 10) or die "Connection closed";

        send(S, "\x05\xAA",0) or die "Send: Connection closed";
        sysread(S, $buf, $BUFSIZ) or die "Connection closed";

        close(S);
        close(SOCK);
    };
    kill_children;
}

for my $count (0, 1, 10) {
	max_conns_test_tcp_sctp_ssl("--max-conns $count --keep-open", ["--keep-open"], [], $count);
}

for my $count (0, 1, 10) {
	max_conns_test_tcp_ssl("--max-conns $count --broker", ["--broker"], [], $count);
}

max_conns_test_all("--max-conns 0 --keep-open with exec", ["--keep-open", "--exec", "/bin/cat"], [], 0);
for my $count (1, 10) {
	max_conns_test_multi(["tcp", "sctp", "udp xfail", "tcp ssl", "sctp ssl"],
		"--max-conns $count --keep-open with exec", ["--keep-open", "--exec", "/bin/cat"], [], $count);
}

# Tests for zero byte option.

($s_pid, $s_out, $s_in) = ncat_server();
test "-z client with Connect success exit code (tcp)",
sub {
        my ($pid, $code);
        local $SIG{CHLD} = sub { };

        my ($c_pid, $c_out, $c_in) = ncat_client("-z");

        do {
                $pid = waitpid($c_pid, 0);
        } while ($pid > 0 && $pid != $c_pid);
        $pid == $c_pid or die "$pid != $c_pid";
        $code = $? >> 8;
        $code == 0 or die "Exit code was $code, not 0";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--udp");
test "-z client sends \"\\0\" to server and exits with success exit code (udp)",
sub {
        my ($resp, $pid, $code);
        local $SIG{CHLD} = sub { };

        my ($c_pid, $c_out, $c_in) = ncat_client("-z", "--udp");
        $resp = timeout_read($s_out);
        $resp eq "\0" or die "Server got \"$resp\", not \"\\0\" from client";

        do {
                $pid = waitpid($c_pid, 0);
        } while ($pid > 0 && $pid != $c_pid);
        $pid == $c_pid or die "$pid != $c_pid";
        $code = $? >> 8;
        $code == 0 or die "Exit code was $code, not 0";
};
kill_children;

test "-z client with connection refused exit code (tcp)",
sub {
        my ($pid, $code);
        local $SIG{CHLD} = sub { };
        ($c_pid, $c_out, $c_in) = ncat_client("-z");

        do {
                $pid = waitpid($c_pid, 0);
        } while ($pid > 0 && $pid != $c_pid);
        $pid == $c_pid or die "$pid != $c_pid";
        $code = $? >> 8;
        $code == 1 or die "Exit code was $code, not 1";
};
kill_children;

test "-z client with connection refused exit code (udp)",
sub {
        my ($pid, $code);
        local $SIG{CHLD} = sub { };
        ($c_pid, $c_out, $c_in) = ncat_client("-z", "--udp");

        do {
                $pid = waitpid($c_pid, 0);
        } while ($pid > 0 && $pid != $c_pid);
        $pid == $c_pid or die "$pid != $c_pid";
        $code = $? >> 8;
        $code == 1 or die "Exit code was $code, not 1";
};
kill_children;

# Without --keep-open, just make sure that --max-conns 0 disallows any connection.
max_conns_test_all("--max-conns 0", [], [], 0);
max_conns_test_all("--max-conns 0 with exec", ["--exec", "/bin/cat"], [], 0);

print "$num_expected_failures expected failures.\n" if $num_expected_failures > 0;
print "$num_unexpected_passes unexpected passes.\n" if $num_unexpected_passes > 0;
print "$num_failures unexpected failures.\n";
print "$num_tests tests total.\n";

if ($num_failures + $num_unexpected_passes == 0) {
	exit 0;
} else {
	exit 1;
}
