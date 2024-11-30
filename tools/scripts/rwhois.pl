#!/usr/local/bin/perl
#
# rwhois - do command line rwhois queries
#
# usage:
#   rwhois [-h server] query[@server]
#
# steve rader
# June 28th, 1998
#
# $Id: rwhois.pl 1496 1998-10-21 18:02:33Z davidb $
#
# TCP code snatched from _Programming Perl_ page 352
#

use Socket;

$default_server = "root.rwhois.net";
$rwhois_port = 4321;
$label_width = 18;

if ( $ARGV[0] eq "-h" ) {
  $rwhois_server = $ARGV[1];
  $query = "$ARGV[2]\n-quit\n";
} elsif ( $ARGV[0] =~ /(\S+)\@(\S+)/ ) {
  $rwhois_server = $2;
  $query = "$1\n-quit\n";
} else {
  $rwhois_server = $default_server;
  $query = "$ARGV[0]\n-quit\n";
}

# who, what and where...
$my_addr = gethostbyname('localhost');
$proto = getprotobyname('tcp');
$port = $rwhois_port;
#$port = getservbyname('time', 'tcp');
$socket = sockaddr_in(0, $my_addr);

# crank up the connection...
$| = 1;
$serv_addr = inet_aton($rwhois_server)
  or &die ("unknown host: \"$rwhois_server\"");
$serv_socket = sockaddr_in($port, $serv_addr);
socket(SOCKET, PF_INET, SOCK_STREAM, $proto)
  or &die ("socket create failed: \"$!\"");
connect(SOCKET, $serv_socket)
  or &die ("connect to $rwhois_server failed: \"$!\"");

# send the query...
send(SOCKET, "$query", 0, $serv_socket)
  or &die ("send to $rwhois_server failed: \"$!\"");

# ignore connect banner...
$resp = <SOCKET>;
# but print some connect info as fwhois...
print "[$rwhois_server]\n";

# read and print response...
$ans = 1;
while ( $resp = <SOCKET> ) {
  chop $resp;
  # ignore cruft...
  if (( $resp eq "" ) || ( $resp =~ /\%ok/ )) { next; }
  # parse Class-Name and seperate
  # out multiple responses...
  if ( $resp =~ /Class-Name:(\S+)/ ) {
    $class = $1;
    if ( $ans > 1 ) { print "---\n"; }
    $ans++;
  }
  if (( $resp =~ /\%error/ ) || ( $resp =~ /\%referral/ )) {
    print "$resp\n";
    next;
  }
  # strip off class...
  $resp =~ s/^$class://;
  @F = split(/\:/, $resp);
  # un-obfuscate what rfc2167 calls ID type character...
  if ( $F[0] =~ s/\;I$// ) { $F[0] .= "-ID"; }
  # make the output pretty...
  printf "%-${label_width}.${label_width}s %s\n", "$F[0]:", $F[1];
}

close(SOCKET);
exit;

#------------------------------------------------------------------------------

sub die {
  local($msg) = @_;
  print "$msg\n";
  exit 0;
}
