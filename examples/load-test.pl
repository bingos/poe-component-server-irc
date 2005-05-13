#!/usr/bin/perl -w
#
# $Id: load-test.pl,v 1.4 2004/12/05 11:34:18 chris Exp $
#
# This is an adaption of Dennis Taylor's test.pl.  It combines a very
# simple bot with Chatbot::Eliza to make something fairly annoying.
# -- Rocco Caputo, <troc+pci@netrus.net>

use strict;

use POE::Kernel;
use POE::Session;
use POE::Component::IRC;
use Chatbot::Eliza;

my $eliza = Chatbot::Eliza->new();

# This gets executed as soon as the kernel sets up this session.
sub _start {
  my ($kernel, $session) = @_[KERNEL, SESSION];

  # Uncomment this to turn on more verbose POE debugging information.
  # $session->option( trace => 1 );

  # Ask the IRC component to send us all IRC events it receives. This
  # is the easy, indiscriminate way to do it.

  foreach my $counter (1..( $ARGV[2] || 10 )) {
  $kernel->post( $counter, 'register', 'all');

  # Setting Debug to 1 causes P::C::IRC to print all raw lines of text
  # sent to and received from the IRC server. Very useful for debugging.
  $kernel->post( $counter, 'connect', { Debug    => 0,
                                      Nick     => "ClInt^" . $counter,
                                      Server   => $ARGV[0] ||
                                                  'localhost',
                                      Port     => $ARGV[1] || 6969,
                                      Username => "clint" . $counter,
                                      Ircname  => 'Clint Client',
                                    }

               );
  }
}

sub delayed_connect {
  my ($kernel,$counter,$hashref) = @_[KERNEL,ARG0,ARG1];

  $kernel->post( $counter, 'connect', $hashref );
}

# After we successfully log into the IRC server, join a channel.
sub irc_001 {
  my ($kernel, $sender) = @_[KERNEL, SENDER];
  if ( defined ( $ARGV[3] ) and $ARGV[3] == 1 ) {
    $kernel->post( $sender, 'join', '#PoE' );
  } else {
    foreach my $counter (1..($ARGV[3] || 1)) {
      $kernel->post( $sender, 'join', '#PoCo' . $counter );
    }
  }
}


sub _stop {
  my ($kernel, $sender) = @_[KERNEL, SENDER];

  print "Control session stopped.\n";
#  $kernel->call( $sender, 'quit', 'Neenios on ice!' );
}


sub irc_disconnected {
  my $server = $_[ARG0];
  print "Lost connection to server $server.\n";
}


sub irc_error {
  my $err = $_[ARG0];
  print "Server error occurred! $err\n";
}


sub irc_socketerr {
  my $err = $_[ARG0];
  print "Couldn't connect to server: $err\n";
}

sub irc_public {
  my ($kernel, $sender, $who, $where, $msg) = @_[KERNEL, SENDER, ARG0 .. ARG2];
  my $nick = (split /!/, $who)[0];
  #print "<$nick:@{$where}[0]> $msg\n";
  $kernel->post( $sender => privmsg => $where,
                 $eliza->transform($msg)     # Filter it through a Chatbot.
               );
}

sub irc_join {
  my ($kernel, $sender, $who, $where) = @_[KERNEL, SENDER, ARG0, ARG1];
  my $nick = (split /!/, $who)[0];
  my ($botcount) = $ARGV[2] || 10;

  if ( $nick =~ /$botcount$/ ) {
	$kernel->post ( $sender, 'privmsg', [ $where ], "Hi, $nick!" );
  }
}


# here's where execution starts.
foreach my $counter (1..($ARGV[2] || 10)){
POE::Component::IRC->new( $counter ) or
  die "Can't instantiate new IRC component!\n";
}
POE::Session->new( 'main' =>
                   [ qw( _start _stop irc_001 irc_disconnected irc_join
                         irc_error irc_socketerr irc_public delayed_connect
                       )
                   ]
                 );
$poe_kernel->run();

exit 0;
