# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 1.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 10;
BEGIN { use_ok('POE::Component::Server::IRC::Backend') };
BEGIN { use_ok('POE::Component::IRC') };
BEGIN { use_ok('POE') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

my $pocosi = POE::Component::Server::IRC::Backend->create( options => { trace => 0 } );
my $pocoirc = POE::Component::IRC->spawn();

if ( $pocosi and $pocoirc ) {
	isa_ok( $pocosi, "POE::Component::Server::IRC::Backend" );
	POE::Session->create(
		package_states => [ 
			'main' => [ qw( _start 
					_shutdown
					ircd_backend_connection
					ircd_backend_cmd_nick 
					ircd_backend_cmd_user 
					ircd_backend_registered
					ircd_backend_listener_add
					ircd_backend_listener_del) ],
		],
		options => { trace => 0 },
		heap => { irc => $pocoirc, ircd => $pocosi },
	);
	$poe_kernel->run();
}

exit 0;

sub _start {
  my ($kernel,$heap) = @_[KERNEL,HEAP];

  $heap->{irc}->yield( 'register' => 'all' );
  $heap->{ircd}->yield( 'register' );
  $heap->{ircd}->add_listener();
  $kernel->delay( '_shutdown' => 20 );
  undef;
}

sub _shutdown {
  my ($kernel,$heap) = @_[KERNEL,HEAP];

  $kernel->delay( '_shutdown' => undef );
  $heap->{irc}->yield( 'unregister' => 'all' );
  $heap->{irc}->yield( 'shutdown' );
  $heap->{ircd}->yield( 'shutdown' );
}

sub ircd_backend_registered {
  my ($heap,$object) = @_[HEAP,ARG0];

  isa_ok( $object, "POE::Component::Server::IRC::Backend" );
  undef;
}

sub ircd_backend_listener_add {
  my ($heap,$port) = @_[HEAP,ARG0];

  ok( "Started a listener on $port" );
  $heap->{port} = $port;
  $heap->{irc}->yield( connect => { server => 'localhost', port => $port, nick => __PACKAGE__ } );
}

sub ircd_backend_listener_del {
  my ($heap,$port) = @_[HEAP,ARG0];

  ok( "Stopped listener on $port" );
  $_[KERNEL]->yield( '_shutdown' );
}

sub ircd_backend_connection {
  ok( 'ircd_backend_connection' );
}

sub ircd_backend_cmd_nick {
  ok( 'ircd_backend_nick' );
  $_[HEAP]->{result}++;
  if ( $_[HEAP]->{result} >= 2 ) {
	#$_[KERNEL]->yield( '_shutdown' );
	$_[HEAP]->{ircd}->del_listener( port => $_[HEAP]->{port} );
  }
}

sub ircd_backend_cmd_user {
  ok( 'ircd_backend_user' );
  $_[HEAP]->{result}++;
  if ( $_[HEAP]->{result} >= 2 ) {
	#$_[KERNEL]->yield( '_shutdown' );
	$_[HEAP]->{ircd}->del_listener( port => $_[HEAP]->{port} );
  }
}


