use Test::More tests => 12;
BEGIN { use_ok('POE') };
BEGIN { use_ok('POE::Component::Server::IRC') };

my $pocosi = POE::Component::Server::IRC->spawn( auth => 0, options => { trace => 0 }, antiflood => 0, plugin_debug => 0, debug => 0 );

if ( $pocosi ) {
	isa_ok( $pocosi, "POE::Component::Server::IRC" );
	POE::Session->create(
		package_states => [ 
			'main' => [ qw( _start 
					_shutdown
					ircd_registered
					ircd_daemon_quit
					ircd_daemon_nick ) ],
		],
		options => { trace => 0 },
		heap => { ircd => $pocosi },
	);
	$poe_kernel->run();
}

exit 0;

sub _start {
  my ($kernel,$heap) = @_[KERNEL,HEAP];
  $heap->{ircd}->yield( 'register' );
  $heap->{ircd}->yield( 'add_spoofed_nick', { nick => 'OperServ', umode => 'o' } );
  $kernel->delay( '_shutdown' => 20 );
  undef;
}

sub _shutdown {
  my $heap = $_[HEAP];
  $_[KERNEL]->delay( '_shutdown' => undef );
  $heap->{ircd}->yield( 'shutdown' );
  delete $heap->{ircd};
  undef;
}

sub ircd_registered {
  my ($heap,$object) = @_[HEAP,ARG0];
  my $backend = $_[SENDER]->get_heap();
  isa_ok( $object, "POE::Component::Server::IRC" );
  isa_ok( $backend, "POE::Component::Server::IRC" );
  undef;
}

sub ircd_daemon_quit {
  pass('Deleted Spoof User');
  $poe_kernel->yield( '_shutdown' );
  undef;
}

sub ircd_daemon_nick {
  my @args = @_[ARG0..$#_];
  ok( $args[0] eq 'OperServ', 'Spoof Test 1: Nick' );
  ok( $args[4] eq 'OperServ', 'Spoof Test 1: User' );
  ok( $args[5] eq 'poco.server.irc', 'Spoof Test 1: Host' );
  ok( $args[6] eq 'poco.server.irc', 'Spoof Test 1: Server' );
  ok( $args[3] eq '+o', 'Spoof Test 1: Umode' );
  ok( $args[7] eq "* I'm too lame to read the documentation *", 'Spoof Test 1: GECOS' );
  $_[SENDER]->get_heap()->yield( 'del_spoofed_nick', $args[0] );
  undef;
}
