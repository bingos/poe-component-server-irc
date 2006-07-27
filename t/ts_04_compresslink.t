use Test::More tests => 16;
BEGIN { use_ok('POE::Component::Server::IRC') };
BEGIN { use_ok('POE') };
use IO::Handle;
STDOUT->autoflush(1);
STDERR->autoflush(1);

my $listener = POE::Component::Server::IRC->spawn( auth => 0, options => { trace => 0 }, antiflood => 0, plugin_debug => 0, debug => 0, config => { servername => 'listen.server.irc' } );
my $connector = POE::Component::Server::IRC->spawn( auth => 0, options => { trace => 0 }, antiflood => 0, plugin_debug => 0, debug => 0, config => { servername => 'connect.server.irc' } );

if ( $listener and $connector ) {
	isa_ok( $listener, "POE::Component::Server::IRC" );
	isa_ok( $connector, "POE::Component::Server::IRC" );
	POE::Session->create(
		package_states => [ 
			'main' => [ qw( _start 
					_shutdown
					ircd_registered
					ircd_daemon_nick
					ircd_daemon_quit
					ircd_daemon_server
					ircd_listener_add
					ircd_listener_del) ],
		],
		options => { trace => 0 },
		heap => { listen => $listener, connect => $connector },
	);
	$poe_kernel->run();
}

exit 0;

sub _start {
  my ($kernel,$heap) = @_[KERNEL,HEAP];
  $heap->{listen}->yield( 'register' );
  $heap->{connect}->yield( 'register' );
  my $time = time();
  $heap->{listen}->yield( 'add_spoofed_nick', { nick => 'fubar', ts => $time, ircname => 'Fubar', umode => 'i' } );
  $time += 10;
  $heap->{connect}->yield( 'add_spoofed_nick', { nick => 'fubar', ts => $time, ircname => 'Fubar', umode => 'i' } );
  $heap->{listen}->add_listener();
  $kernel->delay( '_shutdown' => 20 );
  undef;
}

sub _shutdown {
  my $heap = $_[HEAP];
  $_[KERNEL]->delay( '_shutdown' => undef );
  $heap->{listen}->yield( 'shutdown' );
  $heap->{connect}->yield( 'shutdown' );
  delete $heap->{listen}; delete $heap->{connect};
  undef;
}

sub ircd_registered {
  my ($heap,$object) = @_[HEAP,ARG0];
  my $backend = $_[SENDER]->get_heap();
  isa_ok( $object, "POE::Component::Server::IRC" );
  isa_ok( $backend, "POE::Component::Server::IRC" );
  undef;
}

sub ircd_listener_add {
  my ($heap,$port) = @_[HEAP,ARG0];
  ok( 1, "Started a listener on $port" );
  $heap->{port} = $port;
  $heap->{listen}->add_peer( name => 'connect.server.irc', pass => 'foo', rpass => 'foo', type => 'c', zip => 1 );
  $heap->{connect}->add_peer( name => 'listen.server.irc', pass => 'foo', rpass => 'foo', type => 'r', raddress => '127.0.0.1', rport => $port, auto => 1, zip => 1 );
  undef;
}

sub ircd_listener_del {
  my ($heap,$port) = @_[HEAP,ARG0];
  ok( 1, "Stopped listener on $port" );
  $_[KERNEL]->yield( '_shutdown' );
  undef;
}

sub ircd_daemon_server {
  my ($kernel,$heap,$sender) = @_[KERNEL,HEAP,SENDER];
  my $ircd = $sender->get_heap();
  if ( $ircd->server_name() eq 'connect.server.irc' ) {
	ok( $_[ARG0] eq 'listen.server.irc', $_[ARG0] . ' connected to ' . $_[ARG1] );
  }
  if ( $ircd->server_name() eq 'listen.server.irc' ) {
	ok( $_[ARG0] eq 'connect.server.irc', $_[ARG0] . ' connected to ' . $_[ARG1] );
  }
  undef;
}

sub ircd_daemon_nick {
  my ($kernel,$heap,$sender) = @_[KERNEL,HEAP,SENDER];
  pass("Nick test");
  undef;
}

sub ircd_daemon_quit {
  my ($kernel,$heap,$sender) = @_[KERNEL,HEAP,SENDER];
  pass("Kill test");
  $heap->{listen}->del_listener( port => $heap->{port} );
  $kernel->state( $_[STATE] );
  undef;
}

