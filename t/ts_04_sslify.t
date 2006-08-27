use Test::More; # tests => 18;
use POE;
use POE::Component::Server::IRC;
use POE::Component::IRC;

my $GOT_SSL;

BEGIN: {
  $GOT_SSL = 0;
  eval {
        require POE::Component::SSLify;
	import POE::Component::SSLify qw( Server_SSLify SSLify_Options Client_SSLify );
        $GOT_SSL = 0;
  };
}

unless ( $GOT_SSL ) {
  plan skip_all => "Not done yet";
}

plan tests => 18;

my $pocosi = POE::Component::Server::IRC->spawn( auth => 0, options => { trace => 0 }, antiflood => 0, plugin_debug => 0, debug => 0, sslify_options => [ 'ircd.key', 'ircd.crt' ] );
my $pocoirc = POE::Component::IRC->spawn( flood => 1, UseSSL => 1, options => { trace => 0 } );

if ( $pocosi and $pocoirc ) {
	isa_ok( $pocosi, "POE::Component::Server::IRC" );
	POE::Session->create(
		package_states => [ 
			'main' => [ qw( _start 
					_shutdown
					_default
					ircd_registered
					ircd_daemon_nick
					ircd_listener_add
					ircd_listener_del) ],
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
  $heap->{ircd}->add_listener( usessl => 1 );
  $kernel->delay( '_shutdown' => 20 );
  undef;
}

sub _shutdown {
  my $heap = $_[HEAP];
  $_[KERNEL]->delay( '_shutdown' => undef );
  $heap->{irc}->yield( 'unregister' => 'all' );
  $heap->{irc}->yield( 'shutdown' );
  $heap->{ircd}->yield( 'shutdown' );
  delete $heap->{irc}; delete $heap->{ircd};
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
  $heap->{irc}->yield( connect => { server => 'localhost', port => $port, nick => __PACKAGE__ } );
  undef;
}

sub ircd_listener_del {
  my ($heap,$port) = @_[HEAP,ARG0];
  ok( 1, "Stopped listener on $port" );
  $_[KERNEL]->yield( '_shutdown' );
  undef;
}

sub ircd_backend_connection {
  ok( 1, 'ircd_backend_connection' );
  undef;
}

sub ircd_backend_auth_done {
  ok( 1, 'ircd_backend_auth_done' );
  undef;
}

sub ircd_daemon_nick {
  ok( 1, 'ircd_daemon_nick' );
  undef;
}

sub ircd_backend_cmd_user {
  ok( 1, 'ircd_backend_cmd_user' );
  undef;
}

sub _default {
  my $event = $_[ARG0];
  if ( $event =~ /^irc_(00[1234]|25[15]|422)/ or $event eq 'irc_isupport' ) {
	ok( 1, $event );
  }
  if ( $event eq 'irc_mode' ) {
	ok( 1, $event );
	$_[HEAP]->{irc}->yield( 'nick' => 'moo' );
  }
  if ( $event eq 'irc_nick' ) {
	ok( 1, $event );
	$_[HEAP]->{irc}->yield( 'quit' => 'moo' );
  }
  if ( $event eq 'irc_error' ) {
	ok( 1, $event );
	$_[HEAP]->{ircd}->del_listener( port => $_[HEAP]->{port} );
  }
  undef;
}
