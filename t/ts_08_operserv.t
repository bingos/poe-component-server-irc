use Test::More tests => 17;
BEGIN { use_ok('POE') };
BEGIN { use_ok('POE::Component::IRC') };
BEGIN { use_ok('POE::Component::Server::IRC::OperServ') };

my $pocosi = POE::Component::Server::IRC::OperServ->spawn( auth => 0, options => { trace => 0 }, antiflood => 0, plugin_debug => 0, debug => 0 );

my $pocoirc = POE::Component::IRC->spawn( flood => 1 );

if ( $pocosi and $pocoirc ) {
	isa_ok( $pocosi, "POE::Component::Server::IRC" );
	POE::Session->create(
		package_states => [ 
			'main' => [ qw( _start 
					_shutdown
					irc_001
					irc_381
					irc_join
					ircd_registered
					ircd_listener_add
					ircd_daemon_quit
					ircd_daemon_nick ) ],
		],
		options => { trace => 0 },
		heap => { ircd => $pocosi, irc => $pocoirc },
	);
	$poe_kernel->run();
}

exit 0;

sub _start {
  my ($kernel,$heap) = @_[KERNEL,HEAP];
  $heap->{ircd}->yield( 'register' );
  $heap->{irc}->yield( 'register', 'all' );
  $heap->{ircd}->add_listener();
  $heap->{ircd}->add_operator( { username => 'moo', password => 'fishdont' } );
  $kernel->delay( '_shutdown' => 20 );
  undef;
}

sub ircd_listener_add {
  my ($heap,$port) = @_[HEAP,ARG0];
  ok( 1, "Started a listener on $port" );
  $heap->{port} = $port;
  $heap->{irc}->yield( connect => { server => 'localhost', port => $port, nick => 'moo' } );
  undef;
}

sub irc_001 {
  pass('Connected to ircd');
  $_[SENDER]->get_heap()->yield( 'oper' => 'moo' => 'fishdont' );
  undef;
}

sub irc_381 {
  pass('We are operator');
  $_[SENDER]->get_heap()->yield( 'join', '#test' );
  undef;
}

sub irc_join {
  my ($heap,$who,$where) = @_[HEAP,ARG0..ARG1];
  my $nick = ( split /!/, $who )[0];
  my $mynick = $heap->{irc}->nick_name();
  if ( $nick eq $mynick ) {
     $heap->{irc}->yield( 'privmsg', 'OperServ', "clear $where" );
  } else {
     ok( $nick eq 'OperServ', 'OperServ cleared channel' );
     $heap->{ircd}->yield( 'del_spoofed_nick', 'OperServ' );
  }
  undef;
}

sub _shutdown {
  my $heap = $_[HEAP];
  $_[KERNEL]->delay( '_shutdown' => undef );
  $heap->{irc}->yield( 'shutdown' );
  $heap->{ircd}->yield( 'shutdown' );
  delete $heap->{ircd}; delete $heap->{irc};
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
  return unless $args[0] eq 'OperServ';
  ok( $args[0] eq 'OperServ', 'Spoof Test 1: Nick' );
  ok( $args[4] eq 'OperServ', 'Spoof Test 1: User' );
  ok( $args[5] eq 'poco.server.irc', 'Spoof Test 1: Host' );
  ok( $args[6] eq 'poco.server.irc', 'Spoof Test 1: Server' );
  ok( $args[3] eq '+Doi', 'Spoof Test 1: Umode' );
  ok( $args[7] eq 'The OperServ bot', 'Spoof Test 1: GECOS' );
  #$_[SENDER]->get_heap()->yield( 'del_spoofed_nick', $args[0] );
  undef;
}

sub _default {
    my($event, $args) = @_[ARG0, ARG1];
    return unless $event =~ /^irc_/;
    my(@output) = ( "$event: " );
    for my $arg ( @$args ) {
        if ( ref($arg) eq 'ARRAY' ) {
            push @output, "[" . join(", ", @$arg) . "]";
        } else {
            push @output, "'$arg'";
        }
    }
    print "@output\n";
    return;
}
