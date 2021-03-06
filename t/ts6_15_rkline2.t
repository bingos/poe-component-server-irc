{
  package Poco::Server::IRC::Plugin::Hackity;

  use strict;
  use warnings;
  use POE;
  use POE::Component::Server::IRC::Plugin qw(:ALL);

  sub new {
    my ($package, %args) = @_;
    return bless \%args, $package;
  }

  sub PCSI_register {
    my ($self, $ircd) = splice @_, 0, 2;

    $ircd->plugin_register($self, 'SERVER', qw(daemon_rkline));
    return 1;
  }

  sub PCSI_unregister {
    return 1;
  }

  sub IRCD_daemon_rkline {
    my ($self, $ircd) = splice @_, 0, 2;
    my $alarm_id = $ircd->{state}{rklines}[0]{alarm};
    $poe_kernel->delay_adjust( $alarm_id, 10 );
    return PCSI_EAT_NONE;
  }

}

use strict;
use warnings;
use Test::More 'no_plan';
use POE qw[Filter::Stackable Filter::Line Filter::IRCD];
use POE::Component::Server::IRC;
use Test::POE::Client::TCP;
use IRC::Utils qw[BOLD YELLOW NORMAL];

my $pocosi = POE::Component::Server::IRC->spawn(
    auth         => 0,
    antiflood    => 0,
    plugin_debug => 1,
    config => { servername => 'listen.server.irc', sid => '1FU' },
);

$pocosi->plugin_add( 'hackity', Poco::Server::IRC::Plugin::Hackity->new() );

POE::Session->create(
    package_states => [
        'main' => [qw(
            _start
            _shutdown
            _launch_client
            ircd_listener_add
            ircd_daemon_nick
            ircd_daemon_rkline
            ircd_daemon_expired
            client_connected
            client_input
            client_disconnected
        )],
        'main' => {
            client_registered  => 'testc_registered',
        },
    ],
    heap => {
      ircd  => $pocosi,
      eob   => 0,
      topic => 0,
    },
);

$poe_kernel->run();

sub _start {
    my ($kernel, $heap) = @_[KERNEL, HEAP];
    $heap->{ircd}->yield('register', 'all');
    $heap->{ircd}->add_listener();
    $kernel->delay('_shutdown', 100, 'timeout');
}

sub _shutdown {
    my $heap = $_[HEAP];
    if ( $_[ARG0] && $_[ARG0] eq 'timeout' ) {
      fail('We timed out');
    }
    exit;
    return;
}

sub ircd_listener_add {
    my ($heap, $port) = @_[HEAP, ARG0];
    pass("Started a listener on $port");
    $heap->{port} = $port;
    $heap->{ircd}->add_peer(
        name  => 'groucho.server.irc',
        pass  => 'foo',
        rpass => 'foo',
        type  => 'c',
        zip   => 1,
    );
    $heap->{ircd}->add_peer(
        name  => 'harpo.server.irc',
        pass  => 'foo',
        rpass => 'foo',
        type  => 'c',
        zip   => 1,
    );
    $heap->{ircd}->yield(
        'add_spoofed_nick',
        {
            nick  => 'OperServ',
            umode => 'o',
        },
    );
    return;
}

sub ircd_daemon_nick {
    my ($heap,@args) = @_[HEAP,ARG0..$#_];

    is($args[0], 'OperServ', 'Spoof Test 1: Nick');
    is($args[4], 'OperServ', 'Spoof Test 1: User');
    is($args[5], 'listen.server.irc', 'Spoof Test 1: Host');
    is($args[6], 'listen.server.irc', 'Spoof Test 1: Server');
    is($args[3], '+o', 'Spoof Test 1: Umode');
    is($args[7], "* I'm too lame to read the documentation *", 'Spoof Test 1: GECOS');
    is( scalar keys %{ $pocosi->{state}{uids} }, 1, 'Spoof generated a UID' );

    $heap->{ircd}->yield( 'daemon_cmd_rkline', 'OperServ', 1, '[bcd]obb.+@127\.0\.0\.1', 'Banhammer' );
    $poe_kernel->state($_[STATE]);
    return;
}

sub ircd_daemon_rkline {
    my ($heap,@args) = @_[HEAP,ARG0..$#_];
    is($args[0], 'OperServ!OperServ@listen.server.irc', 'Setter is okay' );
    is($args[3], '[bcd]obb.+', 'The usermask is right' );
    is($args[4], '127\.0\.0\.1', 'The hostmask is right' );
    is($args[2], 1, 'Duration should be 1 minute' );
    is($args[5], 'Banhammer', 'The reasoning is sound' );
    $poe_kernel->yield('_launch_client');
    return;
}

sub ircd_daemon_expired {
    my ($heap,@args) = @_[HEAP,ARG0..$#_];
    # $full, $target, $user, $host
    is($args[0], 'rk-line', 'Type is RK-Line' );
    is($args[1], '[bcd]obb.+@127\.0\.0\.1', 'The mask is right' );
    $poe_kernel->post('client','connect');
    return;
}

sub _launch_client {
  my ($kernel,$heap) = @_[KERNEL,HEAP];
  my $filter = POE::Filter::Stackable->new();
  $filter->push( POE::Filter::Line->new( InputRegexp => '\015?\012', OutputLiteral => "\015\012" ),
             POE::Filter::IRCD->new( debug => 0 ), );
  my $tag = 'client';
  $heap->{client} = Test::POE::Client::TCP->spawn( alias => $tag, filter => $filter, address => '127.0.0.1', port => $heap->{port}, prefix => $tag );
  return;
}

sub testc_registered {
  my ($kernel,$sender) = @_[KERNEL,SENDER];
  pass($_[STATE]);
  $kernel->post( $sender, 'connect' );
  return;
}

sub client_connected {
  my ($kernel,$heap,$sender) = @_[KERNEL,HEAP,SENDER];
  pass($_[STATE]);
  $kernel->post( $sender, 'send_to_server', { command => 'NICK', params => [ 'bobbins' ], colonify => 0 } );
  $kernel->post( $sender, 'send_to_server', { command => 'USER', params => [ 'bobbins', '*', '*', 'This is NastyBot v1.2' ], colonify => 1 } );
  return;
}

sub client_input {
  my ($heap,$sender,$in) = @_[HEAP,SENDER,ARG0];
  my $prefix = $in->{prefix};
  my $cmd    = $in->{command};
  my $params = $in->{params};
  #diag($in->{raw_line}, "\n");
  if ( $cmd eq 'ERROR' ) {
    is( $cmd, 'ERROR', 'ERROR ERROR!' );
    is( $params->[0], 'Closing Link: 127.0.0.1 (K-Lined: [Banhammer])', 'I want to be your Banhammer' );
    return;
  }
  is( $cmd, '465', 'Got a 465' );
  return;
}

sub client_input2 {
  my ($heap,$sender,$in) = @_[HEAP,SENDER,ARG0];
  my $prefix = $in->{prefix};
  my $cmd    = $in->{command};
  my $params = $in->{params};
  #diag($in->{raw_line}, "\n");
  pass("IRC_$cmd");
  if ( $cmd eq 'MODE' && $params->[0] eq 'bobbins' ) {
    $poe_kernel->post( $sender, 'send_to_server', { command => 'QUIT' } );
    return;
  }
  if ( $cmd eq 'ERROR' ) {
    like( $params->[0], qr/Closing Link/, 'Closing Link' );
    return;
  }
  return;
}

sub client_disconnected {
  my ($heap,$state,$sender) = @_[HEAP,STATE,SENDER];
  pass($state);
  $poe_kernel->state('client_disconnected','main','client_disconnected2');
  $poe_kernel->state('client_input','main','client_input2');
  diag("Waiting for RK-Line to expire, should be 10 seconds or so\n");
  return;
}
sub client_disconnected2 {
  my ($heap,$state,$sender) = @_[HEAP,STATE,SENDER];
  pass($state);
  $poe_kernel->call( $sender, 'shutdown' );
  $heap->{ircd}->yield('shutdown');
  $poe_kernel->delay('_shutdown');
  return;
}
