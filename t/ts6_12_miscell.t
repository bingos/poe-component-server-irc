use strict;
use warnings;
use Test::More 'no_plan';
use POE qw[Filter::Stackable Filter::Line Filter::IRCD];
use POE::Component::Server::IRC;
use Test::POE::Client::TCP;
use IRC::Utils qw[BOLD YELLOW NORMAL];

my $motd = [];

while (<DATA>) {
  chomp;
  push @$motd, $_;
}

my %servers = (
 'listen.server.irc'   => '1FU',
 'groucho.server.irc'  => '7UP',
 'harpo.server.irc'    => '9T9',
 'fake.server.irc'     => '4AK',
);

my $ts = time();

my $uidts;

my $pocosi = POE::Component::Server::IRC->spawn(
    auth         => 0,
    antiflood    => 0,
    plugin_debug => 1,
    config => { servername => 'listen.server.irc', sid => '1FU', anti_spam_exit_message_time => 0 },
);

POE::Session->create(
    package_states => [
        'main' => [qw(
            _start
            _shutdown
            _launch_client
            ircd_listener_add
            ircd_daemon_eob
            ircd_daemon_snotice
            groucho_connected
            groucho_input
            groucho_disconnected
            harpo_connected
            harpo_input
            harpo_disconnected
            client_connected
            client_input
            client_disconnected
        )],
        'main' => {
            groucho_registered => 'testc_registered',
            harpo_registered   => 'testc_registered',
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
    $kernel->delay('_shutdown', 60, 'timeout');
}

sub _shutdown {
    my $heap = $_[HEAP];
    if ( $_[ARG0] && $_[ARG0] eq 'timeout' ) {
      fail('We timed out');
    }
    exit;
    return;
}

sub ircd_daemon_snotice {
    pass($_[ARG0]);
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
    foreach my $tag ( qw[groucho harpo] ) {
      my $filter = POE::Filter::Stackable->new();
      $filter->push( POE::Filter::Line->new( InputRegexp => '\015?\012', OutputLiteral => "\015\012" ),
                POE::Filter::IRCD->new( debug => 0 ), );
      push @{ $heap->{testc} }, Test::POE::Client::TCP->spawn( alias => $tag, filter => $filter, address => '127.0.0.1', port => $port, prefix => $tag );
    }
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
  $kernel->post( $sender, 'send_to_server', { command => 'USER', params => [ 'bobbins', '*', '*', 'bobbins along' ], colonify => 1 } );
  return;
}

sub groucho_connected {
  my ($kernel,$heap,$sender) = @_[KERNEL,HEAP,SENDER];
  pass($_[STATE]);
  $kernel->post( $sender, 'send_to_server', { command => 'PASS', params => [ 'foo', 'TS', '6', '7UP' ], } );
  $kernel->post( $sender, 'send_to_server', { command => 'CAPAB', params => [ 'KNOCK UNDLN DLN TBURST GLN ENCAP UNKLN KLN CHW IE EX HOPS SVS CLUSTER EOB QS' ], colonify => 1 } );
  $kernel->post( $sender, 'send_to_server', { command => 'SERVER', params => [ 'groucho.server.irc', '1', 'Open the door and come in!!!!!!' ], colonify => 1 } );
  $kernel->post( $sender, 'send_to_server', { command => 'SVINFO', params => [ '6', '6', '0', time() ], colonify => 1 } );
  $uidts = time() - 20;
  $kernel->post( $sender, 'send_to_server', { prefix => '7UP', command => 'SID', params => [ 'fake.server.irc', 2, '4AK', 'This is a fake server' ] } );
  $kernel->post( $sender, 'send_to_server', { prefix => '7UP', command => 'UID', params => [ 'groucho', '1', $uidts, '+aiow', 'groucho', 'groucho.marx', '0', '7UPAAAAAA', '0', 'Groucho Marx' ], colonify => 1 } );
  $kernel->post( $sender, 'send_to_server', { command => 'EOB', prefix => '7UP' } );
  $kernel->post( $sender, 'send_to_server', { command => 'EOB', prefix => '4AK' } );
  $kernel->post( $sender, 'send_to_server', { command => 'PING', params => [ '7UP' ], colonify => 1 } );
  return;
}

sub harpo_connected {
  my ($kernel,$heap,$sender) = @_[KERNEL,HEAP,SENDER];
  pass($_[STATE]);
  $kernel->post( $sender, 'send_to_server', { command => 'PASS', params => [ 'foo', 'TS', '6', '9T9' ], } );
  $kernel->post( $sender, 'send_to_server', { command => 'CAPAB', params => [ 'KNOCK UNDLN DLN TBURST GLN ENCAP UNKLN KLN CHW IE EX HOPS SVS CLUSTER EOB QS' ], colonify => 1 } );
  $kernel->post( $sender, 'send_to_server', { command => 'SERVER', params => [ 'harpo.server.irc', '1', 'Open the door and come in!!!!!!' ], colonify => 1 } );
  $kernel->post( $sender, 'send_to_server', { command => 'SVINFO', params => [ '6', '6', '0', time() ], colonify => 1 } );
  $uidts = time() - 20;
  $kernel->post( $sender, 'send_to_server', { prefix => '9T9', command => 'UID', params => [ 'harpo', '1', $uidts, '+aiow', 'harpo', 'harpo.marx', '0', '9T9AAAAAA', '0', 'Harpo Marx' ], colonify => 1 } );
  $kernel->post( $sender, 'send_to_server', { command => 'EOB', prefix => '9T9' } );
  $kernel->post( $sender, 'send_to_server', { command => 'PING', params => [ '9T9' ], colonify => 1 } );
  return;
}


sub client_input {
  my ($heap,$sender,$in) = @_[HEAP,SENDER,ARG0];
  my $prefix = $in->{prefix};
  my $cmd    = $in->{command};
  my $params = $in->{params};
  diag($in->{raw_line}, "\n") if $cmd eq '372';
  if ( $cmd eq 'MODE' && $prefix =~ m'^bobbins' && $params->[1] eq '+i' ) {
    $poe_kernel->post( $sender, 'send_to_server', { command => 'VERSION' } );
    $poe_kernel->post( 'groucho', 'send_to_server', { prefix => '7UPAAAAAA', command => 'VERSION', params => [ '1FU' ], colonify => 1 } );
    $poe_kernel->post( $sender, 'send_to_server', { command => 'ADMIN' } );
    $poe_kernel->post( 'groucho', 'send_to_server', { prefix => '7UPAAAAAA', command => 'ADMIN', params => [ '1FU' ], colonify => 1 } );
    $poe_kernel->post( $sender, 'send_to_server', { command => 'INFO' } );
    $poe_kernel->post( 'groucho', 'send_to_server', { prefix => '7UPAAAAAA', command => 'INFO', params => [ '1FU' ], colonify => 1 } );
    $poe_kernel->post( $sender, 'send_to_server', { command => 'TIME' } );
    $poe_kernel->post( 'groucho', 'send_to_server', { prefix => '7UPAAAAAA', command => 'TIME', params => [ '1FU' ], colonify => 1 } );
    $poe_kernel->post( $sender, 'send_to_server', { command => 'MOTD' } );
    $poe_kernel->post( 'groucho', 'send_to_server', { prefix => '7UPAAAAAA', command => 'MOTD', params => [ '1FU' ], colonify => 1 } );
    return;
  }
  if ( $cmd eq 'ERROR' ) {
    pass($cmd);
    my $state = $heap->{ircd}{state};
    is( scalar keys %{ $state->{chans} }, 0, 'No channels' );
    is( scalar keys %{ $state->{conns} }, 2, 'Should only be 2 connections' );
    is( scalar keys %{ $state->{uids} }, 2, 'Two UIDs' );
    is( scalar keys %{ $state->{users} }, 2, 'Two users' );
    is( scalar keys %{ $state->{peers}{'LISTEN.SERVER.IRC'}{users} }, 0, 'No local users' );
    is( scalar keys %{ $state->{sids}{'1FU'}{uids} }, 0, 'No local UIDs' );
    $poe_kernel->post( $sender, 'shutdown' );
    $poe_kernel->post( 'harpo', 'terminate' );
    return;
  }
  if ( $cmd =~ m'^(001|002|003|004|251|252|255|265|266|250|256|257|258|259|351|005|371|374|391|375|372)$' ) {
    pass("IRC$cmd");
    is( $prefix, 'listen.server.irc', 'The PREFIX is correct: listen.server.irc' );
    is( $params->[0], 'bobbins', 'The NICK is correct: bobbins' );
    return;
  }
  if ( $cmd eq '422' ) {
    pass("IRC$cmd");
    is( $prefix, 'listen.server.irc', 'The PREFIX is correct: listen.server.irc' );
    is( $params->[0], 'bobbins', 'The NICK is correct: bobbins' );
    $heap->{ircd}{config}{MOTD} = $motd;
    return;
  }
  if ( $cmd eq '376' ) {
    pass("IRC$cmd");
    is( $prefix, 'listen.server.irc', 'The PREFIX is correct: listen.server.irc' );
    is( $params->[0], 'bobbins', 'The NICK is correct: bobbins' );
    $poe_kernel->post( $sender, 'send_to_server', { command => 'QUIT', params => [ 'Connection reset by fear' ] } );
    return;
  }
  if ( $cmd =~ m!^\d{3}$! ) {
    fail("Unhandled $cmd by bobbins");
    return;
  }
  return;
}

sub groucho_input {
  my ($heap,$sender,$in) = @_[HEAP,SENDER,ARG0];
  #diag($in->{raw_line}, "\n");
  my $prefix = $in->{prefix};
  my $cmd    = $in->{command};
  my $params = $in->{params};
  if ( $cmd =~ m'^(351|005|256|257|258|259|371|374|391|422|375|372|376)$' ) {
    pass("IRC$cmd");
    is( $prefix, '1FU', 'The PREFIX is correct: 1FU' );
    is( $params->[0], '7UPAAAAAA', 'The NICK is correct: 7UPAAAAAA' );
    return;
  }
  if ( $cmd =~ m!^\d{3}$! ) {
    fail("Unhandled $cmd by groucho");
    return;
  }
  if ( $cmd eq 'QUIT' ) {
    pass($cmd);
    is( $prefix, '1FUAAAAAA', 'Correct prefix: 1FUAAAAAAA' );
    is( $params->[0], q{Quit: "Connection reset by fear"}, 'Correct QUIT message' );
    return;
  }
  if ( $cmd eq 'SQUIT' ) {
    pass($cmd);
    is( $params->[0], '9T9', 'Correct SID: 9T9' );
    is( $params->[1], 'Remote host closed the connection', 'Remote host closed the connection' );
    $poe_kernel->post( $sender, 'terminate' );
    return;
  }
  return;
}

sub harpo_input {
  my ($heap,$in) = @_[HEAP,ARG0];
  #diag($in->{raw_line}, "\n");
  my $prefix = $in->{prefix};
  my $cmd    = $in->{command};
  my $params = $in->{params};
  if ( $cmd eq 'PART' ) {
    pass($cmd);
    is( $prefix, '1FUAAAAAA', 'Correct prefix: 1FUAAAAAAA' );
    is( $params->[0], '#potato', 'Channel is correct: #potato' );
    is( $params->[1], 'Suckers', 'There is a parting messge' );
    return;
  }
  if ( $cmd eq 'QUIT' ) {
    pass($cmd);
    is( $prefix, '1FUAAAAAA', 'Correct prefix: 1FUAAAAAAA' );
    is( $params->[0], q{Quit: "Connection reset by fear"}, 'Correct QUIT message' );
    return;
  }
  return;
}

sub client_disconnected {
  my ($heap,$state,$sender) = @_[HEAP,STATE,SENDER];
  pass($state);
  return;
}

sub groucho_disconnected {
  my ($heap,$state,$sender) = @_[HEAP,STATE,SENDER];
  pass($state);
  $poe_kernel->call( $sender, 'shutdown' );
  $heap->{ircd}->yield('shutdown');
  $poe_kernel->delay('_shutdown');
  return;
}

sub harpo_disconnected {
  my ($heap,$state,$sender) = @_[HEAP,STATE,SENDER];
  pass($state);
  $poe_kernel->call( $sender, 'shutdown' );
  #$poe_kernel->post( 'groucho', 'terminate' );
  return;
}

sub ircd_daemon_eob {
  my ($kernel,$heap,$sender,@args) = @_[KERNEL,HEAP,SENDER,ARG0..$#_];
  $heap->{eob}++;
  pass($_[STATE]);
  if ( defined $servers{ $args[0] } ) {
    pass('Correct server name in EOB: ' . $args[0]);
    is( $args[1], $servers{ $args[0] }, 'Correct server ID in EOB: ' . $args[1] );
  }
  else {
    fail('No such server expected');
  }
  if ( $heap->{eob} >= 3 ) {
      $poe_kernel->yield('_launch_client');
  }
  return;
}


__DATA__

  __ _     _                                               
 / _(_)___| |__     __ _  ___    _ __ ___   ___   ___  ___ 
| |_| / __| '_ \   / _` |/ _ \  | '_ ` _ \ / _ \ / _ \/ __|
|  _| \__ \ | | | | (_| | (_) | | | | | | | (_) | (_) \__ \
|_| |_|___/_| |_|  \__, |\___/  |_| |_| |_|\___/ \___/|___/
                   |___/                                   

