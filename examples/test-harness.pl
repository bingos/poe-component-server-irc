use lib '../blib/lib';
use strict;
use warnings;
use POE qw(Component::Server::IRC);
use Net::Netmask;
use Data::Dumper;

$Data::Dumper::Indent = 1;
$|=1;

my $pocosi = POE::Component::Server::IRC->spawn( auth => 1, options => { trace => 1 }, plugin_debug => 0, debug => 1, config => { servername => 'logserv.gumbynet.org.uk' } );

POE::Session->create(
		package_states => [ 
			'main' => [  qw(_default 
					_start 
					sig_hup 
					ircd_daemon_join
					ircd_daemon_privmsg
			) ],
		],
		options => { trace => 0 },
		heap => { ircd => $pocosi },
);

$poe_kernel->run();
exit 0;

sub _start {
  my ($kernel,$heap) = @_[KERNEL,HEAP];

  print STDOUT "$$\n";
  $kernel->sig( 'HUP' => 'sig_hup' );
  my $denial = Net::Netmask->new2('default');
  my $exemption = Net::Netmask->new2('127.0.0');
  $heap->{ircd}->add_denial( $denial ) if $denial;
  $heap->{ircd}->add_exemption( $exemption ) if $denial and $exemption;
  $heap->{ircd}->yield( 'register' );
  $heap->{ircd}->add_listener( port => 7667 );
  $heap->{ircd}->add_listener( port => 7668, auth => 0, antiflood => 0 );
  $heap->{ircd}->add_peer( name => 'irc2.gumbynet.org.uk', pass => 'op3rs3rv', rpass => 'op3rs3rv', type => 'r', raddress => '127.0.0.12', rport => 7666 );
  $heap->{ircd}->add_operator( { username => 'moo', password => 'fishdont' } );
  $heap->{ircd}->yield( 'add_spoofed_nick', { nick => 'OperServ', umode => 'oi', ircname => 'The OperServ bot' } );
  $heap->{ircd}->yield( 'daemon_cmd_join', 'OperServ', '#foo' );
  undef;
}

sub _default {
  my ( $event, $args ) = @_[ ARG0 .. $#_ ];
  print STDOUT "$event: ";
  #print STDOUT Dumper(@$args) unless $event eq "ircd_registered";
  #print STDOUT "\n";
  #return 0;
  foreach (@$args) {
    SWITCH: {
        if ( ref($_) eq 'ARRAY' ) {
            print STDOUT "[", join ( ", ", @$_ ), "] ";
	    last SWITCH;
        } 
        if ( ref($_) eq 'HASH' ) {
            print STDOUT "{", join ( ", ", %$_ ), "} ";
	    last SWITCH;
        } 
        print STDOUT "'$_' ";
    }
  }
  print STDOUT "\n";
  return 0;    # Don't handle signals.  
}

sub sig_hup {
  my ($kernel,$heap) = @_[KERNEL,HEAP];
  $heap->{ircd}->yield( 'del_spoofed_nick' => 'OperServ' => 'ARGH! SIGHUP!' );
  $kernel->sig_handled();
}

sub ircd_daemon_join {
  my ($kernel,$heap) = @_[KERNEL,HEAP];
  my $nick = ( split /!/, $_[ARG0] )[0];
  return if $nick eq 'OperServ';
  return unless $heap->{ircd}->_state_user_is_operator($nick);
  my $channel = $_[ARG1];
  return if $heap->{ircd}->_state_is_chan_op( $nick, $channel );
  $heap->{ircd}->daemon_server_mode( $channel, '+o', $nick );
  undef;
}

sub ircd_daemon_privmsg {
  my ($kernel,$heap) = @_[KERNEL,HEAP];
  my $nick = ( split /!/, $_[ARG0] )[0];
  return unless $heap->{ircd}->_state_user_is_operator($nick);
  my $target = $_[ARG1];
  $heap->{ircd}->yield( 'daemon_cmd_privmsg', $target, $nick, $_[ARG2] );
  undef;
}
