use lib '../blib/lib';
use strict;
use warnings;
use POE qw(Component::Server::IRC);
use Net::Netmask;
use Data::Dumper;

$Data::Dumper::Indent = 1;
$|=1;

my $pocosi = POE::Component::Server::IRC->spawn( auth => 1, options => { trace => 0 }, plugin_debug => 0, debug => 1, config => { servername => 'penguin2.gumbynet.org.uk' } );

POE::Session->create(
		package_states => [ 
			'main' => [ qw(_default _start sig_hup) ],
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
  $heap->{ircd}->add_peer( name => 'logserv.gumbynet.org.uk', pass => 'op3rs3rv', rpass => 'op3rs3rv' );
  $heap->{ircd}->add_operator( { username => 'moo', password => 'fishdont' } );
  $heap->{ircd}->yield( 'add_spoofed_nick', { nick => 'OperServ', umode => 'oi', ircname => 'The OperServ bot' } );
  $heap->{ircd}->yield( 'daemon_cmd_join', 'OperServ', '#foo' );
  undef;
}

sub _default {
  my ( $event, $args ) = @_[ ARG0 .. $#_ ];
  print STDOUT "$event: ";
  print STDOUT Dumper(@$args) unless $event eq "ircd_registered";
  print STDOUT "\n";
  return 0;
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
  print STDOUT Dumper($heap->{ircd}->{state});
  $heap->{ircd}->yield( 'del_spoofed_nick' => 'OperServ' => 'ARGH! SIGHUP!' );
  #$heap->{ircd}->yield( 'daemon_cmd_part' => 'OperServ' => '#foo' );
  $kernel->sig_handled();
}
