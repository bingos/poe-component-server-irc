use lib '../blib/lib';
use strict;
use warnings;
use POE qw(Component::Server::IRC);
use Net::Netmask;

my $pocosi = POE::Component::Server::IRC->create( auth => 1, options => { trace => 0 }, plugin_debug => 1, debug => 1, config => { servername => 'penguin2.gumbynet.org.uk' } );

POE::Session->create(
		package_states => [ 
			'main' => [ qw(_start) ],
		],
		options => { trace => 0 },
		heap => { ircd => $pocosi },
);

$poe_kernel->run();
exit 0;

sub _start {
  my ($kernel,$heap) = @_[KERNEL,HEAP];

  my $denial = Net::Netmask->new2('default');
  my $exemption = Net::Netmask->new2('127.0.0');
  $heap->{ircd}->add_denial( $denial ) if $denial;
  $heap->{ircd}->add_exemption( $exemption ) if $denial and $exemption;
  $heap->{ircd}->yield( 'register' );
  $heap->{ircd}->add_listener( port => 7667 );
  $heap->{ircd}->add_listener( port => 7668, auth => 0, antiflood => 0 );
  $heap->{ircd}->daemon->add_peer( name => 'logserv.gumbynet.org.uk', pass => 'op3rs3rv', rpass => 'op3rs3rv' );
  $heap->{ircd}->daemon->add_operator( { username => 'moo', password => 'fishdont' } );
  undef;
}

sub _default {
  my ( $event, $args ) = @_[ ARG0 .. $#_ ];
  print STDOUT "$event: ";

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
