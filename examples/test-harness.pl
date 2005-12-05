use lib '../blib/lib';
use strict;
use warnings;
use POE qw(Component::Server::IRC);

my $pocosi = POE::Component::Server::IRC->create( auth => 1, options => { trace => 1 } );

POE::Session->create(
		package_states => [ 
			'main' => [ qw( _start _default) ],
		],
		options => { trace => 1 },
		heap => { ircd => $pocosi },
);

$poe_kernel->run();
exit 0;

sub _start {
  my ($kernel,$heap) = @_[KERNEL,HEAP];

  $heap->{ircd}->yield( 'register' );
  $heap->{ircd}->add_listener( port => 7667 );
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
