package POE::Component::Server::IRC::Backend;

use POE qw(Wheel::SocketFactory Wheel::ReadWrite Filter::Stackable Filter::Line Filter::IRCD);
use Socket;
use Carp;
use vars qw($VERSION);

$VERSION = '0.6';

sub spawn {
  my ($package) = shift;
  my %parms = @_;
  #ToDo: croak on uneven parameter list.

  foreach ( keys %parms ) {
	$parms{ lc($_) } = delete $parms{$_};
  }

  my $self = bless \%parms, $package;

  $self->{session_id} = POE::Session->create(
	object_states => [
		$self => [ qw(_start add_listener register shutdown unregister) ],
	],
	( ref($options) eq 'HASH' ? ( options => $options ) : () ),
  )->ID();

  return $self;
}

sub _start {
  my ($kernel,$self) = @_[KERNEL,OBJECT];

  if ( $Self->{alias} ) {
	$kernel->alias_set( $self->{alias} );
  } else {
	$kernel->refcount_increment( $self->{session_id} => __PACKAGE__ );
  }

  $self->{filter} = POE::Filter::Stackable->new();
  $self->{ircd_filter} = POE::Filter::IRCD->new( DEBUG => $self->{debug} );
  $self->{filter}->push( POE::Filter::Line->new( InputRegexp => '\015?\012', OutputLiteral => "\015\012" ), 
			 $self->{ircd_filter} );

  $self->{can_do_auth} = 0;
  eval {
	require POE::Component::Client::Ident;
	require POE::Component::Client::DNS;
  };
  unless ( $@ ) {
	$self->{ident_client} = 'poco_ident_' . $self->{session_id};
	POE::Component::Client::Ident->spawn( $self->{ident_client} );
	$self->{resolver} = POE::Component::Client::DNS->spawn( Alias => 'poco_dns_' . $self->{session_id}, Timeout => 10 );
	$self->{can_do_auth} = 1;
  }
  $self->{will_do_auth} = 0;
  if ( $self->{auth} and $self->{can_do_auth} ) {
	$self->{will_do_auth} = 1;
  }
  undef;
}

###################
# Control methods #
###################

sub register {
}

sub unregister {
}

sub shutdown {
  my ($kernel,$self) = @_[KERNEL,OBJECT];

  if ( $self->{alias} ) {
	$kernel->alias_remove( $_ ) for $kernel->alias_list();
  } else {
	$kernel->refcount_decrement( $self->{session_id} => __PACKAGE__ );
  }

  #ToDo: Terminate listeners
  #ToDo: Terminate all connections gracefully
  
  $kernel->call( $self->{ident_client} => 'shutdown' );
  undef;
}

############################
# Listener related methods #
############################

sub add_listener {
}

sub _accept_failed {
}

sub _accept_connection {
}
