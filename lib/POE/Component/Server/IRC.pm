# Author: Chris "BinGOs" Williams
#
# This module may be used, modified, and distributed under the same
# terms as Perl itself. Please see the license that came with your Perl
# distribution for details.
#
package POE::Component::Server::IRC;

use POE;
use POE::Component::Server::IRC::Backend;
use POE::Component::Server::IRC::Plugin qw ( :ALL );
use Carp;
use vars qw($VERSION);

$VERSION = '0.31';

sub spawn {
  my ($package) = shift;
  croak "$package requires an even numbers of parameters\n" if @_ & 1;
  my %parms = @_;

  foreach my $key ( keys %parms ) {
	$parms{ lc $key } = delete $parms{ $key };
  }

  my $options = delete $parms{options};

  my $self = bless \%parms, $package;

  $self->{backend} = POE::Component::Server::IRC::Backend->create();

  $self->{session_id} = POE::Session->create(
	object_states => [
		$self => [ qw(_start shutdown) ],
	],
	( ref($options) eq 'HASH' ? ( options => $options ) : () ),
  )->ID();

  return $self;
}

sub PCSI_register {
  my ($self,$ircd) = splice @_, 0, 2;

  $ircd->plugin_register( $self, 'SERVER', qw(all) );
  return 1;
}

sub PCSI_unregister {
  return 1;
}

sub session_id {
  my ($self) = shift;

  return $self->{session_id};
}

sub yield {
  my ($self) = shift;

  $poe_kernel->post( $self->session_id() => @_ );
}

sub call {
  my ($self) = shift;

  $poe_kernel->call( $self->session_id() => @_ );
}

######################
# POE event handlers #
######################

sub _start {
  my ($kernel,$self) = @_[KERNEL,OBJECT];
  $self->{session_id} = $_[SESSION]->ID();

  if ( $self->{alias} ) {
	$kernel->alias_set( $self->{alias} );
  } else {
	$kernel->refcount_increment( $self->{session_id} => __PACKAGE__ );
  }

  $self->{backend}->plugin_add( __PACKAGE__ => $self );
  undef;
}

sub shutdown {
  my ($kernel,$self) = @_[KERNEL,OBJECT];

  if ( $self->{alias} ) {
	$kernel->alias_remove( $_ ) for $kernel->alias_list();
  } else {
	$kernel->refcount_decrement( $self->{session_id} => __PACKAGE__ );
  }
  $self->{backend}->yield( 'shutdown' );
  undef;
}

##########################
# Backend plugin methods #
##########################

sub _default {
  my ($self,$ircd) = splice @_, 0, 2;
  my ($event) = shift;

  print STDERR "Got an $event\n";
  
  return PCSI_EAT_NONE;
}

##############################
# State manipulation methods #
##############################

1;
