# Author: Chris "BinGOs" Williams
#
# This module may be used, modified, and distributed under the same
# terms as Perl itself. Please see the license that came with your Perl
# distribution for details.
#
package POE::Component::Server::IRC::Daemon;

use AnyData;
use POE::Component::Server::IRC::Plugin qw ( :ALL );
use Carp;
use vars qw($VERSION);

$VERSION = '0.31';

sub new {
  my ($package) = shift;
  croak "$package requires an even numbers of parameters\n" if @_ & 1;
  my %parms = @_;

  foreach my $key ( keys %parms ) {
	$parms{ lc $key } = delete $parms{ $key };
  }

  return bless \%parms, $package;
}

sub PCSI_register {
  my ($self,$ircd) = splice @_, 0, 2;

  $ircd->plugin_register( $self, 'SERVER', qw(all) );
  $self->{ircd} = $ircd;
  $self->_state_create();
  return 1;
}

sub PCSI_unregister {
  my ($self) = shift;

  delete ( $self->{ircd} );
  $self->_state_delete();
  return 1;
}

sub IRCD_connection {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id,$peeraddr,$peerport,$sockaddr,$sockport) = map { ${ $_ } } @_;

  #ToDo: Cleanup state for stale entries for this conn_id
  if ( $self->_connection_exists( $conn_id ) ) {
  	delete ( $self->{state}->{connections}->{ $conn_id } );
  }
  $self->{state}->{connections}->{ $conn_id }->{registered} = 0;
  $self->{state}->{connections}->{ $conn_id }->{socket} = [ $peeraddr, $peerport, $sockaddr, $sockport ];
  return PCSI_EAT_NONE;
}

sub IRCD_auth_done {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id,$ref) = map { ${ $_ } } @_;

  unless ( $self->_connection_exists( $conn_id ) ) {
	return PCSI_EAT_NONE;
  }

  $self->{state}->{connections}->{ $conn_id }->{auth} = $ref;
  #ToDo: Connection matches an I-line check goes here. Maybe.
  return PCSI_EAT_NONE;
}

sub IRCD_cmd_pass {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id,$input) = map { ${ $_ } } @_;
  return PCSI_EAT_NONE unless ( $self->_connection_exists( $conn_id ) );

  return PCSI_EAT_NONE;
}

sub IRCD_cmd_user {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id,$input) = map { ${ $_ } } @_;
  return PCSI_EAT_NONE unless ( $self->_connection_exists( $conn_id ) );

  return PCSI_EAT_NONE;
}

sub IRCD_cmd_server {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id,$input) = map { ${ $_ } } @_;
  return PCSI_EAT_NONE unless ( $self->_connection_exists( $conn_id ) );

  return PCSI_EAT_NONE;
}

sub IRCD_cmd_nick {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id,$input) = map { ${ $_ } } @_;
  return PCSI_EAT_NONE unless ( $self->_connection_exists( $conn_id ) );

  return PCSI_EAT_NONE;
}

sub IRCD_cmd_quit {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id,$input) = map { ${ $_ } } @_;
  return PCSI_EAT_NONE unless ( $self->_connection_exists( $conn_id ) );

  my ($peeraddr) = ( $ircd->connection_info( $conn_id ) )[0];
  my ($msg) = $input->{params}->[0] || 'Client Quit';
  $ircd->disconnect( $conn_id );
  $ircd->send_output( { command => 'ERROR', params => [ 'Closing link: ' . $peeraddr . ' (' . $msg . ')' ] }, $conn_id );
  return PCSI_EAT_NONE;
}

sub _connection_exists {
  my ($self) = shift;
  my ($conn_id) = shift || return 0;

  unless ( defined ( $self->{state}->{connections}->{ $conn_id } ) ) {
	return 0;
  }
  return 1;
}

sub _connection_registered {
  my ($self) = shift;
  my ($conn_id) = shift || return undef;

  unless ( $self->_connection_exists( $conn_id ) ) {
	return undef;
  }
  return $self->{state}->{connections}->{ $conn_id }->{registered};
}

#################
# State methods #
#################

sub _state_create {
  my ($self) = shift;

  $self->_state_delete();
  $self->{state}->{nicknames} = adTie( 'ARRAY', [ ], 'u', { cols => 'id,connid,nick,server,user,host,hops,ts', key => 'id' } );
  $self->{state}->{servers} = adTie( 'ARRAY', [ ['id','connid','server','delta'],[ $numeric, undef, $server, 0 ] ], 'u', { key => 'id' } );
  $self->{state}->{channels} = adTie( 'ARRAY', [ ], 'u', { cols => 'id,name,mode,chankey,chanlimit,topic,topic_ts,topic_by' } );
  $self->{state}->{channel_lists} = adTie( 'ARRAY', [ ], 'u', { cols => 'channel_id,nick_id' } );
  $self->{state}->{channel_bans} = adTie( 'ARRAY', [ ], 'u', { cols => 'channel_id,banmask,setby,ts' } );
  $self->{state}->{channel_excepts} = adTie( 'ARRAY', [ ], 'u', { cols => 'channel_id,excmask,setby,ts' } );
  $self->{state}->{channel_invites} = adTie( 'ARRAY', [ ], 'u', { cols => 'channel_id,invmask,setby,ts'} );
  return 1;
}

sub _state_delete {
  my ($self) = shift;

  delete $self->{state};
  return 1;
}

1;
