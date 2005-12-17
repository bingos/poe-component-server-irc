# Author: Chris "BinGOs" Williams
#
# This module may be used, modified, and distributed under the same
# terms as Perl itself. Please see the license that came with your Perl
# distribution for details.
#
package POE::Component::Server::IRC::Daemon;

use strict;
use warnings;
use POE::Component::Server::IRC::Plugin qw ( :ALL );
use POE::Component::Server::IRC::Common qw ( :ALL );
use Carp;
use Date::Format;
use Data::Dumper;
use vars qw($VERSION);

$VERSION = '0.31';

sub new {
  my ($package) = shift;
  croak "$package requires an even numbers of parameters\n" if @_ & 1;
  my %parms = @_;

  foreach my $key ( keys %parms ) {
	$parms{ lc $key } = delete $parms{ $key };
  }

  my $self = bless \%parms, $package;

  $self->configure();

  return $self;
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

sub IRCD_listener_add {
  my ($self,$ircd) = splice @_, 0, 2;
  return PCSI_EAT_NONE;
}

sub IRCD_connection {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id,$peeraddr,$peerport,$sockaddr,$sockport) = map { ${ $_ } } @_;

  #ToDo: Cleanup state for stale entries for this conn_id
  if ( $self->_connection_exists( $conn_id ) ) {
  	delete $self->{state}->{conns}->{ $conn_id };
  }
  $self->{state}->{conns}->{ $conn_id }->{registered} = 0;
  $self->{state}->{conns}->{ $conn_id }->{type} = 'u';
  $self->{state}->{conns}->{ $conn_id }->{seen} = time();
  $self->{state}->{conns}->{ $conn_id }->{socket} = [ $peeraddr, $peerport, $sockaddr, $sockport ];
  return PCSI_EAT_NONE;
}

sub IRCD_connection_flood {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id) = map { ${ $_ } } @_;
  $self->{ircd}->disconnect( $conn_id, 'Excess Flood' );
  $self->_send_output_to_client( $conn_id => { command => 'ERROR', params => [ 'Closing Link: ' . $self->client_ip( $conn_id ) . ' (Excess Flood)' ] } );
  return PCSI_EAT_NONE;
}

sub IRCD_connection_idle {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id,$interval) = map { ${ $_ } } @_;
  return PCSI_EAT_NONE unless $self->_connection_exists( $conn_id );
  my $conn = $self->{state}->{conns}->{ $conn_id };
  if ( $conn->{type} eq 'u' ) {
  	$self->{ircd}->disconnect( $conn_id, 'Connection timeout' );
  	$self->_send_output_to_client( $conn_id => { command => 'ERROR', params => [ 'Closing Link: ' . $self->client_ip( $conn_id ) . ' (Connection timeout)' ] } );
  	return PCSI_EAT_NONE;
  }
  if ( $conn->{pinged} ) {
	my $msg = 'Ping timeout: ' . ( time() - $conn->{seen} ) . ' seconds';
  	$self->{ircd}->disconnect( $conn_id, $msg );
  	$self->_send_output_to_client( $conn_id => { command => 'ERROR', params => [ 'Closing Link: ' . $self->client_ip( $conn_id ) . ' (' . $msg . ')' ] } );
  	return PCSI_EAT_NONE;
  }
  $conn->{pinged} = 1;
  $self->_send_output_to_client( $conn_id => { command => 'PING', params => [ ':' . $self->server_name() ] } );
  return PCSI_EAT_NONE;
}

sub IRCD_auth_done {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id,$ref) = map { ${ $_ } } @_;
  return PCSI_EAT_NONE unless $self->_connection_exists( $conn_id );
  $self->{state}->{conns}->{ $conn_id }->{auth} = $ref;
  $self->_client_register( $conn_id );
  return PCSI_EAT_NONE;
}

sub IRCD_disconnected {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id,$errstr) = map { ${ $_ } } @_;
  return PCSI_EAT_NONE unless $self->_connection_exists( $conn_id );

  SWITCH: {
    unless ( $self->_connection_registered( $conn_id ) ) {
	delete $self->{state}->{conns}->{ $conn_id };
	last SWITCH;
    }
    if ( $self->_connection_is_peer( $conn_id ) ) {
	last SWITCH;
    }
    if ( $self->_connection_is_client( $conn_id ) ) {
	$self->{ircd}->send_output( @{ $self->_daemon_cmd_quit( $self->client_nickname( $conn_id ) ) } );
	delete $self->{state}->{conns}->{ $conn_id };
	last SWITCH;
    }
  }
  return PCSI_EAT_NONE;
}

sub _default {
  my ($self,$ircd,$event) = splice @_, 0, 3;
  return PCSI_EAT_NONE unless ( $event =~ /^IRCD_cmd_/ );
  my ($conn_id,$input) = map { ${ $_ } } @_;

  return PCSI_EAT_NONE unless $self->_connection_exists( $conn_id );
  $self->{state}->{conns}->{ $conn_id }->{seen} = time();
  SWITCH: {
	# Registered ?
	  # no. okay is a valid command for an unreg'ed conn ?
		# No, tell them so.
		# Yes, process.
	# valid command for a reg'ed connection ?
		# No, bitch at connection.
	# Okay, start of our routing:
	 # Must be either a server or client connection by this point. Let's find out which.
	# Is connection type == 'server' ?
		# Yes, process as server.
	# Okay, must be a client by this point.
	 # Wipe out prefix, not should be ignored.
	# Process as client.
	unless ( $self->_connection_registered( $conn_id ) ) {
		$self->_cmd_from_unknown( $conn_id, $input );
		last SWITCH;
	}
	if ( $self->_connection_is_peer( $conn_id ) ) {
		$self->_cmd_from_peer( $conn_id, $input );
		last SWITCH;
	}
	if ( $self->_connection_is_client( $conn_id ) ) {
		delete $input->{prefix};
		$self->_cmd_from_client( $conn_id, $input );
		last SWITCH;
	}
  };

  return PCSI_EAT_NONE;
}

sub _auth_done {
  my ($self) = shift;
  my ($conn_id) = shift || return undef;
  return unless $self->_connection_exists( $conn_id );
  return $self->{state}->{conns}->{ $conn_id }->{auth};
}

sub _connection_exists {
  my $self = shift;
  my $conn_id = shift || return 0;
  return 0 unless defined $self->{state}->{conns}->{ $conn_id };
  return 1;
}

sub _client_register {
  my $self = shift;
  my $conn_id = shift || return undef;
  return unless $self->_connection_exists( $conn_id );
  return unless $self->{state}->{conns}->{ $conn_id }->{nick};
  return unless $self->{state}->{conns}->{ $conn_id }->{user};
  my $auth = $self->_auth_done( $conn_id );
  return unless $auth;
  # pass required for link
  # Add new nick
  $self->_state_register_client( $conn_id );
  my $server = $self->server_name();
  my $nick = $self->client_nickname( $conn_id );
  my $port = $self->{state}->{conns}->{ $conn_id }->{socket}->[3];
  my $version = $self->server_version();
  $self->_send_output_to_client( $conn_id => { prefix => $server, command => '001', params => [ $nick, "Welcome to the Internet Relay Chat network $nick" ] } );
  $self->_send_output_to_client( $conn_id => { prefix => $server, command => '002', params => [ $nick, "Your host is ${server}[${server}/${port}], running version $version" ] } );
  $self->_send_output_to_client( $conn_id => { prefix => $server, command => '003', params => [ $nick, $self->server_created() ] } );
  $self->_send_output_to_client( $conn_id => { prefix => $server, command => '004', params => [ $nick, $server, $version, 'oiw', 'biklmnopstveIh', 'bkloveIh' ] } );
  $self->_send_output_to_client( $conn_id => $_ ) for @{ $self->_daemon_cmd_isupport( $nick ) };
  $self->{state}->{conns}->{ $conn_id }->{registered} = 1;
  $self->{state}->{conns}->{ $conn_id }->{type} = 'c';
  $self->{ircd}->send_event( 'cmd_lusers' => $conn_id => { command => 'LUSERS' } );
  $self->{ircd}->send_event( 'cmd_motd' => $conn_id => { command => 'MOTD' } );
  $self->{ircd}->send_event( 'cmd_mode' => $conn_id => { command => 'MODE', params => [ $nick, '+i' ] } );
  #print STDERR Dumper( $self->{state} );
  return 1;
}

sub _connection_registered {
  my $self = shift;
  my $conn_id = shift || return undef;
  return unless $self->_connection_exists( $conn_id );
  return $self->{state}->{conns}->{ $conn_id }->{registered};
}

sub _connection_is_peer {
  my $self = shift;
  my $conn_id = shift || return undef;

  return unless $self->_connection_exists( $conn_id );
  return unless $self->{state}->{conns}->{ $conn_id }->{registered};
  return 1 if $self->{state}->{conns}->{ $conn_id }->{type} eq 'p';
  return 0;
}

sub _connection_is_client {
  my $self = shift;
  my $conn_id = shift || return undef;

  return unless $self->_connection_exists( $conn_id );
  return unless $self->{state}->{conns}->{ $conn_id }->{registered};
  return 1 if $self->{state}->{conns}->{ $conn_id }->{type} eq 'c';
  return 0;
}

sub _cmd_from_unknown {
  my ($self,$wheel_id,$input) = splice @_, 0, 3;

  my $cmd = uc $input->{command};
  my $params = $input->{params} || [ ];
  my $pcount = scalar @{ $params };
  SWITCH: {
    if ( $cmd eq 'QUIT' ) {
	$self->{ircd}->disconnect( $wheel_id );
	$self->_send_output_to_client( $wheel_id => { command => 'ERROR', params => [ 'Closing Link: ' . $self->client_ip( $wheel_id ) . ' (Client Quit)' ] } );
	last SWITCH;
    }
    # PASS or NICK cmd but no parameters.
    if ( $cmd =~ /^(PASS|NICK)$/ and !$pcount ) {
	$self->_send_output_to_client( $wheel_id => '461' => $cmd );
	last SWITCH;
    }
    # PASS or NICK cmd with one parameter, connection from client
    if ( $cmd eq 'PASS' and $pcount ) {
	$self->{state}->{conns}->{ $wheel_id }->{ lc $cmd } = $params->[0];
	last SWITCH;
    }
    if ( $cmd eq 'NICK' and $pcount ) {
	if ( !validate_nick_name( $params->[0] ) ) {
	  $self->_send_output_to_client( $wheel_id => '432' => $params->[0] );
	  last SWITCH;
	}
	if ( $self->_state_nick_exists( $params->[0] ) ) {
	  $self->_send_output_to_client( $wheel_id => '433' => $params->[0] );
	  last SWITCH;
	}
	my $nicklen = $self->server_config('NICKLEN');
	$params->[0] = substr($params->[0],0,$nicklen) if length( $params->[0] ) > $nicklen;
	$self->{state}->{conns}->{ $wheel_id }->{ lc $cmd } = $params->[0];
	$self->_client_register( $wheel_id );
	last SWITCH;
    }
    if ( $cmd eq 'USER' and $pcount < 4 ) {
	$self->_send_output_to_client( $wheel_id => '461' => $cmd );
	last SWITCH;
    }
    if ( $cmd eq 'USER' ) {
	$self->{state}->{conns}->{ $wheel_id }->{user} = $params->[0];
	$self->{state}->{conns}->{ $wheel_id }->{ircname} = $params->[3] || '';
	$self->_client_register( $wheel_id );
	last SWITCH;
    }
    $self->_send_output_to_client( $wheel_id => '451' );
  }
  return 1;
}

sub _cmd_from_peer {
  my ($self,$conn_id,$input) = splice @_, 0, 3;

  my $cmd = $input->{command};
  my $params = $input->{params};
  my $prefix = $input->{prefix};
  SWITCH: {
	last SWITCH;
  }
  return 1;
}

sub _cmd_from_client {
  my ($self,$wheel_id,$input) = splice @_, 0, 3;

  my $cmd = uc $input->{command};
  my $params = $input->{params} || [ ];
  my $pcount = scalar @{ $params };
  my $server = $self->server_name();
  my $nick = $self->client_nickname( $wheel_id );
  SWITCH: {
    my $method = '_daemon_cmd_' . lc $cmd;
    if ( $cmd eq 'QUIT' ) {
	$self->{ircd}->disconnect( $wheel_id, ( $pcount ? $params->[0] : 'Client Quit' ) );
	$self->_send_output_to_client( $wheel_id => { command => 'ERROR', params => [ 'Closing Link: ' . $self->client_ip( $wheel_id ) . ' (Client Quit)' ] } );
	last SWITCH;
    }
    if ( $cmd =~ /^(USERHOST|MODE)$/ and !$pcount ) {
	$self->_send_output_to_client( $wheel_id => '461' => $cmd );
	last SWITCH;
    }
    if ( $cmd =~ /^(USERHOST)$/ ) {
	$self->_send_output_to_client( $wheel_id => $_ ) for $self->$method( $nick, ( $pcount <= 5 ? @{ $params } : @{ $params }[0..5] ) );
	last SWITCH;
    }
    if ( $cmd eq 'MODE' and $self->_state_nick_exists( $params->[0] ) ) {
	if ( ( u_irc $nick ) ne ( u_irc $params->[0] ) ) {
		$self->_send_output_to_client( $wheel_id => '502' );
		last SWITCH;
	}
	my $modestring = join('', @{ $params }[1..$#{ $params }] );
	$modestring =~ s/\s+//g;
	$modestring =~ s/[^a-zA-Z+-]+//g;
	$modestring =~ s/[^wio+-]+//g;
	$modestring = unparse_mode_line $modestring;
	$self->_send_output_to_client( $wheel_id => $_ ) for $self->_daemon_cmd_umode( $nick, $modestring );
	last SWITCH;
    }
    if ( $self->can($method) ) {
	$self->_send_output_to_client( $wheel_id => ( ref $_ eq 'ARRAY' ? @{ $_ } : $_ ) ) for $self->$method( $nick, @{ $params } );
	last SWITCH;
    }
    $self->_send_output_to_client( $wheel_id => '421' => $cmd );
  }
  return 1;
}

sub _daemon_cmd_quit {
  my $self = shift;
  my $nick = shift || return;
  my $qmsg = shift || 'Client Quit';
  my $ref = [ ];
  my $full = $self->_state_user_full( $nick );

  push( @{ $ref }, { prefix => $full, command => 'QUIT', params => [ $qmsg ] } );
  # Get conn_ids for each of our peers.
  push @{ $ref }, $_ for $self->_state_connected_peers();
  # Okay, all 'local' users who share a common channel with user.
  my $common = { };
  foreach my $uchan ( $self->_state_user_chans( $nick ) ) {
    delete $self->{state}->{chans}->{ u_irc( $uchan ) }->{users}->{ u_irc( $nick ) };
    foreach my $user ( $self->_state_chan_list( $uchan ) ) {
	next unless $self->_state_is_local_user( $user );
	$common->{ $user } = $self->_state_user_route( $user );
    }
  }
  push( @{ $ref }, $common->{$_} ) for keys %{ $common };
  $nick = u_irc( $nick );
  my $record = delete $self->{state}->{users}->{ $nick };
  my $server = uc $record->{server};
  delete $self->{state}->{peers}->{ $server }->{users}->{ $nick };
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_ping {
  my $self = shift;
  my $nick = shift || return;
  my $server = uc $self->server_name();
  my $args = [ @_ ]; my $count = scalar @{ $args };
  my $ref = [ ];
  SWITCH: {
     if ( !$count ) {
	push @{ $ref }, [ '409' ];
	last SWITCH;
     }
     if ( $count >= 2 and !$self->_state_peer_exists( $args->[1] ) ) {
	push @{ $ref }, [ '402', $args->[1] ];
	last SWITCH;
     } 
     if ( $count >= 2 and ( uc $args->[1] ne uc $server ) ) {
	my $target = $self->_state_peer_name( $args->[1] );
	$self->{ircd}->send_output( { command => 'PING', params => [ $nick, $target ] }, $self->_state_peer_route( $args->[1] ) );
	last SWITCH;
     }
     push @{ $ref }, { command => 'PONG', params => [ $server, $args->[0] ] };
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_pong {
  my $self = shift;
  my $nick = shift || return;
  my $server = uc $self->server_name();
  my $args = [ @_ ]; my $count = scalar @{ $args };
  my $ref = [ ];
  SWITCH: {
     if ( !$count ) {
	push @{ $ref }, [ '409' ];
	last SWITCH;
     }
     if ( $count >= 2 and !$self->_state_peer_exists( $args->[1] ) ) {
	push @{ $ref }, [ '402', $args->[1] ];
	last SWITCH;
     } 
     if ( $count >= 2 and ( uc $args->[1] ne uc $server ) ) {
	my $target = $self->_state_peer_name( $args->[1] );
	$self->{ircd}->send_output( { command => 'PONG', params => [ $nick, $target ] }, $self->_state_peer_route( $args->[1] ) );
	last SWITCH;
     }
     delete $self->{state}->{users}->{ u_irc $nick }->{pinged};
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_pass {
  my $self = shift;
  my $nick = shift || return;
  my $server = uc $self->server_name();
  my $ref = [ [ '462' ] ];
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_user {
  my $self = shift;
  my $nick = shift || return;
  my $server = uc $self->server_name();
  my $ref = [ [ '462' ] ];
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_nick {
  my $self = shift;
  my $nick = shift || return;
  my $new = shift;
  my $server = uc $self->server_name();
  my $ref = [ ];
  SWITCH: {
    if ( !$new ) {
	push @{ $ref }, [ '431' ];
	last SWITCH;
    }
    my $nicklen = $self->server_config('NICKLEN');
    $new = substr($new,0,$nicklen) if length($new) > $nicklen;
    if ( $nick eq $new ) {
	last SWITCH;
    }
    if ( !validate_nick_name( $new ) ) {
	push @{ $ref }, [ '432', $new ];
	last SWITCH;
    }
    my $unick = u_irc $nick;
    my $unew = u_irc $new;
    if ( $self->_state_nick_exists( $new ) and $unick ne $unew ) {
	push @{ $ref }, [ '433', $new ];
	last SWITCH;
    }
    my $full = $self->_state_user_full( $nick );
    my $record = $self->{state}->{users}->{ $unick };
    if ( $unick eq $unew ) {
	$record->{nick} = $new;
    } else {
	$record->{nick} = $new;
	delete $self->{state}->{users}->{ $unick };
	$self->{state}->{users}->{ $unew } = $record;
	delete $self->{state}->{peers}->{ $server }->{users}->{ $unick };
	$self->{state}->{peers}->{ $server }->{users}->{ $unew } = $record;
	foreach my $chan ( keys %{ $record->{chans} } ) {
	   $self->{state}->{chans}->{ $chan }->{users}->{ $unew } = delete $self->{state}->{chans}->{ $chan }->{users}->{ $unick };
	}
    }
    my @peers = $self->_state_connected_peers();
    my $common = { $nick => $record->{route_id} };
    foreach my $chan ( keys %{ $record->{chans} } ) {
      foreach my $user ( $self->_state_chan_list( $chan ) ) {
	next unless $self->_state_is_local_user( $user );
	$common->{ $user } = $self->_state_user_route( $user );
      }
    }
    $self->{ircd}->send_output( { prefix => $full, command => 'NICK', params => [ $new ] }, @peers, map{ $common->{$_} } keys %{ $common } );
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_away {
  my $self = shift;
  my $nick = shift || return;
  my $msg = shift;
  my $server = $self->server_name();
  my $ref = [ ];
  SWITCH: {
     my $record = $self->{state}->{users}->{ u_irc $nick };
     if ( !$msg ) {
	$record->{umode} =~ s/a//g;
	delete $record->{away};
	push @{ $ref }, { prefix => $server, command => '305', params => [ 'You are no longer marked as being away' ] };
	last SWITCH;
     }
     $record->{umode} .= 'a' unless $record->{umode} =~ /a/;
     $record->{away} = $msg;
     push @{ $ref }, { prefix => $server, command => '306', params => [ 'You have been marked as being away' ] };
  }
  return @{ $ref } if wantarray();
  return $ref;
}

# Pseudo cmd for ISupport 005 numerics
sub _daemon_cmd_isupport {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ];
  push @{ $ref }, { prefix => $server, command => '005', params => [ $nick, join(' ', map { ( defined ( $self->{config}->{isupport}->{$_} ) ? join('=', $_, $self->{config}->{isupport}->{$_} ) : $_ ) } qw(EXCEPTS INVEX MAXCHANNELS MAXBANS MAXTARGETS NICKLEN TOPICLEN KICKLEN) ), 'are supported by this server' ] };
  push @{ $ref }, { prefix => $server, command => '005', params => [ $nick, join(' ', map { ( defined ( $self->{config}->{isupport}->{$_} ) ? join('=', $_, $self->{config}->{isupport}->{$_} ) : $_ ) } qw(CHANTYPES PREFIX CHANMODES NETWORK CASEMAPPING) ), 'are supported by this server' ] };
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_info {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ];

  push( @{ $ref }, { prefix => $server, command => '371', params => [ $nick, ( / / ? $_ : ":$_" ) ] } ) for @{ $self->server_config('Info') };
  push( @{ $ref }, { prefix => $server, command => '374', params => [ $nick, 'End of /INFO list.' ] } );

  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_version {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ];
  push @{ $ref }, { prefix => $server, command => '351', params => [ $nick, $self->server_version(), $server, 'eGHIMZ', 'TS5ow' ] };
  push @{ $ref }, $_ for @{ $self->_daemon_cmd_isupport( $nick ) };
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_admin {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $admin = $self->server_config('Admin');
  push @{ $ref }, { prefix => $server, command => '256', params => [ $nick, $server, 'Administrative Info' ] };
  push @{ $ref }, { prefix => $server, command => '257', params => [ $nick, $admin->[0] ] };
  push @{ $ref }, { prefix => $server, command => '258', params => [ $nick, $admin->[1] ] };
  push @{ $ref }, { prefix => $server, command => '259', params => [ $nick, $admin->[2] ] };
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_summon {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ];
  push ( @{ $ref }, '445' );
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_time {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ];
  push @{ $ref }, { prefix => $server, command => '351', params => [ $nick, $server, time2str( "%A %B %e %Y -- %T %z", time() ) ] };
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_lusers {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ];

  my $users = scalar keys %{ $self->{state}->{users} };
  my $servers = scalar keys %{ $self->{state}->{peers} };
  my $chans = scalar keys %{ $self->{state}->{chans} };
  push( @{ $ref }, { prefix => $server, command => '251', params =>[ $nick, "There are $users users on $servers servers" ] } );
  $servers--;
  push( @{ $ref }, { prefix => $server, command => '254', params =>[ $nick, $chans, "channels formed" ] } ) if $chans;
  push( @{ $ref }, { prefix => $server, command => '255', params =>[ $nick, "I have $users clients and $servers servers" ] } );

  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_motd {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $motd = $self->server_config('MOTD');

  if ( $motd and ref $motd eq 'ARRAY' ) {
    push( @{ $ref }, { prefix => $server, command => '375', params => [ $nick, "- $server Message of the day - " ] } );
    push( @{ $ref }, { prefix => $server, command => '372', params => [ $nick, "- $_" ] } ) for ( @{ $motd } );
    push( @{ $ref }, { prefix => $server, command => '376', params => [ $nick, "End of MOTD command" ] } );
  } else {
    push( @{ $ref }, '422' );
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_userhost {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $str = '';

  foreach my $query ( @_ ) {
    my ($proper,$userhost) = split /!/, $self->_state_user_full( $query );
    $str = join(' ', $str, $proper . ( $self->_state_user_is_operator($proper) ? '*' : '' ) . '=' . ( $self->_state_user_away($proper) ? '-' : '+' ) . $userhost ) if $proper and $userhost;
  }

  push( @{ $ref }, { prefix => $server, command => '302', params => [ $nick, ( $str ? $str : ':' ) ] } );

  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_ison {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    if ( !$count ) {
	push @{ $ref }, [ '461', 'ISON' ];
	last SWITCH;
    }
    my $string = '';
    $string = join ' ', map { $self->{state}->{users}->{ u_irc $_ }->{nick} } grep { $self->_state_nick_exists($_) } @{ $args };
    push @{ $ref }, { prefix => $server, command => '303', params => [ $nick, ( $string =~ /\s+/ ? $string : ":$string" ) ] };
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_list {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    my @chans;
    if ( !$count ) {
	@chans = map { $self->_state_chan_name($_) } keys %{ $self->{state}->{chans} };
    }
    my $last = pop @{ $args };
    if ( $count and $last !~ /^(\x23|\x26|\x2B)/ and !$self->_state_peer_exists( $last ) ) {
        push @{ $ref }, [ '401', $last ];
        last SWITCH;
    }
    if ( $count and $last !~ /^(\x23|\x26|\x2B)/ and ( uc $last ne uc $server ) ) {
        $self->{ircd}->send_output( { prefix => $self->_state_user_full( $nick ), command => 'LIST', params => [ @{ $args }, $self->_state_peer_name( $last ) ] }, $self->_state_peer_route( $last ) );
        last SWITCH;
    }
    if ( $count and $last !~ /^(\x23|\x26|\x2B)/ and scalar @{ $args } == 0 ) {
	@chans = map { $self->_state_chan_name($_) } keys %{ $self->{state}->{chans} };
    }
    if ( $count and $last !~ /^(\x23|\x26|\x2B)/ and scalar @{ $args } == 1 ) {
        $last = pop @{ $args };
    }
    if ( $count and $last =~ /^(\x23|\x26|\x2B)/ ) {
	@chans = split /,/, $last;
    }
    push @{ $ref }, { prefix => $server, command => '321', params => [ $nick, 'Channel', 'Users  Name' ] };
    my $count = 0;
    INNER: foreach my $chan (@chans) {
	unless ( validate_chan_name( $chan ) and $self->_state_chan_exists( $chan ) ) {
	  unless ( $count ) {
		push @{ $ref }, [ '401', $chan ];
	  	last INNER;
	  }
	  $count++;
	  next INNER;
	}
	$count++;
	next INNER if $self->_state_chan_mode_set( $chan, 'p' ) or $self->_state_chan_mode_set( $chan, 's' ) and !$self->_state_is_chan_member( $nick, $chan );
	my $record = $self->{state}->{chans}->{ u_irc $chan };
	push @{ $ref }, { prefix => $server, command => '322', params => [ $nick, $record->{name}, scalar keys %{ $record->{users} }, ( defined $record->{topic} ? $record->{topic} : ':' ) ] };
    }
    push @{ $ref }, { prefix => $server, command => '323', params => [ $nick, 'End of /LIST' ] };
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_names {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    my @chans; my $query;
    if ( !$count ) {
	@chans = $self->_state_user_chans( $nick );
	$query = '*';
    }
    my $last = pop @{ $args };
    if ( $count and $last !~ /^(\x23|\x26|\x2B)/ and !$self->_state_peer_exists( $last ) ) {
	push @{ $ref }, [ '401', $last ];
	last SWITCH;
    }
    if ( $count and $last !~ /^(\x23|\x26|\x2B)/ and ( uc $last ne uc $server ) ) {
	$self->{ircd}->send_output( { prefix => $self->_state_user_full( $nick ), command => 'NAMES', params => [ @{ $args }, $self->_state_peer_name( $last ) ] }, $self->_state_peer_route( $last ) );
	last SWITCH;
    }
    if ( $count and $last !~ /^(\x23|\x26|\x2B)/ and scalar @{ $args } == 0 ) {
	@chans = $self->_state_user_chans( $nick );
	$query = '*';
    }
    if ( $count and $last !~ /^(\x23|\x26|\x2B)/ and scalar @{ $args } == 1 ) {
	$last = pop @{ $args };
    }
    if ( $count and $last =~ /^(\x23|\x26|\x2B)/ ) {
	my ($chan) = grep { $_ &&
			    $self->_state_chan_exists( $_ ) && 
			    $self->_state_is_chan_member( $nick, $_ ) 
			  } split /,/, $last;
	@chans = ();
	if ( $chan ) {
	  push @chans, $chan;
	  $query = $self->_state_chan_name( $chan );
	} else {
	  $query = '*';
	}
    }
    foreach my $chan ( @chans ) {
	my $record = $self->{state}->{chans}->{ u_irc $chan };
	my $type = '=';
	$type = '@' if $record->{mode} =~ /s/;
	$type = '*' if $record->{mode} =~ /p/;
	push @{ $ref }, { prefix => $server, command => '353', params => [ $nick, $type, $record->{name}, join(' ', $self->_state_chan_list_prefixed( $record->{name} ) ) ] };
    }
    push @{ $ref }, { prefix => $server, command => '366', params => [ $nick, $query, 'End of NAMES list' ] };
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_whois {
  my $self = shift;
  my $nick = shift || return;
  my ($first,$second) = @_;
  my $server = $self->server_name();
  my $ref = [ ];
  SWITCH: {
    if ( !$first and !$second ) {
	push @{ $ref }, [ '431' ];
	last SWITCH;
    }
    if ( !$second and $first ) {
	$second = ( split /,/, $first )[0];
	$first = $server;
    }
    if ( $first and $second ) {
	$second = ( split /,/, $second )[0];
    } 
    if ( u_irc( $first ) eq u_irc( $second ) and $self->_state_nick_exists( $second ) ) {
	$first = $self->_state_user_server( $second );
    }
    my $query;
    my $target;
    $query = $first unless $second;
    $query = $second if $second;
    $target = $first if $second and uc( $first ) ne uc( $server );
    if ( $target and !$self->_state_peer_exists( $target ) ) {
	push @{ $ref }, [ '402', $target ];
	last SWITCH;
    }
    if ( $target ) {
	$self->{ircd}->send_output( { prefix => $self->_state_user_full( $nick ), command => 'WHOIS', params => [ $self->_state_peer_name( $target ), $second ] }, $self->_state_peer_route( $target ) );
	last SWITCH;
    }
    # Okay we got here *phew*
    if ( !$self->_state_nick_exists( $query ) ) {
	push @{ $ref }, [ '401', $query ];
    } else {
	my $record = $self->{state}->{users}->{ u_irc $query };
	push @{ $ref }, { prefix => $server, command => '311', params => [ $nick, $record->{nick}, $record->{auth}->{ident}, $record->{auth}->{hostname}, '*', ( $record->{ircname} =~ /\s+/ ? $record->{ircname} : ':' . $record->{ircname} ) ] };
        my @chans;
	LOOP: foreach my $chan ( keys %{ $record->{chans} } ) {
	  next LOOP if $self->{state}->{chans}->{ $chan }->{mode} =~ /[ps]/ and !$self->_state_is_chan_member( $nick, $chan );
	  my $prefix = '';
	  $prefix .= '@' if $record->{chans}->{ $chan } =~ /o/;
	  $prefix .= '%' if $record->{chans}->{ $chan } =~ /h/;
	  $prefix .= '+' if $record->{chans}->{ $chan } =~ /v/;
	  push @chans, $prefix . $self->{state}->{chans}->{ $chan }->{name};
        }
	push @{ $ref }, { prefix => $server, command => '319', params => [ $nick, $record->{nick}, join(' ', @chans) ] } if scalar @chans;
	push @{ $ref }, { prefix => $server, command => '312', params => [ $nick, $record->{nick}, $record->{server}, $self->_state_peer_desc( $record->{server} ) ] };
	push @{ $ref }, { prefix => $server, command => '301', params => [ $nick, $record->{nick}, ( $record->{away} =~ /\s+/ ? $record->{away} : ':' . $record->{away} ) ] } if $record->{type} eq 'c' and $record->{umode} =~ /a/;
	push @{ $ref }, { prefix => $server, command => '313', params => [ $nick, $record->{nick}, 'is an IRC Operator' ] } if $record->{umode} =~ /o/;
	push @{ $ref }, { prefix => $server, command => '317', params => [ $nick, $record->{nick}, ( time() - $record->{idle_time} ), $record->{conn_time}, 'seconds idle, signon time' ] } if $record->{type} eq 'c';
    }
    push @{ $ref }, { prefix => $server, command => '318', params => [ $nick, $query, 'End of /WHOIS list.' ] };
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_who {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my ($who,$op_only) = splice @_, 0, 2;
  my $ref = [ ];
  SWITCH: {
    if ( !$who ) {
	push @{ $ref }, [ '461', 'WHO' ];
	last SWITCH;
    }
    if ( $self->_state_chan_exists( $who ) and $self->_state_is_chan_member( $nick, $who ) ) {
	my $record = $self->{state}->{chans}->{ u_irc $who };
	$who = $record->{name};
	foreach my $member ( keys %{ $record->{users} } ) {
	  my $rpl_who = { prefix => $server, command => '352', params => [ $nick, $who ] };
	  my $memrec = $self->{state}->{users}->{ $member };
	  push @{ $rpl_who->{params} }, $memrec->{auth}->{ident};
	  push @{ $rpl_who->{params} }, $memrec->{auth}->{hostname};
	  push @{ $rpl_who->{params} }, $memrec->{server};
	  push @{ $rpl_who->{params} }, $memrec->{nick};
          my $status = ( $memrec->{umode} =~ /a/ ? 'G' : 'H' );
	  $status .= '*' if $memrec->{umode} =~ /o/;
	  $status .= '@' if $record->{users}->{ $member } =~ /o/;
	  $status .= '%' if $record->{users}->{ $member } =~ /h/;
	  $status .= '+' if $record->{users}->{ $member } !~ /o/ and $record->{users}->{ $member } =~ /v/;
	  push @{ $rpl_who->{params} }, $status;
	  push @{ $rpl_who->{params} }, $memrec->{hops} . ' ' . $memrec->{ircname};
	  push @{ $ref }, $rpl_who;
	}
    }
    if ( $self->_state_nick_exists( $who ) ) {
	my $nickrec = $self->{state}->{users}->{ u_irc $who };
	$who = $nickrec->{nick};
	my $rpl_who = { prefix => $server, command => '352', params => [ $nick, '*' ] };
	push @{ $rpl_who->{params} }, $nickrec->{auth}->{ident};
        push @{ $rpl_who->{params} }, $nickrec->{auth}->{hostname};
        push @{ $rpl_who->{params} }, $nickrec->{server};
        push @{ $rpl_who->{params} }, $nickrec->{nick};
        my $status = ( $nickrec->{umode} =~ /a/ ? 'G' : 'H' );
	$status .= '*' if $nickrec->{umode} =~ /o/;
	push @{ $rpl_who->{params} }, $status;
	push @{ $rpl_who->{params} }, $nickrec->{hops} . ' ' . $nickrec->{ircname};
	push @{ $ref }, $rpl_who;
    }
    push @{ $ref }, { prefix => $server, command => '315', params => [ $nick, $who, 'End of WHO list' ] };
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_mode {
  my $self = shift;
  my $nick = shift || return;
  my $chan = shift;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    if ( !$self->_state_chan_exists( $chan ) ) {
	push @{ $ref }, [ '403', $chan ];
	last SWITCH;
    }
    my $record = $self->{state}->{chans}->{ u_irc $chan };
    $chan = $record->{name};
    if ( $chan =~ /^\x2B/ ) {
	push @{ $ref }, [ '477', $chan ];
	last SWITCH;
    }
    if ( !$count and !$self->_state_is_chan_member( $nick, $chan ) ) {
	push @{ $ref }, { prefix => $server, command => '324', params => [ $nick, '+' . $record->{mode} ] };
	push @{ $ref }, { prefix => $server, command => '329', params => [ $nick, $record->{ts} ] };
	last SWITCH;
    }
    if ( !$count ) {
	push @{ $ref }, { prefix => $server, command => '324', params => [ $nick, '+' . $record->{mode}, ( $record->{ckey} || () ), ( $record->{climit} || () ) ] };
	push @{ $ref }, { prefix => $server, command => '329', params => [ $nick, $record->{ts} ] };
	last SWITCH;
    }
    my $unknown = 0;
    my $notop = 0;
    my $nick_is_op = $self->_state_is_chan_op( $nick, $chan );
    my $reply; my @reply_args;
    my $parsed_mode = parse_mode_line( @{ $args } );
    while( my $mode = shift ( @{ $parsed_mode->{modes} } ) ) {
      if ( $mode !~ /[eIbklimnpstohv]/ ) {
	push @{ $ref }, [ '472', ( split //, $mode )[1] ] unless $unknown;
	$unknown++;
	next;
      }
      my $arg;
      $arg = shift ( @{ $parsed_mode->{args} } ) if ( $mode =~ /^(\+[ovklbIe]|-[ovbIe])/ );
      if ( $mode =~ /(\+|-)b/ and !defined $arg ) {
	push @{ $ref }, { prefix => $server, command => '367', params => [ $nick, $chan, @{ $record->{bans}->{$_} } ] } for keys %{ $record->{bans} };
	push @{ $ref }, { prefix => $server, command => '368', params => [ $nick, $chan, 'End of Channel Ban List' ] };
	next;
      }
      if ( !$nick_is_op ) {
	push @{ $ref }, [ '482', $chan ] unless $notop;
	$notop++;
	next;
      }
      if ( $mode =~ /(\+|-)I/ and !defined $arg ) {
	push @{ $ref }, { prefix => $server, command => '346', params => [ $nick, $chan, @{ $record->{invex}->{$_} } ] } for keys %{ $record->{invex} };
	push @{ $ref }, { prefix => $server, command => '347', params => [ $nick, $chan, 'End of Channel Invite List' ] };
	next;
      }
      if ( $mode =~ /(\+|-)e/ and !defined $arg ) {
	push @{ $ref }, { prefix => $server, command => '348', params => [ $nick, $chan, @{ $record->{excepts}->{$_} } ] } for keys %{ $record->{excepts} };
	push @{ $ref }, { prefix => $server, command => '349', params => [ $nick, $chan, 'End of Channel Exception List' ] };
	next;
      }
      if ( ( $mode =~ /^(\+|-)([ohv])/ or $mode =~ /^\+[lk]/ ) and !defined $arg ) {
	next;
      }
      if ( $mode =~ /^(\+|-)([ohv])/ and !$self->_state_nick_exists($arg) ) {
	push @{ $ref }, [ '401', $arg ];
	next;
      }
      if ( $mode =~ /^(\+|-)([ohv])/ and !$self->_state_is_chan_member( $arg, $chan ) ) {
	push @{ $ref }, [ '441', $chan, (split /!/, $self->_state_user_full( $arg ))[0] ];
	next;
      }
      if ( my ($flag,$char) = $mode =~ /^(\+|-)([ohv])/ ) {
	if ( $flag eq '+' and $record->{users}->{ u_irc $arg } !~ /$char/ ) {
	  # Update user and chan record
	  $arg = u_irc $arg;
	  $record->{users}->{ $arg } .= $char;
	  $self->{state}->{users}->{ $arg }->{chans}->{ u_irc $chan } = $record->{users}->{ $arg };
	  $reply .= $mode;
	  push @reply_args, (split /!/, $self->_state_user_full( $arg ))[0];
        }
	if ( $flag eq '-' and $record->{users}->{ u_irc $arg } =~ /$char/ ) {
	  # Update user and chan record
	  $arg = u_irc $arg;
	  $record->{users}->{ $arg } =~ s/$char//g;
	  $self->{state}->{users}->{ $arg }->{chans}->{ u_irc $chan } = $record->{users}->{ $arg };
	  $reply .= $mode;
	  push @reply_args, (split /!/, $self->_state_user_full( $arg ))[0];
        }
	next;
      }
      if ( $mode eq '+l' and $arg =~ /^\d+$/ and $arg > 0 ) {
	$reply .= $mode;
	push @reply_args, $arg;
	$record->{mode} .= 'l' unless $record->{mode} =~ /l/;
	$record->{mode} = join('', sort split //, $record->{mode} );
	$record->{climit} = $arg;
	next;
      }
      if ( $mode eq '-l' and $record->{mode} =~ /l/ ) {
	$record->{mode} =~ s/l//g;
	delete $record->{climit};
	$reply .= $mode;
	next;
      }
      if ( $mode eq '+k' and $arg ) {
	$reply .= $mode;
	push @reply_args, $arg;
	$record->{mode} .= 'k' unless $record->{mode} =~ /k/;
	$record->{mode} = join('', sort split //, $record->{mode} );
	$record->{ckey} = $arg;
	next;
      }
      if ( $mode eq '-k' and $record->{mode} =~ /k/ ) {
	$reply .= $mode;
	push @reply_args, '*';
	$record->{mode} =~ s/k//g;
	delete $record->{ckey};
	next;
      }
      # Bans
      if ( my ($flag) = $mode =~ /(\+|-)b/ ) {
	my $mask = parse_ban_mask( $arg );
	my $umask = u_irc $mask;
	if ( $flag eq '+' and !$record->{bans}->{ $umask } ) {
	  $record->{bans}->{ $umask } = [ $mask, $self->_state_user_full( $nick ), time() ];
	  $reply .= $mode;
	  push @reply_args, $mask;
	}
	if ( $flag eq '-' and $record->{bans}->{ $umask } ) {
	  delete $record->{bans}->{ $umask };
	  $reply .= $mode;
	  push @reply_args, $mask;
	}
	next;
      }
      # Invex
      if ( my ($flag) = $mode =~ /(\+|-)I/ ) {
	my $mask = parse_ban_mask( $arg );
	my $umask = u_irc $mask;
	if ( $flag eq '+' and !$record->{invex}->{ $umask } ) {
	  $record->{invex}->{ $umask } = [ $mask, $self->_state_user_full( $nick ), time() ];
	  $reply .= $mode;
	  push @reply_args, $mask;
	}
	if ( $flag eq '-' and $record->{invex}->{ $umask } ) {
	  delete $record->{invex}->{ $umask };
	  $reply .= $mode;
	  push @reply_args, $mask;
	}
	next;
      }
      # Exceptions
      if ( my ($flag) = $mode =~ /(\+|-)e/ ) {
	my $mask = parse_ban_mask( $arg );
	my $umask = u_irc $mask;
	if ( $flag eq '+' and !$record->{excepts}->{ $umask } ) {
	  $record->{excepts}->{ $umask } = [ $mask, $self->_state_user_full( $nick ), time() ];
	  $reply .= $mode;
	  push @reply_args, $mask;
	}
	if ( $flag eq '-' and $record->{excepts}->{ $umask } ) {
	  delete $record->{excepts}->{ $umask };
	  $reply .= $mode;
	  push @reply_args, $mask;
	}
	next;
      }
      # The rest should be argumentless.
      my ($flag,$char) = split //, $mode;
      if ( $flag eq '+' and $record->{mode} !~ /$char/ ) {
	$reply .= $mode;
	$record->{mode} .= $char;
	$record->{mode} = join('', sort split //, $record->{mode} );
	next;
      }
      if ( $flag eq '-' and $record->{mode} =~ /$char/ ) {
	$reply .= $mode;
	$record->{mode} =~ s/$char//g;
	next;
      }
    } # while
    if ( $reply ) {
	$reply = unparse_mode_line( $reply );
	$self->_send_output_to_channel( $chan, { prefix => $self->_state_user_full( $nick ), command => 'MODE', params => [ $chan, $reply, @reply_args ] } );
    }
  } # SWITCH
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_join {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  my $route_id = $self->_state_user_route( $nick );
  my $unick = u_irc $nick;
  SWITCH: {
    my @channels; my @chankeys;
    if ( !$count ) {
	push @{ $ref }, [ '461', 'JOIN' ];
	last SWITCH;
    }
    @channels = split /,/, $args->[0];
    @chankeys = split /,/, $args->[1] if ( $args->[1] );
    my $channel_length = $self->server_config('CHANNELLEN');
    LOOP: foreach my $channel ( @channels ) {
      my $uchannel = u_irc $channel;
      if ( $channel eq '0' and my @chans = $self->_state_user_chans( $nick ) ) {
	$self->_send_output_to_client( $route_id => ( ref $_ eq 'ARRAY' ? @{ $_ } : $_ ) ) for ( map { $self->_daemon_cmd_part( $nick, $_ ) } @chans );
	next LOOP;
      }
      # Channel isn't valid
      if ( !validate_chan_name( $channel ) or length( $channel ) > $channel_length ) {
	$self->_send_output_to_client( $route_id => '403' => $channel );
	next LOOP;
      }
      # Too many channels
      if ( scalar $self->_state_user_chans( $nick ) >= $self->server_config('MAXCHANNELS') ) {
	$self->_send_output_to_client( $route_id => '405' => $channel );
	next LOOP;
      }
      # Channel doesn't exist
      unless ( $self->_state_chan_exists( $channel ) ) {
	my $record = { name => $channel, ts => time(), mode => 'nt', users => { $unick => 'o' }, };
	$self->{state}->{chans}->{ $uchannel } = $record;
	$self->{state}->{users}->{ $unick }->{chans}->{ $uchannel } = 'o';
	my @peers = $self->_state_connected_peers();
	$self->{ircd}->send_output( { command => 'SJOIN', params => [ $record->{ts}, $channel, '+' . $record->{mode}, ':@' . $nick ] }, @peers );
	$self->{ircd}->send_output( { prefix => $self->_state_user_full( $nick ), command => 'JOIN', params => [ $channel ] }, $route_id );
	$self->{ircd}->send_output( { prefix => $server, command => 'MODE', params => [ $channel, '+' . $record->{mode} ] }, $route_id );
	$self->_send_output_to_client( $route_id => ( ref $_ eq 'ARRAY' ? @{ $_ } : $_ ) ) for $self->_daemon_cmd_names( $nick, $channel );
	$self->_send_output_to_client( $route_id => ( ref $_ eq 'ARRAY' ? @{ $_ } : $_ ) ) for $self->_daemon_cmd_topic( $nick, $channel );
	next LOOP;
      }
      # Numpty user is already on channel
      if ( $self->_state_is_chan_member( $nick, $channel ) ) {
	next LOOP;
      }
      my $chanrec = $self->{state}->{chans}->{ $uchannel };
      # Channel is full
      if ( $chanrec->{mode} =~ /l/ and scalar keys %{ $chanrec } >= $chanrec->{climit} ) {
	$self->_send_output_to_client( $route_id => '471' => $channel );
        next LOOP;
      }
      my $chankey;
      $chankey = shift @chankeys if $chanrec->{mode} =~ /k/;
      # Channel +k and no key or invalid key provided
      if ( $chanrec->{mode} =~ /k/ and ( !$chankey or ( $chankey ne $chanrec->{ckey} ) ) ) {
	$self->_send_output_to_client( $route_id => '475' => $channel );
        next LOOP;
      }
      # Channel +i and not INVEX
      if ( $chanrec->{mode} =~ /i/ and !$self->_state_user_invited( $nick, $channel ) ) {
	$self->_send_output_to_client( $route_id => '473' => $channel );
        next LOOP;
      }
      # Channel +b and no exception
      print STDERR Dumper( $chanrec );
      if ( $self->_state_user_banned( $nick, $channel ) ) {
	$self->_send_output_to_client( $route_id => '474' => $channel );
	next LOOP;
      }
      # JOIN the channel
      delete $self->{state}->{users}->{ $unick }->{invites}->{ $uchannel };
      # Add user
      $self->{state}->{users}->{ $unick }->{chans}->{ $uchannel } = '';
      $self->{state}->{chans}->{ $uchannel }->{users}->{ $unick } = '';
      # Send JOIN message to peers and local users.
      $self->_send_output_to_channel( $channel, { prefix => $self->_state_user_full( $nick ), command => 'JOIN', params => [ $channel ] } );
      # Send NAMES and TOPIC to client
      $self->_send_output_to_client( $route_id => ( ref $_ eq 'ARRAY' ? @{ $_ } : $_ ) ) for $self->_daemon_cmd_names( $nick, $channel );
      $self->_send_output_to_client( $route_id => ( ref $_ eq 'ARRAY' ? @{ $_ } : $_ ) ) for $self->_daemon_cmd_topic( $nick, $channel );
    }
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_part {
  my $self = shift;
  my $nick = shift || return;
  my $chan = shift;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    if ( !$chan ) {
	push @{ $ref }, [ '461', 'PART' ];
	last SWITCH;
    }
    if ( !$self->_state_chan_exists( $chan ) ) {
	push @{ $ref }, [ '403', $chan ];
	last SWITCH;
    }
    if ( !$self->_state_is_chan_member( $nick, $chan ) ) {
	push @{ $ref }, [ '442', $chan ];
	last SWITCH;
    }
    $self->_send_output_to_channel( $chan, { prefix => $self->_state_user_full( $nick ), command => 'PART', params => [ $chan, ( $args->[0] || $nick ) ] } );
    $nick = u_irc $nick;
    $chan = u_irc $chan;
    delete $self->{state}->{chans}->{ $chan }->{users}->{ $nick };
    delete $self->{state}->{users}->{ $nick }->{chans}->{ $chan };
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_kick {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    if ( !$count or $count < 2 ) {
	push @{ $ref }, [ '461', 'KICK' ];
	last SWITCH;
    }
    my $chan = ( split /,/, $args->[0] )[0];
    my $who = ( split /,/, $args->[1] )[0];
    if ( !$self->_state_chan_exists( $chan ) ) {
	push @{ $ref }, [ '403', $chan ];
	last SWITCH;
    }
    $chan = $self->_state_chan_name( $chan );
    if ( !$self->_state_nick_exists( $who ) ) {
	push @{ $ref }, [ '401', $who ];
	last SWITCH;
    }
    $who = ( split /!/, $self->_state_user_full( $who ) )[0];
    if ( !$self->_state_is_chan_op( $nick, $chan ) ) {
	push @{ $ref }, [ '482', $chan ];
	last SWITCH;
    }
    if ( !$self->_state_is_chan_member( $who, $chan ) ) {
	push @{ $ref }, [ '441', $who, $chan ];
	last SWITCH;
    }
    my $comment = $args->[2] || $who;
    $self->_send_output_to_channel( $chan, { prefix => $self->_state_user_full( $nick ), command => 'KICK', params => [ $chan, $who, ( $comment =~ /\s+/ ? $comment : ":$comment" ) ] } );
    if ( $self->_state_is_local_user( $who ) ) {
      $who = u_irc $who; $chan = u_irc $chan;
      delete $self->{state}->{chans}->{ $chan }->{users}->{ $who };
      delete $self->{state}->{users}->{ $who }->{chans}->{ $chan };
    }
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_invite {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    if ( !$count or $count < 2 ) {
	push @{ $ref }, [ '461', 'INVITE' ];
	last SWITCH;
    }
    my ($who,$chan) = @{ $args };
    if ( !$self->_state_nick_exists( $who ) ) {
	push @{ $ref }, [ '401', $who ];
	last SWITCH;
    }
    $who = ( split /!/, $self->_state_user_full( $who ) )[0];
    if ( !$self->_state_chan_exists( $chan ) ) {
	push @{ $ref }, [ '403', $chan ];
	last SWITCH;
    }
    $chan = $self->_state_chan_name( $chan );
    if ( !$self->_state_is_chan_member( $nick, $chan ) ) {
	push @{ $ref }, [ '442', $chan ];
	last SWITCH;
    }
    if ( $self->_state_is_chan_member( $who, $chan ) ) {
	push @{ $ref }, [ '443', $who, $chan ];
	last SWITCH;
    }
    if ( $self->_state_chan_mode_set( $chan, 'i' ) and !$self->_state_is_chan_op( $nick, $chan ) ) {
	push @{ $ref }, [ '482', $chan ];
	last SWITCH;
    }
    my $local; my $away;
    if ( $self->_state_is_local_user( $who ) ) {
	my $record = $self->{state}->{users}->{ u_irc $who };
	$record->{invites}->{ u_irc $chan } = time();
        $local = 1;
	$away = $record->{away} if $record->{umode} =~ /a/;
    }
    $self->{ircd}->send_output( { prefix => $self->_state_user_full( $nick ), command => 'INVITE', params => [ $who, $chan ] }, $self->_state_user_route( $who ) );
    push @{ $ref }, { prefix => $server, command => '341', params => [ $chan, $who ] };
    if ( $local and $away ) {
	push @{ $ref }, { prefix => $server, command => '301', params => [ $nick, $who, ( $away =~ /\s+/ ? $away : ":$away" ) ] };
    }
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_umode {
  my $self = shift;
  my $nick = shift || return;
  my $umode = shift;
  my $server = $self->server_name();
  my $ref = [ ];
  my $record = $self->{state}->{users}->{ u_irc $nick };
  unless ( $umode ) {
    push @{ $ref }, { prefix => $server, command => '422', params => [ $nick, '+' . $record->{umode} ] };
  } else {
    my $set = '';
    my $parsed_mode = parse_mode_line( $umode );
    while ( my $mode = shift ( @{ $parsed_mode->{modes} } ) ) {
	next if ( $mode eq '+o' );
	my ($action,$char) = split //, $mode;
	if ( $action eq '+' and $record->{umode} !~ /$char/ ) {
	  $record->{umode} .= $char;
	  $set .= $mode;
	}
	if ( $action eq '-' and $record->{umode} =~ /$char/ ) {
	  $record->{umode} =~ s/$char//g;
	  $set .= $mode;
	}
    }
    push @{ $ref }, { prefix => $nick, command => 'MODE', params => [ $nick, $set ] } if $set;
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_topic {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH:{
    if ( !$count ) {
	push @{ $ref }, [ '461', 'TOPIC' ];
	last SWITCH;
    }
    if ( !$self->_state_chan_exists( $args->[0] ) ) {
	push @{ $ref }, [ '403', $args->[0] ];
	last SWITCH;
    }
    if ( $self->_state_chan_mode_set( $args->[0], 's' ) and !$self->_state_chan_member( $nick, $args->[0] ) ) {
	push @{ $ref }, [ '442', $args->[0] ];
	last SWITCH;
    }
    my $chan_name = $self->_state_chan_name( $args->[0] );
    if ( $count == 1 and my $topic = $self->_state_chan_topic( $args->[0] ) ) {
	push @{ $ref }, { prefix => $server, command => '332', params => [ $nick, $chan_name, $topic->[0] ] };
	push @{ $ref }, { prefix => $server, command => '333', params => [ $nick, $chan_name, @{ $topic }[1..2] ] };
	last SWITCH;
    }
    if ( $count == 1 ) {
	push @{ $ref }, { prefix => $server, command => '331', params => [ $nick, $chan_name, 'No topic is set' ] };
	last SWITCH;
    }
    if ( !$self->_state_chan_member( $nick, $args->[0] ) ) {
	push @{ $ref }, [ '442', $args->[0] ];
	last SWITCH;
    }
    if ( $self->_state_chan_mode_set( $args->[0], 't' ) and !$self->_state_is_chan_op( $nick, $args->[0] ) ) {
	push @{ $ref }, [ '482', $args->[0] ];
	last SWITCH;
    }
    my $record = $self->{state}->{chans}->{ u_irc $args->[0] };
    my $topic_length = $self->server_config('TOPICLEN');
    $args->[1] = substr( $args->[0],0,$topic_length) if length( $args->[0] ) > $topic_length;
    $record->{topic} = [ $args->[1], $self->_state_user_full( $nick ), time() ];
    $self->_send_output_to_channel( $args->[0], { prefix => $self->_state_full_user( $nick ), command => 'TOPIC', params => [ $chan_name, $args->[1] ] } );
  }
  return @{ $ref } if wantarray();
  return $ref;
}

#################
# State methods #
#################

sub _state_create {
  my ($self) = shift;

  $self->_state_delete();
  # Connection specific tables
  $self->{state}->{conns} = { };
  # IRC State specific
  $self->{state}->{users} = { };
  $self->{state}->{peers} = { };
  $self->{state}->{chans} = { };
  $self->{state}->{peers}->{ uc $self->server_name() } = { name => $self->server_name(), hops => 0, desc => $self->{config}->{ServerDesc} };
  return 1;
}

sub _state_delete {
  my ($self) = shift;

  delete $self->{state};
  return 1;
}

sub _state_register_client {
  my ($self) = shift;
  my ($conn_id) = shift || return;
  return unless $self->_connection_exists( $conn_id );
  my $record = $self->{state}->{conns}->{ $conn_id };
  $record->{server} = $self->server_name();
  $record->{hops} = 0;
  $record->{route_id} = $conn_id;
  $record->{umode} = '';
  $record->{conn_time} = time();
  $record->{idle_time} = $record->{conn_time};
  $record->{auth}->{ident} = '~' . $record->{user} unless $record->{auth}->{ident};
  $record->{auth}->{ident} = '~' . $record->{user} unless $record->{auth}->{ident};
  $record->{auth}->{hostname} = $self->server_name() if $record->{socket}->[0] =~ /^127\./;
  $record->{auth}->{hostname} = $record->{socket}->[0] unless $record->{auth}->{hostname};
  $self->{state}->{users}->{ u_irc( $record->{nick} ) } = $record;
  $self->{state}->{peers}->{ uc( $record->{server} ) }->{users}->{ u_irc( $record->{nick} ) } = $record; 
  my @peers = $self->_state_connected_peers();
  $self->{ircd}->send_output( { }, @peers );
  return 1;
}

sub _state_nick_exists {
  my $self = shift;
  my $nick = shift || return 1;
  return 0 unless defined $self->{state}->{users}->{ u_irc( $nick ) };
  return 1;
}

sub _state_chan_exists {
  my $self = shift;
  my $chan = shift || return;
  return 0 unless defined $self->{state}->{chans}->{ u_irc( $chan ) };
  return 1;
}

sub _state_peer_exists {
  my $self = shift;
  my $peer = shift || return;
  return 0 unless defined $self->{state}->{peers}->{ uc( $peer ) };
  return 1;
}

sub _state_peer_name {
  my $self = shift;
  my $peer = shift || return;
  return unless $self->_state_peer_exists( $peer );
  return $self->{state}->{peers}->{ uc $peer }->{name};
}

sub _state_peer_desc {
  my $self = shift;
  my $peer = shift || return;
  return unless $self->_state_peer_exists( $peer );
  return $self->{state}->{peers}->{ uc $peer }->{desc};
}

sub _state_user_full {
  my $self = shift;
  my $nick = shift || return;
  return unless $self->_state_nick_exists( $nick );
  my $record = $self->{state}->{users}->{ u_irc( $nick ) };
  return $record->{nick} . '!' . $record->{auth}->{ident} . '@' . $record->{auth}->{hostname};
}

sub _state_user_away {
  my $self = shift;
  my $nick = shift || return;
  return unless $self->_state_nick_exists( $nick );
  return 0 unless $self->{state}->{users}->{ u_irc $nick }->{umode} =~ /a/;
  return 1;
}

sub _state_user_is_operator {
  my $self = shift;
  my $nick = shift || return;
  return unless $self->_state_nick_exists( $nick );
  return 0 unless $self->{state}->{users}->{ u_irc $nick }->{umode} =~ /o/;
  return 1;
}

sub _state_user_chans {
  my $self = shift;
  my $nick = shift || return;
  return unless $self->_state_nick_exists( $nick );
  my $record = $self->{state}->{users}->{ u_irc( $nick ) };
  return map { $self->{state}->{chans}->{ $_ }->{name} } keys %{ $record->{chans} };
}

sub _state_user_route {
  my $self = shift;
  my $nick = shift || return;
  return unless $self->_state_nick_exists( $nick );
  my $record = $self->{state}->{users}->{ u_irc( $nick ) };
  return $record->{route_id};
}

sub _state_user_server {
  my $self = shift;
  my $nick = shift || return;
  return unless $self->_state_nick_exists( $nick );
  my $record = $self->{state}->{users}->{ u_irc( $nick ) };
  return $record->{server};
}

sub _state_peer_route {
  my $self = shift;
  my $peer = shift || return;
  return unless $self->_state_peer_exists( $peer );
  my $record = $self->{state}->{peers}->{ uc $peer };
  return $record->{route_id};
}

sub _state_connected_peers {
  my $self = shift;
  my $server = uc $self->server_name();
  return unless scalar keys %{ $self->{state}->{peers} } > 1;
  my $record = $self->{state}->{peers}->{ $server };
  return map { $record->{peers}->{$_}->{route_id} } keys %{ $record->{peers} };
}

sub _state_chan_list {
  my $self = shift;
  my $chan = shift || return;
  return unless $self->_state_chan_exists( $chan );
  my $record = $self->{state}->{chans}->{ u_irc( $chan ) };
  return map { $self->{state}->{users}->{ $_ }->{nick} } keys %{ $record->{users} };
}

sub _state_chan_list_prefixed {
  my $self = shift;
  my $chan = shift || return;
  return unless $self->_state_chan_exists( $chan );
  my $record = $self->{state}->{chans}->{ u_irc( $chan ) };
  return map { 
		my $n = $self->{state}->{users}->{ $_ }->{nick};
		my $m = $record->{users}->{$_};
		my $p = '';
		$p = '@' if $m =~ /o/;
		$p = '%' if $m =~ /h/ and !$p;
		$p = '+' if $m =~ /v/ and !$p;
		$p . $n;
	     } keys %{ $record->{users} };
}

sub _state_chan_topic {
  my $self = shift;
  my $chan = shift || return;
  return unless $self->_state_chan_exists( $chan );
  my $record = $self->{state}->{chans}->{ u_irc( $chan ) };
  return unless $record->{topic};
  return [ @{ $record->{topic} } ];
}

sub _state_is_local_user {
  my $self = shift;
  my $nick = shift || return;
  return unless $self->_state_nick_exists( $nick );
  my $record = $self->{state}->{peers}->{ uc $self->server_name() };
  return 1 if defined ( $record->{users}->{ u_irc $nick } );
  return 0;
}

sub _state_chan_name {
  my $self = shift;
  my $chan = shift || return;
  return unless $self->_state_chan_exists( $chan );
  return $self->{state}->{chans}->{ u_irc $chan }->{name};
}

sub _state_chan_mode_set {
  my $self = shift;
  my $chan = shift || return;
  my $mode = shift || return;
  return unless $self->_state_chan_exists( $chan );
  $mode =~ s/[^a-zA-Z]+//g;
  $mode = ( split //, $mode )[0] if length $mode > 1;
  my $record = $self->{state}->{chans}->{ u_irc $chan };
  return 1 if $record->{mode} =~ /$mode/;
  return 0;
}

sub _state_user_invited {
  my $self = shift;
  my $nick = shift || return;
  my $chan = shift || return;
  return unless $self->_state_nick_exists( $nick );
  return 0 unless $self->_state_chan_exists( $chan );
  my $nickrec = $self->{state}->{users}->{ u_irc $nick };
  return 1 if $nickrec->{invites}->{ u_irc $chan };
  # Check if user matches INVEX
  return 1 if $self->_state_user_matches_list( $nick, $chan, 'invex' );
  return 0;
}

sub _state_user_banned {
  my $self = shift;
  my $nick = shift || return;
  my $chan = shift || return;
  return 0 unless $self->_state_user_matches_list( $nick, $chan, 'bans' );
  return 1 unless $self->_state_user_matches_list( $nick, $chan, 'excepts' );
  return 0;
}

sub _state_user_matches_list {
  my $self = shift;
  my $nick = shift || return;
  my $chan = shift || return;
  my $list = shift || 'bans';
  return unless $self->_state_nick_exists( $nick );
  return 0 unless $self->_state_chan_exists( $chan );
  my $full = u_irc $self->_state_user_full( $nick );
  my $record = $self->{state}->{chans}->{ u_irc $chan };
  foreach my $mask ( keys %{ $record->{ $list } } ) {
	$mask = quotemeta( $mask );
	# From RFC ? == [\x01-\xFF]{1,1} * == [\x01-\xFF]* @ would be \x2A
        $mask =~ s/\\\*/[\x01-\xFF]{0,}/g;
    	$mask =~ s/\\\?/[\x01-\xFF]{1,1}/g;
        print STDERR "$full =~ $mask\n";
	if ( $full =~ /^$mask$/ ) {
		return 1;
	}
  }
  return 0;
}

sub _state_is_chan_member {
  my $self = shift;
  my $nick = shift || return;
  my $chan = shift || return;
  return unless $self->_state_nick_exists( $nick );
  return 0 unless $self->_state_chan_exists( $chan );
  my $record = $self->{state}->{users}->{ u_irc( $nick ) };
  return 1 if defined ( $record->{chans}->{ u_irc( $chan ) } );
  return 0;
}

sub _state_is_chan_op {
  my $self = shift;
  my $nick = shift || return;
  my $chan = shift || return;
  return unless $self->_state_is_chan_member( $nick, $chan );
  my $record = $self->{state}->{users}->{ u_irc( $nick ) };
  return 1 if $record->{chans}->{ u_irc $chan } =~ /o/;
  return 0;
}

sub _state_is_chan_hop {
  my $self = shift;
  my $nick = shift || return;
  my $chan = shift || return;
  return unless $self->_state_is_chan_member( $nick, $chan );
  my $record = $self->{state}->{users}->{ u_irc( $nick ) };
  return 1 if $record->{chans}->{ u_irc $chan } =~ /h/;
  return 0;
}

sub _state_has_chan_voice {
  my $self = shift;
  my $nick = shift || return;
  my $chan = shift || return;
  return unless $self->_state_is_chan_member( $nick, $chan );
  my $record = $self->{state}->{users}->{ u_irc( $nick ) };
  return 1 if $record->{chans}->{ u_irc $chan } =~ /v/;
  return 0;
}

sub server_name {
  return $_[0]->server_config('ServerName');
}

sub server_version {
  return $_[0]->server_config('Version');
}

sub server_created {
  return time2str("This server was created %a %h %d %Y at %H:%M:%S %Z",$_[0]->server_config('created'));
}

sub client_nickname {
  my ($self) = shift;
  my ($wheel_id) = $_[0] || return undef;
  return '*' unless $self->{state}->{conns}->{ $wheel_id }->{nick};
  return $self->{state}->{conns}->{ $wheel_id }->{nick};
}


sub client_ip {
  my ($self) = shift;
  my ($wheel_id) = shift || return '';
  return $self->{state}->{conns}->{ $wheel_id }->{socket}->[0];
}

sub server_config {
  my $self = shift;
  my $value = shift || return;
  return $self->{config}->{$value};
}

sub configure {
  my ($self) = shift;
  my ($options);
  
  if ( ref $_[0] eq 'HASH' ) {
    $options = $_[0];
  } else {
    $options = { @_ };
  }

  foreach my $option ( keys %{ $options } ) {
     $self->{config}->{ $option }  = $options->{ $option };
  }

  $self->{config}->{created} = time();
  $self->{config}->{CASEMAPPING} = 'rfc1459';
  $self->{config}->{ServerName} = 'poco.server.irc' unless ( $self->{config}->{ServerName} );
  $self->{config}->{ServerDesc} = 'Poco? POCO? POCO!' unless ( $self->{config}->{ServerDesc} );
  $self->{config}->{Version} = ref ( $self ) . '-' . $VERSION unless ( $self->{config}->{Version} );
  $self->{config}->{Network} = 'poconet' unless ( $self->{config}->{Network} );
  $self->{config}->{HOSTLEN} = 63 unless ( defined ( $self->{config}->{HOSTLEN} ) and $self->{config}->{HOSTLEN} > 63 );
  $self->{config}->{NICKLEN} = 9 unless ( defined ( $self->{config}->{NICKLEN} ) and $self->{config}->{NICKLEN} > 9 );
  $self->{config}->{KICKLEN} = 120 unless ( defined ( $self->{config}->{KICKLEN} ) and $self->{config}->{KICKLEN} < 120 );
  $self->{config}->{USERLEN} = 10 unless ( defined ( $self->{config}->{USERLEN} ) and $self->{config}->{USERLEN} > 10 );
  $self->{config}->{REALLEN} = 50 unless ( defined ( $self->{config}->{REALLEN} ) and $self->{config}->{REALLEN} > 50 );
  $self->{config}->{TOPICLEN} = 80 unless ( defined ( $self->{config}->{TOPICLEN} ) and $self->{config}->{TOPICLEN} > 80 );
  $self->{config}->{CHANNELLEN} = 50 unless ( defined ( $self->{config}->{CHANNELLEN} ) and $self->{config}->{CHANNELLEN} > 50 );
  $self->{config}->{PASSWDLEN} = 20 unless ( defined ( $self->{config}->{PASSWDLEN} ) and $self->{config}->{PASSWDLEN} > 20 );
  $self->{config}->{KEYLEN} = 23 unless ( defined ( $self->{config}->{KEYLEN} ) and $self->{config}->{KEYLEN} > 23 );
  $self->{config}->{MAXCHANNELS} = 15 unless ( defined ( $self->{config}->{MAXCHANNELS} ) and $self->{config}->{MAXCHANNELS} > 15 );
  $self->{config}->{MAXRECIPIENTS} = 20 unless ( defined ( $self->{config}->{MAXRECIPIENTS} ) and $self->{config}->{MAXRECIPIENTS} > 20 );
  $self->{config}->{MAXBANS} = 30 unless ( defined ( $self->{config}->{MAXBANS} ) and $self->{config}->{MAXBANS} > 30 );
  $self->{config}->{MAXBANLENGTH} = 1024 unless ( defined ( $self->{config}->{MAXBANLENGTH} ) and $self->{config}->{MAXBANLENGTH} < 1024 );
  $self->{config}->{BANLEN} = $self->{config}->{USERLEN} + $self->{config}->{NICKLEN} + $self->{config}->{HOSTLEN} + 3;
  $self->{config}->{USERHOST_REPLYLEN} = $self->{config}->{USERLEN} + $self->{config}->{NICKLEN} + $self->{config}->{HOSTLEN} + 5;
  # TODO: Find some way to disable requirement for PoCo-Client-DNS and PoCo-Client-Ident
  $self->{config}->{Auth} = 1 unless ( defined ( $self->{config}->{Auth} ) and $self->{config}->{Auth} eq '0' );
  $self->{config}->{AntiFlood} = 1 unless ( defined ( $self->{config}->{AntiFlood} ) and $self->{config}->{AntiFlood} eq '0' );
  if ( ( not defined ( $self->{config}->{Admin} ) ) or ( ref $self->{config}->{Admin} ne 'ARRAY' ) or ( scalar ( @{ $self->{config}->{Admin} } ) != 3 ) ) {
    $self->{config}->{Admin}->[0] = 'Somewhere, Somewhere, Somewhere';
    $self->{config}->{Admin}->[1] = 'Some Institution';
    $self->{config}->{Admin}->[2] = 'someone@somewhere';
  }
  if ( ( not defined ( $self->{config}->{Info} ) ) or ( ref $self->{config}->{Info} eq 'ARRAY' ) or ( scalar ( @{ $self->{config}->{Info} } ) >= 1 ) ) {
    $self->{config}->{Info}->[0] = '# POE::Component::Server::IRC';
    $self->{config}->{Info}->[1] = '#';
    $self->{config}->{Info}->[2] = '# Author: Chris "BinGOs" Williams';
    $self->{config}->{Info}->[3] = '#';
    $self->{config}->{Info}->[4] = '# Filter-IRCD Written by Hachi';
    $self->{config}->{Info}->[5] = '#';
    $self->{config}->{Info}->[6] = '# This module may be used, modified, and distributed under the same';
    $self->{config}->{Info}->[7] = '# terms as Perl itself. Please see the license that came with your Perl';
    $self->{config}->{Info}->[8] = '# distribution for details.';
    $self->{config}->{Info}->[9] = '#';
  }

  $self->{Error_Codes} = {
			401 => [ 1, "No such nick/channel" ],
			402 => [ 1, "No such server" ],
			403 => [ 1, "No such channel" ],
			404 => [ 1, "Cannot send to channel" ],
			405 => [ 1, "You have joined too many channels" ],
			406 => [ 1, "There was no such nickname" ],
			408 => [ 1, "No such service" ],
			409 => [ 1, "No origin specified" ],
			411 => [ 0, "No recipient given (%s)" ],
			412 => [ 1, "No text to send" ],
			413 => [ 1, "No toplevel domain specified" ],
			414 => [ 1, "Wildcard in toplevel domain" ],
			415 => [ 1, "Bad server/host mask" ],
			421 => [ 1, "Unknown command" ],
			422 => [ 0, "MOTD File is missing" ],
			423 => [ 1, "No administrative info available" ],
			424 => [ 1, "File error doing % on %" ],
			431 => [ 1, "No nickname given" ],
			432 => [ 1, "Erroneous nickname" ],
			433 => [ 1, "Nickname is already in use" ],
			436 => [ 1, "Nickname collision KILL from %s\@%s" ],
			437 => [ 1, "Nick/channel is temporarily unavailable" ],
			441 => [ 1, "They aren\'t on that channel" ],
			442 => [ 1, "You\'re not on that channel" ],
			443 => [ 2, "is already on channel" ],
			444 => [ 1, "User not logged in" ],
			445 => [ 0, "SUMMON has been disabled" ],
			446 => [ 0, "USERS has been disabled" ],
			451 => [ 0, "You have not registered" ],
			461 => [ 1, "Not enough parameters" ],
			462 => [ 0, "Unauthorised command (already registered)" ],
			463 => [ 0, "Your host isn\'t among the privileged" ],
			464 => [ 0, "Password mismatch" ],
			465 => [ 0, "You are banned from this server" ],
			466 => [ 0, "You will be banned from this server" ],
			467 => [ 1, "Channel key already set" ],
			471 => [ 1, "Cannot join channel (+l)" ],
			472 => [ 1, "is unknown mode char to me for %s" ],
			473 => [ 1, "Cannot join channel (+i)" ],
			474 => [ 1, "Cannot join channel (+b)" ],
			475 => [ 1, "Cannot join channel (+k)" ],
			476 => [ 1, "Bad Channel Mask" ],
			477 => [ 1, "Channel doesn\'t support modes" ],
			478 => [ 2, "Channel list is full" ],
			481 => [ 0, "Permission Denied- You\'re not an IRC operator" ],
			482 => [ 1, "You\'re not channel operator" ],
			483 => [ 0, "You can\'t kill a server!" ],
			484 => [ 0, "Your connection is restricted!" ],
			485 => [ 0, "You\'re not the original channel operator" ],
			491 => [ 0, "No O-lines for your host" ],
			501 => [ 0, "Unknown MODE flag" ],
			502 => [ 0, "Cannot change mode for other users" ],
  };

  $self->{config}->{isupport} = {
    INVEX => undef,
    EXCEPT => undef,
    CHANTYPES => '#&',
    PREFIX => '(ohv)@%+',
    CHANMODES => 'eIb,k,l,imnpst',
    map { ( uc $_, $self->{config}->{$_} ) } qw(MAXCHANNELS MAXBANS NICKLEN TOPICLEN KICKLEN CASEMAPPING Network),
  };

  return 1;
}

sub _send_output_to_client {
  my ($self) = shift;
  my ($wheel_id) = shift || return 0;
  my ($err) = shift || return 0;
  return unless $self->_connection_exists( $wheel_id );
  SWITCH: {
    if ( ref $err eq 'HASH' ) {
	$self->{ircd}->send_output( $err, $wheel_id );
	last SWITCH;
    }
    if ( defined ( $self->{Error_Codes}->{ $err } ) ) {
	my ($input) = { command => $err, prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id) ] };
	if ( $self->{Error_Codes}->{ $err }->[0] > 0 ) {
	   for ( my $i = 1; $i <= $self->{Error_Codes}->{ $err }->[0]; $i++ ) {
		push ( @{ $input->{params} }, shift );
	   }
	}
	if ( $self->{Error_Codes}->{ $err }->[1] =~ /%/ ) {
	  push ( @{ $input->{params} }, sprintf($self->{Error_Codes}->{ $err }->[1],@_) );
        } else {
	  push ( @{ $input->{params} }, $self->{Error_Codes}->{ $err }->[1] );
        }
	$self->{ircd}->send_output( $input, $wheel_id );
    }
  }
  return 1;
}

sub _send_output_to_channel {
  my $self = shift;
  my $channel = shift || return;
  my $output = shift || return;
  return unless $self->_state_chan_exists( $channel );
  # Get conn_ids for each of our peers.
  my $ref = [ ];
  push @{ $ref }, $_ for $self->_state_connected_peers();
  push @{ $ref }, $self->_state_user_route( $_ ) for grep { $self->_state_is_local_user( $_ ) } $self->_state_chan_list( $channel );
  $self->{ircd}->send_output( $output, @{ $ref } );
  return 1;
}

1;
