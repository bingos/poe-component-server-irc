# Author: Chris "BinGOs" Williams
#
# This module may be used, modified, and distributed under the same
# terms as Perl itself. Please see the license that came with your Perl
# distribution for details.
#
package POE::Component::Server::IRC;

use base qw(POE::Component::Server::IRC::Backend);
use POE::Component::Server::IRC::Common qw(:ALL);
use Date::Format;
use vars qw($VERSION $REVISION);

$VERSION = '0.99';
($REVISION) = (q$LastChangedRevision$=~/(\d+)/g);

sub spawn {
  my $package = shift;
  my $self = $package->create(@_);
  $self->{config}->{ uc $_ } = delete $self->{config}->{$_} for keys %{ $self->{config} };
  $self->configure();
  $self->_state_create();
  $self->{ircd} = $self;
  return $self;
}

sub IRCD_listener_add {
  my ($self,$ircd) = splice @_, 0, 2;
  return PCSI_EAT_NONE;
}

sub IRCD_connection {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id,$peeraddr,$peerport,$sockaddr,$sockport) = map { ${ $_ } } @_;

  delete $self->{state}->{conns}->{ $conn_id } if $self->_connection_exists( $conn_id );
  $self->{state}->{conns}->{ $conn_id }->{registered} = 0;
  $self->{state}->{conns}->{ $conn_id }->{type} = 'u';
  $self->{state}->{conns}->{ $conn_id }->{seen} = time();
  $self->{state}->{conns}->{ $conn_id }->{socket} = [ $peeraddr, $peerport, $sockaddr, $sockport ];
  $self->{state}->{stats}->{conns_cumlative}++;
  return PCSI_EAT_NONE;
}

sub IRCD_connected {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id,$peeraddr,$peerport,$sockaddr,$sockport,$name) = map { ${ $_ } } @_;

  delete $self->{state}->{conns}->{ $conn_id } if $self->_connection_exists( $conn_id );
  $self->{state}->{conns}->{ $conn_id }->{registered} = 0;
  $self->{state}->{conns}->{ $conn_id }->{cntr} = 1;
  $self->{state}->{conns}->{ $conn_id }->{type} = 'u';
  $self->{state}->{conns}->{ $conn_id }->{seen} = time();
  $self->{state}->{conns}->{ $conn_id }->{socket} = [ $peeraddr, $peerport, $sockaddr, $sockport ];
  $self->{state}->{stats}->{conns_cumlative}++;
  $self->_state_send_credentials( $conn_id, $name );
  return PCSI_EAT_NONE;
}

sub IRCD_connection_flood {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id) = map { ${ $_ } } @_;
  $self->terminate_conn_error( $conn_id, 'Excess Flood' );
  return PCSI_EAT_NONE;
}

sub IRCD_connection_idle {
  my ($self,$ircd) = splice @_,0 ,2;
  my ($conn_id,$interval) = map { ${ $_ } } @_;
  return PCSI_EAT_NONE unless $self->_connection_exists( $conn_id );
  my $conn = $self->{state}->{conns}->{ $conn_id };
  if ( $conn->{type} eq 'u' ) {
  	$self->terminate_conn_error( $conn_id, 'Connection Timeout' );
  	return PCSI_EAT_NONE;
  }
  if ( $conn->{pinged} ) {
	my $msg = 'Ping timeout: ' . ( time() - $conn->{seen} ) . ' seconds';
  	$self->terminate_conn_error( $conn_id, $msg );
  	return PCSI_EAT_NONE;
  }
  $conn->{pinged} = 1;
  $self->{ircd}->send_output( { command => 'PING', params => [ $self->server_name() ] }, $conn_id );
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
	my $peer = $self->{state}->{conns}->{ $conn_id }->{name};
	$self->{ircd}->send_output( @{ $self->_daemon_peer_squit( $conn_id, $peer, $self->server_name() ) } );
	delete $self->{state}->{conns}->{ $conn_id };
	last SWITCH;
    }
    if ( $self->_connection_is_client( $conn_id ) ) {
	$self->{ircd}->send_output( @{ $self->_daemon_cmd_quit( $self->client_nickname( $conn_id ), $errstr ) } );
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
  my $network = $self->server_config('NETWORK');
  $self->_send_output_to_client( $conn_id => { prefix => $server, command => '001', params => [ $nick, "Welcome to the $network Internet Relay Chat network $nick" ] } );
  $self->_send_output_to_client( $conn_id => { prefix => $server, command => '002', params => [ $nick, "Your host is ${server}[${server}/${port}], running version $version" ] } );
  $self->_send_output_to_client( $conn_id => { prefix => $server, command => '003', params => [ $nick, $self->server_created() ] } );
  $self->_send_output_to_client( $conn_id => { prefix => $server, command => '004', params => [ $nick, $server, $version, 'oiw', 'biklmnopstveIh', 'bkloveIh' ], colonify => 0 } );
  $self->_send_output_to_client( $conn_id => $_ ) for @{ $self->_daemon_cmd_isupport( $nick ) };
  $self->{state}->{conns}->{ $conn_id }->{registered} = 1;
  $self->{state}->{conns}->{ $conn_id }->{type} = 'c';
  $self->{ircd}->send_event( 'cmd_lusers' => $conn_id => { command => 'LUSERS' } );
  $self->{ircd}->send_event( 'cmd_motd' => $conn_id => { command => 'MOTD' } );
  $self->{ircd}->send_event( 'cmd_mode' => $conn_id => { command => 'MODE', params => [ $nick, '+i' ] } );
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
	$self->terminate_conn_error( $wheel_id, 'Client Quit' );
	last SWITCH;
    }
    # PASS or NICK cmd but no parameters.
    if ( $cmd =~ /^(PASS|NICK|SERVER)$/ and !$pcount ) {
	$self->_send_output_to_client( $wheel_id => '461' => $cmd );
	last SWITCH;
    }
    # PASS or NICK cmd with one parameter, connection from client
    if ( $cmd eq 'PASS' and $pcount ) {
	$self->{state}->{conns}->{ $wheel_id }->{ lc $cmd } = $params->[0];
	if ( $params->[1] and $params->[1] =~ /TS$/ ) {
	  $self->{state}->{conns}->{ $wheel_id }->{ts_server} = 1;
	  $self->{ircd}->antiflood( $wheel_id => 0 );
	}
	last SWITCH;
    }
    # SERVER stuff.
    if ( $cmd eq 'CAPAB' and $pcount ) {
	$self->{state}->{conns}->{ $wheel_id }->{capab} = [ split /\s+/, $params->[0] ];
	last SWITCH;
    }
    if ( $cmd eq 'SERVER' and $pcount < 2 ) {
	$self->_send_output_to_client( $wheel_id => '461' => $cmd );
	last SWITCH;
    }
    if ( $cmd eq 'SERVER' ) {
	my $conn = $self->{state}->{conns}->{ $wheel_id };
	$conn->{name} = $params->[0];
	$conn->{hops} = $params->[1] || 1;
	$conn->{desc} = $params->[2] || '';
	if ( !$conn->{ts_server} ) {
	   $self->terminate_conn_error( $wheel_id, 'Non-TS server.' );
	   last SWITCH;
	}
	if ( !$self->_state_auth_peer_conn( $wheel_id, $conn->{name}, $conn->{pass} ) ) {
	   $self->terminate_conn_error( $wheel_id, 'Unauthorised server.' );
	   last SWITCH;
	}
	if ( $self->_state_peer_exists( $conn->{name} ) ) {
	   $self->terminate_conn_error( $wheel_id, 'Server exists.' );
	   last SWITCH;
	}
	$self->_state_register_peer( $wheel_id );
	$self->_state_send_burst( $wheel_id );
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
    last SWITCH if $self->{state}->{conns}->{ $wheel_id }->{cntr};
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
    my $method = '_daemon_peer_' . lc $cmd;
    if ( $cmd eq 'SQUIT' and !$prefix ) {
	$self->_daemon_peer_squit( $conn_id, @{ $params } );
	$self->_send_output_to_client( $conn_id => $prefix => ( ref $_ eq 'ARRAY' ? @{ $_ } : $_ ) ) for $self->_daemon_cmd_squit( $prefix, @{ $params } );
	last SWITCH;
    }
    if ( $cmd eq 'SQUIT' and !$prefix ) {
	last SWITCH;
    }
    if ( $cmd =~ /\d{3}/ ) {
	$self->{ircd}->send_output( $input, $self->_state_user_route( $params->[0] ) );
	last SWITCH;
    }
    if ( $cmd eq 'QUIT' ) {
	$self->{ircd}->send_output( @{ $self->_daemon_peer_quit( $prefix, @{ $params }, $conn_id ) } );
	last SWITCH;
    }
    if ( $cmd =~ /^(PRIVMSG|NOTICE)$/ ) {
	$self->_daemon_peer_message( $conn_id, $prefix, $cmd, @{ $params } );
	last SWITCH;
    }
    if ( $cmd =~ /^(WHOIS|VERSION|TIME|NAMES|LINKS|ADMIN|INFO|MOTD)$/i ) {
	my $client_method = '_daemon_cmd_' . lc $cmd;
	$self->_send_output_to_client( $conn_id => $prefix => ( ref $_ eq 'ARRAY' ? @{ $_ } : $_ ) ) for $self->$client_method( $prefix, @{ $params } );
	last SWITCH;
    }
    if ( $cmd =~ /^(PING|PONG|SVINFO)$/i and $self->can($method) ) {
	$self->$method( $conn_id, @{ $params } );
	last SWITCH;
    }
    $method = '_daemon_peer_umode' if $cmd eq 'MODE' and $self->_state_nick_exists( $params->[0] );
    if ( $self->can($method) ) {
	$self->$method( $conn_id, $prefix, @{ $params } );
	last SWITCH;
    }
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
	$self->terminate_conn_error( $wheel_id, ( $pcount ? qq{"$params->[0]"} : 'Client Quit' ) );
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
    if ( $cmd =~ /^(PRIVMSG|NOTICE)$/ ) {
	$self->{state}->{conns}->{ $wheel_id }->{idle_time} = time();
	$self->_send_output_to_client( $wheel_id => ( ref $_ eq 'ARRAY' ? @{ $_ } : $_ ) ) for $self->_daemon_cmd_message( $nick, $cmd, @{ $params } );
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

sub _daemon_cmd_message {
  my $self = shift;
  my $nick = shift || return;
  my $type = shift || return;
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    if ( !$count ) {
	push @{ $ref }, [ '461', $type ];
	last SWITCH;
    }
    if ( $count < 2 or !$args->[1] ) {
	push @{ $ref }, [ '412' ];
	last SWITCH;
    }
    my $targets = 0;
    my $max_targets = $self->server_config('MAXTARGETS');
    my $full = $self->_state_user_full( $nick );
    LOOP: foreach my $target ( split /,/, $args->[0] ) {
	my $runt = $target;
	$target = ( split /!/, $target )[0] if $target =~ /\x21/;
	$target = ( split /\x40/, $target )[0] if $target =~ /\x40/;
	unless ( $self->_state_chan_exists( $target ) or $self->_state_nick_exists( $target ) ) {
	   push @{ $ref }, [ '401', $runt ];
	   next LOOP;
	}
	$targets++;
        if ( $targets > $max_targets ) {
	  push @{ $ref }, [ '407', $runt ];
	  last SWITCH;
        }
	my $channel = $self->_state_chan_name( $target );
	if ( $channel and $self->_state_chan_mode_set( $channel, 'n' ) and !$self->_state_is_chan_member( $nick, $channel ) ) {
	  push @{ $ref }, [ '404', $channel ];
	  next LOOP;
	}
	if ( $channel and $self->_state_chan_mode_set( $channel, 'm' ) and !$self->_state_user_chan_mode( $nick, $channel ) ) {
	  push @{ $ref }, [ '404', $channel ];
	  next LOOP;
	}
	#if ( $channel and $self->_state_user_banned( $nick, $channel ) ) {
	#  push @{ $ref }, [ '404', $channel ];
	#  next LOOP;
	#}
	if ( $channel ) {
	  my $common = { };
	  my $msg = { command => $type, params => [ $channel, $args->[1] ] };
	  foreach my $member ( keys %{ $self->{state}->{chans}->{ u_irc $channel }->{users} } ) {
		$common->{ $self->_state_user_route( $member ) }++;
	  }
	  delete $common->{ $self->_state_user_route( $nick ) };
	  foreach my $route_id ( keys %{ $common } ) {
		$msg->{prefix} = $nick;
		$msg->{prefix} = $full if $self->_connection_is_client( $route_id );
	  	$self->{ircd}->send_output( $msg, $route_id )
	  }
	  next LOOP;
	}
	if ( $self->_state_nick_exists( $target ) ) {
	  $target = ( split /!/, $self->_state_user_full( $target ) )[0];
	  my $msg = { prefix => $nick, command => $type, params => [ $target, $args->[1] ] };
	  my $route_id = $self->_state_user_route( $target );
	  $msg->{prefix} = $full if $self->_connection_is_client( $route_id );
	  $self->{ircd}->send_output( $msg, $route_id );
	  next LOOP;
	}
     }
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_quit {
  my $self = shift;
  my $nick = shift || return;
  my $qmsg = shift || 'Client Quit';
  my $ref = [ ];
  my $full = $self->_state_user_full( $nick );

  $nick = u_irc $nick;
  my $record = delete $self->{state}->{peers}->{ uc $self->server_name() }->{users}->{ $nick };
  $self->{ircd}->send_output( { prefix => $record->{nick}, command => 'QUIT', params => [ $qmsg ] }, $self->_state_connected_peers() ) unless $record->{killed};
  push @{ $ref }, { prefix => $full, command => 'QUIT', params => [ $qmsg ] };
  # Okay, all 'local' users who share a common channel with user.
  my $common = { };
  foreach my $uchan ( keys %{ $record->{chans} } ) {
    delete $self->{state}->{chans}->{ $uchan }->{users}->{ $nick };
    foreach my $user ( $self->_state_chan_list( $uchan ) ) {
	next unless $self->_state_is_local_user( $user );
	$common->{ $user } = $self->_state_user_route( $user );
    }
    unless ( scalar keys %{ $self->{state}->{chans}->{ $uchan  }->{users} } ) {
	delete $self->{state}->{chans}->{ $uchan  };
    }
  }
  push( @{ $ref }, $common->{$_} ) for keys %{ $common };
  $self->{state}->{stats}->{ops_online}-- if $record->{umode} =~ /o/;
  $self->{state}->{stats}->{invisible}-- if $record->{umode} =~ /i/;
  delete $self->{state}->{users}->{ $nick } unless $record->{nick_collision};
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_ping {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
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

sub _daemon_cmd_oper {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    last SWITCH if $self->_state_user_is_operator( $nick );
    if ( !$count or $count < 2 ) {
	push @{ $ref }, [ '461', 'OPER' ];
	last SWITCH;
    }
    my $result = $self->_state_o_line( $nick, @{ $args } );
    if ( !$result or $result <= 0 ) {
	push @{ $ref }, [ '491' ];
	last SWITCH;
    }
    $self->{stats}->{ops}++;
    my $record = $self->{state}->{users}->{ u_irc $nick };
    $record->{umode} .= 'o';
    $self->{state}->{stats}->{ops_online}++;
    push @{ $ref }, { prefix => $server, command => '381', params => [ $nick, 'You are now an IRC operator' ] };
    my $reply = { prefix => $nick, command => 'MODE', params => [ $nick, '+o' ] };
    $self->{ircd}->send_output( $reply, $self->_state_connected_peers() );
    $self->{ircd}->antiflood( $self->_state_user_route( $nick ), 0 );
    push @{ $ref }, $reply;
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_die {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ];
  SWITCH: {
     if ( !$self->_state_user_is_operator( $nick ) ) {
	push @{ $ref }, [ '481' ];
	last SWITCH;
     }
     $self->{ircd}->shutdown();
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_connect {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
     if ( !$self->_state_user_is_operator( $nick ) ) {
	push @{ $ref }, [ '481' ];
	last SWITCH;
     }
     if ( !$count ) {
	push @{ $ref }, [ '461', 'CONNECT' ];
	last SWITCH;
     }
     if ( $count >= 3 and !$self->_state_peer_exists( $args->[2] ) ) {
	push @{ $ref }, [ '402', $args->[2] ];
	last SWITCH;
     }
     if ( $count >= 3 and ( uc $server ne uc $args->[2] ) ) {
	$args->[2] = $self->_state_peer_name( $args->[2] );
	$self->{ircd}->send_output( { prefix => $nick, command => 'CONNECT', params => $args }, $self->_state_peer_route( $args->[2] ) );
	last SWITCH;
     }
     if ( !$self->{config}->{peers}->{ uc $args->[0] } or $self->{config}->{peers}->{ uc $args->[0] }->{type} ne 'r' ) {
	push @{ $ref }, { command => 'NOTICE', params => [ $nick, "Connect: Host $args->[0] is not listed in ircd.conf" ] };
	last SWITCH;
     }
     my $connector = $self->{config}->{peers}->{ uc $args->[0] };
     my $name = $connector->{name};
     my $rport = $args->[1] || $connector->{rport};
     my $raddr = $connector->{raddress};
     $self->{ircd}->add_connector( remoteaddress => $raddr, remoteport => $rport, name => $name );
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_squit {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
     if ( !$self->_state_user_is_operator( $nick ) ) {
	push @{ $ref }, [ '481' ];
	last SWITCH;
     }
     if ( !$count ) {
	push @{ $ref }, [ '461', 'SQUIT' ];
	last SWITCH;
     }
     if ( !$self->_state_peer_exists( $args->[0] ) or ( uc $server eq uc $args->[0] ) ) {
	push @{ $ref }, [ '402', $args->[0] ];
	last SWITCH;
     }
     my $peer = uc $args->[0];
     $args->[0] = $self->_state_peer_name( $peer );
     unless ( scalar grep { $_ eq $peer } keys %{ $self->{state}->{peers}->{ uc $server }->{peers} } ) {
	$self->{ircd}->send_output( { prefix => $nick, command => 'SQUIT', params => $args }, $self->_state_peer_route( $args->[0] ) );
	last SWITCH;
     }
     my $conn_id = $self->_state_peer_route( $peer );
     $self->{ircd}->disconnect( $conn_id );
     $self->{ircd}->send_output( { command => 'ERROR', params => [ join ' ', 'Closing Link:', $self->client_ip( $conn_id ), $args->[0], "($nick)" ] }, $conn_id );
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_kill {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
     if ( !$self->_state_user_is_operator( $nick ) ) {
	push @{ $ref }, [ '481' ];
	last SWITCH;
     }
     if ( !$count ) {
	push @{ $ref }, [ '461', 'KILL' ];
	last SWITCH;
     }
     if ( $self->_state_peer_exists( $args->[0] ) ) {
	push @{ $ref }, [ '483' ];
	last SWITCH;
     }
     if ( !$self->_state_nick_exists( $args->[0] ) ) {
	push @{ $ref }, [ '401', $args->[0] ];
	last SWITCH;
     }
     my $target = ( split /!/, $self->_state_user_full( $args->[0] ) )[0];
     my $comment = $args->[1] || '<No reason given>';
     if ( $self->_state_is_local_user( $target ) ) {
	my $route_id = $self->_state_user_route( $target );
        $self->{ircd}->send_output( { prefix => $nick, command => 'KILL', params => [ $target, join('!', $server, $nick ) . " ($comment)" ] }, $self->_state_connected_peers() );
	$self->{ircd}->send_output( { prefix => $self->_state_user_full( $nick ), command => 'KILL', params => [ $target, $comment ] }, $route_id );
	$self->{state}->{conns}->{ $route_id }->{killed} = 1;
	$self->terminate_conn_error( $route_id, "Killed ($nick ($comment))" );
     } else {
	$self->{state}->{users}->{ u_irc $target }->{killed} = 1;
        $self->{ircd}->send_output( { prefix => $nick, command => 'KILL', params => [ $target, join('!', $server, $nick ) . " ($comment)" ] }, $self->_state_connected_peers() );
	$self->{ircd}->send_output( @{ $self->_daemon_peer_quit( $target, "Killed ($nick ($comment))" ) } );
     }
  }
  return @{ $ref } if wantarray();
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
	$record->{ts} = time();
    } else {
	$record->{nick} = $new;
	$record->{ts} = time();
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
    $self->{ircd}->send_output( { prefix => $nick, command => 'NICK', params => [ $new, $record->{ts} ] }, @peers );
    $self->{ircd}->send_output( { prefix => $full, command => 'NICK', params => [ $new ] }, map{ $common->{$_} } keys %{ $common } );
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
	delete $record->{away};
        $self->{ircd}->send_output( { prefix => $nick, command => 'AWAY', colonify => 0 }, $self->_state_connected_peers() );
	push @{ $ref }, { prefix => $server, command => '305', params => [ 'You are no longer marked as being away' ] };
	last SWITCH;
     }
     $record->{away} = $msg;
     $self->{ircd}->send_output( { prefix => $nick, command => 'AWAY', params => [ $msg ], colonify => 0 }, $self->_state_connected_peers() );
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
  my $target = shift;
  my $server = $self->server_name();
  my $ref = [ ];
  SWITCH: {
    if ( $target and !$self->_state_peer_exists( $target ) ) {
	push @{ $ref }, [ '402', $target ];
	last SWITCH;
    }
    if ( $target and ( uc $server ne uc $target ) ) {
	$self->{ircd}->send_output( { prefix => $nick, command => 'INFO', params => [ $self->_state_peer_name( $target ) ] }, $self->_state_peer_route( $target ) );
	last SWITCH;
    }
    push( @{ $ref }, { prefix => $server, command => '371', params => [ $nick, ( / / ? $_ : ":$_" ) ] } ) for @{ $self->server_config('Info') };
    push( @{ $ref }, { prefix => $server, command => '374', params => [ $nick, 'End of /INFO list.' ] } );
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_version {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ];
  my $target = shift;
  SWITCH: {
    if ( $target and !$self->_state_peer_exists( $target ) ) {
	push @{ $ref }, [ '402', $target ];
	last SWITCH;
    }
    if ( $target and ( uc $server ne uc $target ) ) {
	$self->{ircd}->send_output( { prefix => $nick, command => 'VERSION', params => [ $self->_state_peer_name( $target ) ] }, $self->_state_peer_route( $target ) );
	last SWITCH;
    }
    push @{ $ref }, { prefix => $server, command => '351', params => [ $nick, $self->server_version(), $server, 'eGHIMZ TS5ow' ] };
    push @{ $ref }, $_ for @{ $self->_daemon_cmd_isupport( $nick ) };
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_admin {
  my $self = shift;
  my $nick = shift || return;
  my $target = shift;
  my $server = $self->server_name();
  my $ref = [ ]; my $admin = $self->server_config('Admin');
  SWITCH: {
    if ( $target and !$self->_state_peer_exists( $target ) ) {
	push @{ $ref }, [ '402', $target ];
	last SWITCH;
    }
    if ( $target and ( uc $server ne uc $target ) ) {
	$self->{ircd}->send_output( { prefix => $nick, command => 'ADMIN', params => [ $self->_state_peer_name( $target ) ] }, $self->_state_peer_route( $target ) );
	last SWITCH;
    }
    push @{ $ref }, { prefix => $server, command => '256', params => [ $nick, $server, 'Administrative Info' ] };
    push @{ $ref }, { prefix => $server, command => '257', params => [ $nick, $admin->[0] ] };
    push @{ $ref }, { prefix => $server, command => '258', params => [ $nick, $admin->[1] ] };
    push @{ $ref }, { prefix => $server, command => '259', params => [ $nick, $admin->[2] ] };
  }
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
  my $target = shift;
  my $ref = [ ];
  SWITCH: {
    if ( $target and !$self->_state_peer_exists( $target ) ) {
	push @{ $ref }, [ '402', $target ];
	last SWITCH;
    }
    if ( $target and ( uc $server ne uc $target ) ) {
	$self->{ircd}->send_output( { prefix => $nick, command => 'TIME', params => [ $self->_state_peer_name( $target ) ] }, $self->_state_peer_route( $target ) );
	last SWITCH;
    }
    push @{ $ref }, { prefix => $server, command => '351', params => [ $nick, $server, time2str( "%A %B %e %Y -- %T %z", time() ) ] };
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_users {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ];
  my $global = scalar keys %{ $self->{state}->{users} };
  my $local = scalar keys %{ $self->{state}->{peers}->{ uc $server }->{users} };
  push @{ $ref }, { prefix => $server, command => '265', params => [ $nick, "Current local  users: $local  Max: " . $self->{state}->{stats}->{maxlocal} ] };
  push @{ $ref }, { prefix => $server, command => '266', params => [ $nick, "Current global users: $global  Max: " . $self->{state}->{stats}->{maxglobal} ] };
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_lusers {
  my $self = shift;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ];
  my $invisible = $self->{state}->{stats}->{invisible};
  my $users = scalar ( keys %{ $self->{state}->{users} } ) - $invisible;
  my $servers = scalar keys %{ $self->{state}->{peers} };
  my $chans = scalar keys %{ $self->{state}->{chans} };
  my $local = scalar keys %{ $self->{state}->{peers}->{ uc $server }->{users} };
  my $peers = scalar keys %{ $self->{state}->{peers}->{ uc $server }->{peers} };
  push( @{ $ref }, { prefix => $server, command => '251', params =>[ $nick, "There are $users users and $invisible invisible on $servers servers" ] } );
  $servers--;
  push @{ $ref }, { prefix => $server, command => '252', params => [ $nick, $self->{state}->{stats}->{ops_online}, "IRC Operators online" ] } if $self->{state}->{stats}->{ops_online};
  push( @{ $ref }, { prefix => $server, command => '254', params =>[ $nick, $chans, "channels formed" ] } ) if $chans;
  push( @{ $ref }, { prefix => $server, command => '255', params =>[ $nick, "I have $local clients and $peers servers" ] } );
  push @{ $ref }, $_ for $self->_daemon_cmd_users( $nick );
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_motd {
  my $self = shift;
  my $nick = shift || return;
  my $target = shift;
  my $server = $self->server_name();
  my $ref = [ ]; my $motd = $self->server_config('MOTD');
  SWITCH: {
    if ( $target and !$self->_state_peer_exists( $target ) ) {
	push @{ $ref }, [ '402', $target ];
	last SWITCH;
    }
    if ( $target and ( uc $server ne uc $target ) ) {
	$self->{ircd}->send_output( { prefix => $nick, command => 'MOTD', params => [ $self->_state_peer_name( $target ) ] }, $self->_state_peer_route( $target ) );
	last SWITCH;
    }
    if ( $motd and ref $motd eq 'ARRAY' ) {
      push @{ $ref }, { prefix => $server, command => '375', params => [ $nick, "- $server Message of the day - " ] };
      push @{ $ref }, { prefix => $server, command => '372', params => [ $nick, "- $_" ] } for @{ $motd };
      push @{ $ref }, { prefix => $server, command => '376', params => [ $nick, "End of MOTD command" ] };
    } else {
      push @{ $ref }, '422';
    }
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
	push @{ $ref }, { prefix => $server, command => '322', params => [ $nick, $record->{name}, scalar keys %{ $record->{users} }, ( defined $record->{topic} ? $record->{topic} : '' ) ] };
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
	$self->{ircd}->send_output( { prefix => $nick, command => 'NAMES', params => [ @{ $args }, $self->_state_peer_name( $last ) ] }, $self->_state_peer_route( $last ) );
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
	$self->{ircd}->send_output( { prefix => $nick, command => 'WHOIS', params => [ $self->_state_peer_name( $target ), $second ] }, $self->_state_peer_route( $target ) );
	last SWITCH;
    }
    # Okay we got here *phew*
    if ( !$self->_state_nick_exists( $query ) ) {
	push @{ $ref }, [ '401', $query ];
    } else {
	my $record = $self->{state}->{users}->{ u_irc $query };
	push @{ $ref }, { prefix => $server, command => '311', params => [ $nick, $record->{nick}, $record->{auth}->{ident}, $record->{auth}->{hostname}, '*', $record->{ircname} ] };
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
	push @{ $ref }, { prefix => $server, command => '301', params => [ $nick, $record->{nick}, $record->{away} ] } if $record->{type} eq 'c' and $record->{away};
	push @{ $ref }, { prefix => $server, command => '313', params => [ $nick, $record->{nick}, 'is an IRC Operator' ] } if $record->{umode} and $record->{umode} =~ /o/;
	push @{ $ref }, { prefix => $server, command => '338', params => [ $nick, $record->{nick}, $record->{socket}->[0], 'actually using host' ] } if $record->{type} eq 'c';
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
  my $orig = $who;
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
          my $status = ( $memrec->{away} ? 'G' : 'H' );
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
        my $status = ( $nickrec->{away} ? 'G' : 'H' );
	$status .= '*' if $nickrec->{umode} =~ /o/;
	push @{ $rpl_who->{params} }, $status;
	push @{ $rpl_who->{params} }, $nickrec->{hops} . ' ' . $nickrec->{ircname};
	push @{ $ref }, $rpl_who;
    }
    push @{ $ref }, { prefix => $server, command => '315', params => [ $nick, $orig, 'End of WHO list' ] };
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
	push @{ $ref }, { prefix => $server, command => '324', params => [ $nick, $chan, '+' . $record->{mode} ], colonify => 0 };
	push @{ $ref }, { prefix => $server, command => '329', params => [ $nick, $chan, $record->{ts} ], colonify => 0 };
	last SWITCH;
    }
    if ( !$count ) {
	push @{ $ref }, { prefix => $server, command => '324', params => [ $nick, $chan, '+' . $record->{mode}, ( $record->{ckey} || () ), ( $record->{climit} || () ) ], colonify => 0 };
	push @{ $ref }, { prefix => $server, command => '329', params => [ $nick, $chan, $record->{ts} ], colonify => 0 };
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
      $arg = shift ( @{ $parsed_mode->{args} } ) if ( $mode =~ /^(\+[ohvklbIe]|-[ohvbIe])/ );
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
	  next if ( $mode eq '+h' and $record->{users}->{ $arg } =~ /o/ );
	  if ( $char eq 'h' and $record->{users}->{ $arg } =~ /v/ ) {
	     $record->{users}->{ $arg } =~ s/v//g;
	     $reply .= '-v';
	     push @reply_args, (split /!/, $self->_state_user_full( $arg ))[0];
	  }
	  if ( $char eq 'o' and $record->{users}->{ $arg } =~ /h/ ) {
	     $record->{users}->{ $arg } =~ s/h//g;
	     $reply .= '-h';
	     push @reply_args, (split /!/, $self->_state_user_full( $arg ))[0];
	  }
	  $record->{users}->{ $arg }  = join('', sort split //, $record->{users}->{ $arg } . $char );
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
	$record->{mode} = join('', sort split //, $record->{mode} . 'l' ) unless $record->{mode} =~ /l/;
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
	$record->{mode} = join('', sort split //, $record->{mode} . 'k' ) unless $record->{mode} =~ /k/;
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
	$record->{mode} = join('', sort split //, $record->{mode} . $char );
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
	$self->_send_output_to_channel( $chan, { prefix => $self->_state_user_full( $nick ), command => 'MODE', params => [ $chan, $reply, @reply_args ], colonify => 0 } );
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
	$self->{ircd}->send_output( { command => 'SJOIN', params => [ $record->{ts}, $channel, '+' . $record->{mode}, '@' . $nick ] }, @peers );
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
      $self->{ircd}->send_output( { prefix => $server, command => 'SJOIN', params => [ $chanrec->{ts}, $channel, '+', $nick ] }, $self->_state_connected_peers() );
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
    unless ( scalar keys %{ $self->{state}->{chans}->{ $chan  }->{users} } ) {
	delete $self->{state}->{chans}->{ $chan  };
    }
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
    $self->_send_output_to_channel( $chan, { prefix => $self->_state_user_full( $nick ), command => 'KICK', params => [ $chan, $who, $comment ] } );
    $who = u_irc $who; $chan = u_irc $chan;
    delete $self->{state}->{chans}->{ $chan }->{users}->{ $who };
    delete $self->{state}->{users}->{ $who }->{chans}->{ $chan };
    unless ( scalar keys %{ $self->{state}->{chans}->{ $chan  }->{users} } ) {
	delete $self->{state}->{chans}->{ $chan  };
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
	$away = $record->{away} if $record->{away};
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
    my $set = ''; my $peer_ignore;
    my $parsed_mode = parse_mode_line( $umode );
    while ( my $mode = shift ( @{ $parsed_mode->{modes} } ) ) {
	next if $mode eq '+o';
	my ($action,$char) = split //, $mode;
	if ( $action eq '+' and $record->{umode} !~ /$char/ ) {
	  $record->{umode} .= $char;
	  $set .= $mode;
	  if ( $char eq 'i' ) {
	    $self->{state}->{stats}->{invisible}++;
	    $peer_ignore = delete $record->{_ignore_i_umode};
	  }
	}
	if ( $action eq '-' and $record->{umode} =~ /$char/ ) {
	  $record->{umode} =~ s/$char//g;
	  $set .= $mode;
	  $self->{state}->{stats}->{invisible}-- if $char eq 'i';
          if ( $char eq 'o' ) {
    	    $self->{state}->{stats}->{ops_online}--;
            $self->{ircd}->antiflood( $self->_state_user_route( $nick ), 1 );
          }
	}
    }
    if ( $set ) {
      my $hashref = { prefix => $nick, command => 'MODE', params => [ $nick, $set ] };
      $self->{ircd}->send_output( $hashref, $self->_state_connected_peers() ) unless $peer_ignore;
      push @{ $ref }, $hashref;
    }
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
    if ( $self->_state_chan_mode_set( $args->[0], 's' ) and !$self->_state_is_chan_member( $nick, $args->[0] ) ) {
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
    if ( !$self->_state_is_chan_member( $nick, $args->[0] ) ) {
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
    $self->_send_output_to_channel( $args->[0], { prefix => $self->_state_user_full( $nick ), command => 'TOPIC', params => [ $chan_name, $args->[1] ] } );
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_cmd_links {
  my $self = shift;
  my $nick = shift || return;
  my $target = shift;
  my $server = $self->server_name();
  my $ref = [ ];
  SWITCH:{
    if ( $target and !$self->_state_peer_exists( $target ) ) {
	push @{ $ref }, [ '402', $target ];
	last SWITCH;
    }
    if ( $target and ( uc $server ne uc $target ) ) {
	$self->{ircd}->send_output( { prefix => $nick, command => 'LINKS', params => [ $self->_state_peer_name( $target ) ] }, $self->_state_peer_route( $target ) );
	last SWITCH;
    }
    push @{ $ref }, $_ for $self->_state_server_links( $server, $server, $nick );
    push @{ $ref }, { prefix => $server, command => '364', params => [ $nick, $server, $server, join( ' ', '0', $self->server_config('serverdesc') ) ] };
    push @{ $ref }, { prefix => $server, command => '365', params => [ $nick, '*', 'End of /LINKS list.' ] };
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_squit {
  my $self = shift;
  my $peer_id = shift || return;
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  return unless $self->_state_peer_exists( $args->[0] );
  $self->{ircd}->send_output( { command => 'SQUIT', params => [ $self->_state_peer_name( $args->[0] ), $self->server_name() ] }, grep { $_ ne $peer_id } $self->_state_connected_peers() );
  foreach my $nick ( $self->_state_server_squit( $args->[0] ) ) {
    my $output = { prefix => $self->_state_user_full( $nick ), command => 'QUIT', params => [ join ' ', reverse @{ $args } ] };
    my $common = { };
    foreach my $uchan ( $self->_state_user_chans( $nick ) ) {
      $uchan = u_irc $uchan;
      delete $self->{state}->{chans}->{ $uchan }->{users}->{ $nick };
      foreach my $user ( $self->_state_chan_list( $uchan ) ) {
	next unless $self->_state_is_local_user( $user );
	$common->{ $user } = $self->_state_user_route( $user );
      }
      unless ( scalar keys %{ $self->{state}->{chans}->{ $uchan  }->{users} } ) {
	delete $self->{state}->{chans}->{ $uchan  };
      }
    }
    $self->{ircd}->send_output( $output, values %{ $common } );
    my $record = delete $self->{state}->{users}->{ $nick };
    $self->{state}->{stats}->{ops_online}-- if $record->{umode} =~ /o/;
    $self->{state}->{stats}->{invisible}-- if $record->{umode} =~ /i/;
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_kill {
  my $self = shift;
  my $peer_id = shift || return;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
     if ( $self->_state_peer_exists( $args->[0] ) ) {
	last SWITCH;
     }
     if ( !$self->_state_nick_exists( $args->[0] ) ) {
	last SWITCH;
     }
     my $target = ( split /!/, $self->_state_user_full( $args->[0] ) )[0];
     my $comment = $args->[1];
     if ( $self->_state_is_local_user( $target ) ) {
	my $route_id = $self->_state_user_route( $target );
        $self->{ircd}->send_output( { prefix => $nick, command => 'KILL', params => [ $target, join('!', $server, $comment ) ] }, grep { $_ ne $peer_id } $self->_state_connected_peers() );
	$self->{ircd}->send_output( { prefix => $self->_state_user_full( $nick ), command => 'KILL', params => [ $target, join('!', $server, $comment ) ] }, $route_id );
	$self->{state}->{conns}->{ $route_id }->{killed} = 1;
	$self->terminate_conn_error( $route_id, "Killed ($comment)" );
     } else {
	$self->{state}->{users}->{ u_irc $target }->{killed} = 1;
        $self->{ircd}->send_output( { prefix => $nick, command => 'KILL', params => [ $target, join('!', $server, $comment ) ] }, grep { $_ ne $peer_id } $self->_state_connected_peers() );
	$self->{ircd}->send_output( @{ $self->_daemon_peer_quit( $target, "Killed ($nick ($comment))" ) } );
     }
  }
  return @{ $ref } if wantarray();
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_svinfo {
  my $self = shift;
  my $peer_id = shift || return;
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  $self->{state}->{conns}->{ $peer_id }->{svinfo} = $args;
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_ping {
  my $self = shift;
  my $peer_id = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    if ( !$count ) {
	last SWITCH;
    }
    if ( $count >= 2 and ( uc $server ne uc $args->[1] ) ) {
	$self->{ircd}->send_output( { command => 'PING', params => $args }, $self->_state_peer_route( $args->[1] ) ) if $self->_state_peer_exists( $args->[1] );
	$self->{ircd}->send_output( { command => 'PING', params => $args }, $self->_state_user_route( $args->[1] ) ) if $self->_state_user_exists( $args->[1] );
	last SWITCH;
    }
    $self->{ircd}->send_output( { command => 'PONG', params => [ $server, $args->[0] ] }, $peer_id );
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_pong {
  my $self = shift;
  my $peer_id = shift || return;
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    if ( !$count ) {
	last SWITCH;
    }
    if ( $count >= 2 and ( uc $self->server_name() ne uc $args->[1] ) ) {
	$self->{ircd}->send_output( { command => 'PONG', params => $args }, $self->_state_peer_route( $args->[1] ) ) if $self->_state_peer_exists( $args->[1] );
	$self->{ircd}->send_output( { command => 'PONG', params => $args }, $self->_state_user_route( $args->[1] ) ) if $self->_state_nick_exists( $args->[1] );
	last SWITCH;
    }
    delete $self->{state}->{conns}->{ $peer_id }->{pinged};
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_server {
  my $self = shift;
  my $peer_id = shift || return;
  my $prefix = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  my $peer = $self->{state}->{conns}->{ $peer_id }->{name};
  SWITCH: {
    if ( !$count or $count < 2 ) {
	last SWITCH;
    }
    if ( $self->_state_peer_exists( $args->[0] ) ) {
	$self->terminate_conn_error( $peer_id, 'Server exists' );
	last SWITCH;
    }
    my $record = { 
		   name => $args->[0], 
		   hops => $args->[1], 
		   desc => ( $args->[2] || '' ),
		   route_id => $peer_id,
		   type => 'r',
		   peers => { },
		   users => { },
    		 };
    my $uname = uc $record->{name};
    $self->{state}->{peers}->{ $uname } = $record;
    $self->{state}->{peers}->{ uc $prefix }->{peers}->{ $uname } = $record;
    $self->{ircd}->send_output( { prefix => $prefix, command => 'SERVER', params => [ $record->{name}, $record->{hops} + 1, $record->{desc} ] }, grep { $_ ne $peer_id } $self->_state_connected_peers() );
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_quit {
  my $self = shift;
  my $nick = shift || return;
  my $qmsg = shift || 'Client Quit';
  my $conn_id = shift;
  my $ref = [ ];
  my $full = $self->_state_user_full( $nick );

  $nick = u_irc $nick;
  my $record = delete $self->{state}->{users}->{ $nick };
  return unless $record;
  $self->{ircd}->send_output( { prefix => $record->{nick}, command => 'QUIT', params => [ $qmsg ] }, grep { !$conn_id or $_ ne $conn_id } $self->_state_connected_peers() ) unless $record->{killed};
  push @{ $ref }, { prefix => $full, command => 'QUIT', params => [ $qmsg ] };
  # Okay, all 'local' users who share a common channel with user.
  my $common = { };
  foreach my $uchan ( keys %{ $record->{chans} } ) {
    delete $self->{state}->{chans}->{ $uchan }->{users}->{ $nick };
    foreach my $user ( $self->_state_chan_list( $uchan ) ) {
	next unless $self->_state_is_local_user( $user );
	$common->{ $user } = $self->_state_user_route( $user );
    }
    unless ( scalar keys %{ $self->{state}->{chans}->{ $uchan  }->{users} } ) {
	delete $self->{state}->{chans}->{ $uchan  };
    }
  }
  push( @{ $ref }, $common->{$_} ) for keys %{ $common };
  $self->{state}->{stats}->{ops_online}-- if $record->{umode} =~ /o/;
  delete $self->{state}->{peers}->{ uc $record->{server} }->{users}->{ $nick };
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_nick {
  my $self = shift;
  my $peer_id = shift || return;
  my $prefix = shift;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  my $peer = $self->{state}->{conns}->{ $peer_id }->{name};
  SWITCH: {
    if ( !$count or ( $prefix and $count < 2 ) or $count < 8 ) {
	$self->terminate_conn_error( $peer_id, 'Not enough arguments to server command.' );
	last SWITCH;
    }
    if ( $prefix and $self->_state_nick_exists( $args->[0] ) ) {
	last SWITCH;
    }
    if ( $prefix ) {
	my $full = $self->_state_user_full( $prefix );
	my $unick = u_irc $prefix;
	my $new = $args->[0]; my $unew = u_irc $new;
	my $ts = $args->[1];
	my $record = $self->{state}->{users}->{ $unick };
	my $server = uc $record->{server};
        if ( $unick eq $unew ) {
	  $record->{nick} = $new;
	  $record->{ts} = $ts;
    	} else {
	  $record->{nick} = $new;
	  $record->{ts} = $ts;
	  delete $self->{state}->{users}->{ $unick };
	  $self->{state}->{users}->{ $unew } = $record;
	  delete $self->{state}->{peers}->{ $server }->{users}->{ $unick };
	  $self->{state}->{peers}->{ $server }->{users}->{ $unew } = $record;
	  foreach my $chan ( keys %{ $record->{chans} } ) {
	    $self->{state}->{chans}->{ $chan }->{users}->{ $unew } = delete $self->{state}->{chans}->{ $chan }->{users}->{ $unick };
	  }
    	}
    	my $common = { };
    	foreach my $chan ( keys %{ $record->{chans} } ) {
      	  foreach my $user ( $self->_state_chan_list( $chan ) ) {
		next unless $self->_state_is_local_user( $user );
		$common->{ $user } = $self->_state_user_route( $user );
      	  }
    	}
        $self->{ircd}->send_output( { prefix => $prefix, command => 'NICK', params => $args }, grep { $_ ne $peer_id } $self->_state_connected_peers() );
    	$self->{ircd}->send_output( { prefix => $full, command => 'NICK', params => [ $new ] }, map{ $common->{$_} } keys %{ $common } );
	last SWITCH;
    }
    if ( $self->_state_nick_exists( $args->[0] ) and my ($nick,$userhost) = split /!/, $self->_state_user_full( $args->[0] ) ) {
	my $unick = u_irc $nick;
	my $incoming = join '@', @{ $args }[4..5];
	if ( $userhost eq $incoming ) {
	  my $ts = $self->{state}->{users}->{ $unick }->{ts};
	  if ( $args->[2] > $ts ) {
		$self->{state}->{users}->{ $unick }->{nick_collision} = 1;
		$self->daemon_server_kill( $nick, 'Nick Collision', $peer_id );
	  } else {
		last SWITCH;
	  }
	} else {
	  my $ts = $self->{state}->{users}->{ $unick }->{ts};
	  if ( $args->[2] < $ts ) {
		$self->{state}->{users}->{ $unick }->{nick_collision} = 1;
		$self->daemon_server_kill( $nick, 'Nick Collision', $peer_id );
	  } else {
		last SWITCH;
	  }
	}
    }
    if ( !$self->_state_peer_exists( $args->[6] ) ) {
	last SWITCH;
    }
    my $unick = u_irc $args->[0];
    $args->[3] =~ s/^\+//g;
    my $record = { 
			nick => $args->[0], 
			hops => $args->[1],
			ts   => $args->[2],
			type => 'r',
			umode => $args->[3],
			auth => { ident => $args->[4], hostname => $args->[5] },
			route_id => $peer_id,
			server => $args->[6],
			ircname => ( $args->[7] || '' ),
		  };
    $self->{state}->{users}->{ $unick } = $record;
    $self->{state}->{stats}->{ops_online}++ if $record->{umode} =~ /o/;
    $self->{state}->{stats}->{invisible}++ if $record->{umode} =~ /i/;
    $self->{state}->{peers}->{ uc $record->{server} }->{users}->{ $unick } = $record;
    $self->{ircd}->send_output( { command => 'NICK', params => $args }, grep { $_ ne $peer_id } $self->_state_connected_peers() );
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_part {
  my $self = shift;
  my $peer_id = shift || return;
  my $nick = shift || return;
  my $chan = shift;
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    if ( !$chan ) {
	last SWITCH;
    }
    if ( !$self->_state_chan_exists( $chan ) ) {
	last SWITCH;
    }
    if ( !$self->_state_is_chan_member( $nick, $chan ) ) {
	last SWITCH;
    }
    $self->_send_output_to_channel( $chan, { prefix => $self->_state_user_full( $nick ), command => 'PART', params => [ $chan, ( $args->[0] || $nick ) ] }, $peer_id );
    $nick = u_irc $nick;
    $chan = u_irc $chan;
    delete $self->{state}->{chans}->{ $chan }->{users}->{ $nick };
    delete $self->{state}->{users}->{ $nick }->{chans}->{ $chan };
    unless ( scalar keys %{ $self->{state}->{chans}->{ $chan  }->{users} } ) {
	delete $self->{state}->{chans}->{ $chan  };
    }
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_kick {
  my $self = shift;
  my $peer_id = shift || return;
  my $nick = shift || return;
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    if ( !$count or $count < 2 ) {
	last SWITCH;
    }
    my $chan = ( split /,/, $args->[0] )[0];
    my $who = ( split /,/, $args->[1] )[0];
    if ( !$self->_state_chan_exists( $chan ) ) {
	last SWITCH;
    }
    $chan = $self->_state_chan_name( $chan );
    if ( !$self->_state_nick_exists( $who ) ) {
	last SWITCH;
    }
    $who = ( split /!/, $self->_state_user_full( $who ) )[0];
    if ( !$self->_state_is_chan_op( $nick, $chan ) ) {
	last SWITCH;
    }
    if ( !$self->_state_is_chan_member( $who, $chan ) ) {
	last SWITCH;
    }
    my $comment = $args->[2] || $who;
    $self->_send_output_to_channel( $chan, { prefix => $self->_state_user_full( $nick ), command => 'KICK', params => [ $chan, $who, $comment ] }, $peer_id );
    $who = u_irc $who; $chan = u_irc $chan;
    delete $self->{state}->{chans}->{ $chan }->{users}->{ $who };
    delete $self->{state}->{users}->{ $who }->{chans}->{ $chan };
    unless ( scalar keys %{ $self->{state}->{chans}->{ $chan  }->{users} } ) {
	delete $self->{state}->{chans}->{ $chan  };
    }
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_sjoin {
  my $self = shift;
  my $peer_id = shift || return;
  my $prefix = shift;
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  my $peer = $self->{state}->{conns}->{ $peer_id }->{name};
  SWITCH: {
    if ( !$count or $count < 4 ) {
	last SWITCH;
    }
    my $ts = $args->[0];
    my $chan = $args->[1];
    my $nicks = pop @{ $args };
    my $ignore_modes = 0;
    if ( !$self->_state_chan_exists( $chan ) ) {
	my $chanrec = { name => $chan, ts => $ts };
	my @args = @{ $args }[2..$#{ $args }];
	my $cmode = shift @args;
	$cmode =~ s/^\+//g;
	$chanrec->{mode} = $cmode;
	foreach my $mode ( split //, $cmode ) {
	  my $arg;
	  $arg = shift @args if $mode =~ /[lk]/;
	  $chanrec->{climit} = $arg if $mode eq 'l';
	  $chanrec->{ckey} = $arg if $mode eq 'k';
	}
	push @{ $args }, $nicks;
	my $uchan = u_irc $chanrec->{name};
	foreach my $nick ( split /\s+/, $nicks ) {
	  $nick = u_irc $nick;
	  my $umode = '';
	  $umode .= 'o' if $nick =~ s/\@//g;
	  $umode = 'h' if $nick =~ s/\%//g;
	  $umode .= 'v' if $nick =~ s/\+//g;
	  $chanrec->{users}->{ $nick } = $umode;
	  $self->{state}->{users}->{ $nick }->{chans}->{ $uchan } = $umode;
	}
	$self->{state}->{chans}->{ $uchan } = $chanrec;
	$self->{ircd}->send_output( { prefix => $prefix, command => 'SJOIN', params => $args }, grep { $_ ne $peer_id } $self->_state_connected_peers() );
	last SWITCH;
    }
    my $chanrec = $self->{state}->{chans}->{ u_irc $chan };
    if ( $ts < $chanrec->{ts} ) {
	  # Incoming is older
	  if ( $nicks =~ /^\@/ ) {
	     # Remove all modes expect bans/invex/excepts
	     # deop/dehalfop/devoice all existing users
	     my $deop; my @deop_list;
	     my $common = { };
	     foreach my $user ( keys %{ $chanrec->{users} } ) {
		$common->{ $user } = $self->_state_user_route( $user ) if $self->_state_is_local_user( $user );
		next unless $chanrec->{users}->{ $user };
		my $current = $chanrec->{users}->{ $user };
		my $proper = ( split /!/, $self->_state_user_full( $user ) )[0];
		$chanrec->{users}->{ $user } = '';
		$self->{state}->{users}->{ $user }->{chans}->{ u_irc $chanrec->{name} } = '';
		$deop .= '-' . $current; 
		push @deop_list, $proper for split //, $current;
	     }
	     if ( scalar keys %{ $common } and $deop ) {
		$self->{ircd}->send_output( { prefix => $self->server_name(), command => 'MODE', params => [ $chanrec->{name}, unparse_mode_line( $deop ), @deop_list ], colonify => 0 }, values %{ $common } );
	     }
	     my $origmode = $chanrec->{mode};
	     my @args = @{ $args }[2..$#{ $args }];
	     my $chanmode = shift @args;
	     my $reply; my @reply_args;
	     foreach my $mode ( grep { $_ ne '+' } split //, $chanmode ) {
		my $arg;
		$arg = shift @args if $mode =~ /[lk]/;
		if ( $mode eq 'l' and ( $chanrec->{mode} !~ /l/ or $arg ne $chanrec->{climit} ) ) {
		  $reply .= '+' . $mode;
		  push @reply_args, $arg;
		  $chanrec->{mode} .= $mode unless $chanrec->{mode} =~ /$mode/;
		  $chanrec->{mode} = join '', sort split //, $chanrec->{mode};
		  $chanrec->{climit} = $arg;
		} elsif ( $mode eq 'k' and ( $chanrec->{mode} !~ /k/ or $arg ne $chanrec->{ckey} ) ) {
		  $reply .= '+' . $mode;
		  push @reply_args, $arg;
		  $chanrec->{mode} .= $mode unless $chanrec->{mode} =~ /$mode/;
		  $chanrec->{mode} = join '', sort split //, $chanrec->{mode};
		  $chanrec->{ckey} = $arg;
		} elsif ( $chanrec->{mode} !~ /$mode/ ) {
		  $reply .= '+' . $mode;
		  $chanrec->{mode} .= $mode unless $chanrec->{mode} =~ /$mode/;
		  $chanrec->{mode} = join '', sort split //, $chanrec->{mode};
		}
	     }
	     if ( scalar keys %{ $common } and ( $reply or $origmode ) ) {
		$origmode = join '', grep { $chanmode !~ /$_/ } split //, ( $origmode || '' );
		$chanrec->{mode} =~ s/[$origmode]//g if $origmode;
		$reply = '-' . $origmode . $reply if $origmode;
		if ( $origmode and $origmode =~ /k/ ) {
		  unshift @reply_args, '*';
		  delete $chanrec->{ckey};
		}
		delete $chanrec->{climit} if $origmode and $origmode =~ /l/;
		$self->{ircd}->send_output( { prefix => $self->server_name(), command => 'MODE', params => [ $chanrec->{name}, unparse_mode_line( $reply ), @reply_args ], colonify => 0 }, values %{ $common } ) if $reply;
	     }
	     $chanrec->{ts} = $ts;
	  } elsif ( scalar grep { /^\@/ } $self->_state_chan_list_prefixed( $chan ) ) {
	     $args->[0] = $chanrec->{ts};
	  } else {
	     $chanrec->{ts} = $ts;
	  }
    } elsif ( $ts > $chanrec->{ts} ) {
	  # Incoming is younger
	  if ( $nicks !~ /^\@/ ) {
	    $args->[0] = $chanrec->{ts};
	  } elsif ( scalar grep { /^\@/ } $self->_state_chan_list_prefixed( $chan ) ) {
	    pop @{ $args } while $#{ $args } > 2;
	    $args->[2] = '+';
	    $args->[0] = $chanrec->{ts};
	    $nicks = join ' ', map { s/[@%+]//g; $_; } split /\s+/, $nicks;
	  } else {
	     $chanrec->{ts} = $ts;
	  }
    }
    # Propagate SJOIN to connected peers except the one that told us.
    push @{ $args }, $nicks;
    $self->{ircd}->send_output( { prefix => $prefix, command => 'SJOIN', params => $args }, grep { $_ ne $peer_id } $self->_state_connected_peers() );
    # Generate appropriate JOIN messages for all local channel members
    my $uchan = u_irc $chanrec->{name};
    my @local_users = map { $self->_state_user_route($_) } grep { $self->_state_is_local_user($_) } keys %{ $chanrec->{users} };
    my $modes; my @mode_parms;
    foreach my $nick ( split /\s+/, $nicks ) {
	  my $proper = $nick;
	  $proper =~ s/[@%+]//g;
	  $nick = u_irc $nick;
	  my $umode = ''; my @op_list;
	  $umode .= 'o' if $nick =~ s/\@//g;
	  $umode = 'h' if $nick =~ s/\%//g;
	  $umode .= 'v' if $nick =~ s/\+//g;
	  $chanrec->{users}->{ $nick } = $umode;
	  $self->{state}->{users}->{ $nick }->{chans}->{ $uchan } = $umode;
          push @op_list, $proper for split //, $umode;
	  $self->{ircd}->send_output( { prefix => $self->_state_user_full( $nick ), command => 'JOIN', params => [ $chanrec->{name} ] }, @local_users );
	  if ( $umode ) {
		$modes .= $umode;
		push @mode_parms, @op_list;
	  }
    }
    $self->{ircd}->send_output( { prefix => $self->server_name(), command => 'MODE', params => [ $chanrec->{name}, '+' . $modes, @mode_parms ], colonify => 0 }, @local_users ) if $modes;
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_mode {
  my $self = shift;
  my $peer_id = shift || return;
  my $nick = shift || return;
  my $chan = shift;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    if ( !$self->_state_chan_exists( $chan ) ) {
	last SWITCH;
    }
    my $record = $self->{state}->{chans}->{ u_irc $chan };
    $chan = $record->{name};
    if ( $chan =~ /^\x2B/ ) {
	last SWITCH;
    }
    my $full;
    $full = $self->_state_user_full( $nick ) if $self->_state_nick_exists( $full );
    my $parsed_mode = parse_mode_line( @{ $args } );
    while( my $mode = shift ( @{ $parsed_mode->{modes} } ) ) {
      my $arg;
      $arg = shift ( @{ $parsed_mode->{args} } ) if ( $mode =~ /^(\+[ohvklbIe]|-[ohvbIe])/ );
      if ( my ($flag,$char) = $mode =~ /^(\+|-)([ohv])/ ) {
	if ( $flag eq '+' and $record->{users}->{ u_irc $arg } !~ /$char/ ) {
	  # Update user and chan record
	  $arg = u_irc $arg;
	  next if ( $mode eq '+h' and $record->{users}->{ $arg } =~ /o/ );
	  if ( $char eq 'h' and $record->{users}->{ $arg } =~ /v/ ) {
	     $record->{users}->{ $arg } =~ s/v//g;
	  }
	  if ( $char eq 'o' and $record->{users}->{ $arg } =~ /h/ ) {
	     $record->{users}->{ $arg } =~ s/h//g;
	  }
	  $record->{users}->{ $arg }  = join('', sort split //, $record->{users}->{ $arg } . $char );
	  $self->{state}->{users}->{ $arg }->{chans}->{ u_irc $chan } = $record->{users}->{ $arg };
        }
	if ( $flag eq '-' and $record->{users}->{ u_irc $arg } =~ /$char/ ) {
	  # Update user and chan record
	  $arg = u_irc $arg;
	  $record->{users}->{ $arg } =~ s/$char//g;
	  $self->{state}->{users}->{ $arg }->{chans}->{ u_irc $chan } = $record->{users}->{ $arg };
        }
	next;
      }
      if ( $mode eq '+l' and $arg =~ /^\d+$/ and $arg > 0 ) {
	$record->{mode} = join('', sort split //, $record->{mode} . 'l' ) unless $record->{mode} =~ /l/;
	$record->{climit} = $arg;
	next;
      }
      if ( $mode eq '-l' and $record->{mode} =~ /l/ ) {
	$record->{mode} =~ s/l//g;
	delete $record->{climit};
	next;
      }
      if ( $mode eq '+k' and $arg ) {
	$record->{mode} = join('', sort split //, $record->{mode} . 'k' ) unless $record->{mode} =~ /k/;
	$record->{ckey} = $arg;
	next;
      }
      if ( $mode eq '-k' and $record->{mode} =~ /k/ ) {
	$record->{mode} =~ s/k//g;
	delete $record->{ckey};
	next;
      }
      # Bans
      if ( my ($flag) = $mode =~ /(\+|-)b/ ) {
	my $mask = parse_ban_mask( $arg );
	my $umask = u_irc $mask;
	if ( $flag eq '+' and !$record->{bans}->{ $umask } ) {
	  $record->{bans}->{ $umask } = [ $mask, ( $full || $server ), time() ];
	}
	if ( $flag eq '-' and $record->{bans}->{ $umask } ) {
	  delete $record->{bans}->{ $umask };
	}
	next;
      }
      # Invex
      if ( my ($flag) = $mode =~ /(\+|-)I/ ) {
	my $mask = parse_ban_mask( $arg );
	my $umask = u_irc $mask;
	if ( $flag eq '+' and !$record->{invex}->{ $umask } ) {
	   $record->{invex}->{ $umask } = [ $mask, ( $full || $server ), time() ];
	}
	if ( $flag eq '-' and $record->{invex}->{ $umask } ) {
	  delete $record->{invex}->{ $umask };
	}
	next;
      }
      # Exceptions
      if ( my ($flag) = $mode =~ /(\+|-)e/ ) {
	my $mask = parse_ban_mask( $arg );
	my $umask = u_irc $mask;
	if ( $flag eq '+' and !$record->{excepts}->{ $umask } ) {
	  $record->{excepts}->{ $umask } = [ $mask, ( $full || $server ), time() ];
	}
	if ( $flag eq '-' and $record->{excepts}->{ $umask } ) {
	  delete $record->{excepts}->{ $umask };
	}
	next;
      }
      # The rest should be argumentless.
      my ($flag,$char) = split //, $mode;
      if ( $flag eq '+' and $record->{mode} !~ /$char/ ) {
	$record->{mode} = join('', sort split //, $record->{mode} . $char );
	next;
      }
      if ( $flag eq '-' and $record->{mode} =~ /$char/ ) {
	$record->{mode} =~ s/$char//g;
	next;
      }
    } # while
    unshift @{ $args }, $record->{name};
    $self->{ircd}->send_output( { prefix => $nick, command => 'MODE', params => $args, colonify => 0 }, grep { $_ ne $peer_id } $self->_state_connected_peers() );
    $self->{ircd}->send_output( { prefix => ( $full || $server ), command => 'MODE', params => $args, colonify => 0 }, map { $self->_state_user_route($_) } grep { $self->_state_is_local_user($_) } keys %{ $record->{users} } ); 
  } # SWITCH
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_umode {
  my $self = shift;
  my $peer_id = shift || return;
  my $nick = shift || return;
  shift;
  my $umode = shift;
  my $server = $self->server_name();
  my $ref = [ ];
  my $record = $self->{state}->{users}->{ u_irc $nick };
  my $parsed_mode = parse_mode_line( $umode );
  while ( my $mode = shift @{ $parsed_mode->{modes} } ) {
	my ($action,$char) = split //, $mode;
	if ( $action eq '+' and $record->{umode} !~ /$char/ ) {
	  $record->{umode} .= $char;
	  $self->{state}->{stats}->{invisible}++ if $char eq 'i';
          if ( $char eq 'o' ) {
    	    $self->{state}->{stats}->{ops_online}++;
          }
	}
	if ( $action eq '-' and $record->{umode} =~ /$char/ ) {
	  $record->{umode} =~ s/$char//g;
	  $self->{state}->{stats}->{invisible}-- if $char eq 'i';
          if ( $char eq 'o' ) {
    	    $self->{state}->{stats}->{ops_online}--;
          }
	}
  }
  $self->{ircd}->send_output( { prefix => $nick, command => 'MODE', params => [ $nick, $umode ] }, grep { $_ ne $peer_id } $self->_state_connected_peers() );
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_message {
  my $self = shift;
  my $peer_id = shift || return;
  my $nick = shift || return;
  my $type = shift || return;
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    my $full = $self->_state_user_full( $nick ) || $self->server_name();
    LOOP: foreach my $target ( split /,/, $args->[0] ) {
	$target = ( split /!/, $target )[0] if $target =~ /\x21/;
	$target = ( split /\x40/, $target )[0] if $target =~ /\x40/;
	unless ( $self->_state_chan_exists( $target ) or $self->_state_nick_exists( $target ) ) {
	   next LOOP;
	}
	my $channel = $self->_state_chan_name( $target );
	if ( $channel ) {
	  my $common = { };
	  my $msg = { command => $type, params => [ $channel, $args->[1] ] };
	  foreach my $member ( keys %{ $self->{state}->{chans}->{ u_irc $channel }->{users} } ) {
		$common->{ $self->_state_user_route( $member ) }++;
	  }
	  delete $common->{ $peer_id };
	  foreach my $route_id ( keys %{ $common } ) {
		$msg->{prefix} = $nick;
		$msg->{prefix} = $full if $self->_connection_is_client( $route_id );
	  	$self->{ircd}->send_output( $msg, $route_id )
	  }
	  next LOOP;
	}
	if ( $self->_state_nick_exists( $target ) ) {
	  $target = ( split /!/, $self->_state_user_full( $target ) )[0];
	  my $msg = { prefix => $nick, command => $type, params => [ $target, $args->[1] ] };
	  my $route_id = $self->_state_user_route( $target );
	  $msg->{prefix} = $full if $self->_connection_is_client( $route_id );
	  $self->{ircd}->send_output( $msg, $route_id );
	  next LOOP;
	}
     }
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_topic {
  my $self = shift;
  my $peer_id = shift || return;
  my $nick = shift || return;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH:{
    if ( !$count ) {
	last SWITCH;
    }
    if ( !$self->_state_chan_exists( $args->[0] ) ) {
	last SWITCH;
    }
    my $chan_name = $self->_state_chan_name( $args->[0] );
    my $record = $self->{state}->{chans}->{ u_irc $args->[0] };
    $record->{topic} = [ $args->[1], $self->_state_user_full( $nick ), time() ];
    $self->_send_output_to_channel( $args->[0], { prefix => $self->_state_user_full( $nick ), command => 'TOPIC', params => [ $chan_name, $args->[1] ] }, $peer_id );
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _daemon_peer_away {
  my $self = shift;
  my $peer_id = shift || return;
  my $nick = shift || return;
  my $msg = shift;
  my $server = $self->server_name();
  my $ref = [ ];
  SWITCH: {
     my $record = $self->{state}->{users}->{ u_irc $nick };
     if ( !$msg ) {
	delete $record->{away};
        $self->{ircd}->send_output( { prefix => $nick, command => 'AWAY', colonify => 0 }, grep { $_ ne $peer_id } $self->_state_connected_peers() );
	last SWITCH;
     }
     $record->{away} = $msg;
     $self->{ircd}->send_output( { prefix => $nick, command => 'AWAY', params => [ $msg ], colonify => 0 }, grep { $_ ne $peer_id } $self->_state_connected_peers() );
  }
  return @{ $ref } if wantarray();
  return $ref;
}

#################
# State methods #
#################

sub _state_create {
  my $self = shift;

  $self->_state_delete();
  # Connection specific tables
  $self->{state}->{conns} = { };
  # IRC State specific
  $self->{state}->{users} = { };
  $self->{state}->{peers} = { };
  $self->{state}->{chans} = { };
  # Register ourselves as a peer.
  $self->{state}->{peers}->{ uc $self->server_name() } = { name => $self->server_name(), hops => 0, desc => $self->{config}->{SERVERDESC} };
  $self->{state}->{stats} = { maxlocal => 0, maxglobal => 0, ops_online => 0, invisible => 0 };
  return 1;
}

sub _state_delete {
  my $self = shift;
  delete $self->{state};
  return 1;
}

sub _state_update_stats {
  my $self = shift;
  my $server = $self->server_name();
  my $global = scalar keys %{ $self->{state}->{users} };
  my $local = scalar keys %{ $self->{state}->{peers}->{ uc $server }->{users} };
  $self->{state}->{stats}->{maxglobal} = $global if $local > $self->{state}->{stats}->{maxglobal};
  $self->{state}->{stats}->{maxlocal} = $local if $local > $self->{state}->{stats}->{maxlocal};
  return 1;
}

sub _state_auth_peer_conn {
  my $self = shift;
  my ($conn_id,$name,$pass) = @_;
  return unless $conn_id and $self->_connection_exists( $conn_id );
  return unless $name and $pass;
  my $peers = $self->{config}->{peers};
  return 0 unless $peers->{ uc $name } or $peers->{ uc $name }->{pass} ne $pass;
  my $conn = $self->{state}->{conns}->{ $conn_id };
  return 1 if !$peers->{ uc $name }->{ipmask} and $conn->{socket}->[0] =~ /^127\./;
  return 0 unless $peers->{ uc $name }->{ipmask};
  my $client_ip = $conn->{socket}->[0];
  if ( ref $peers->{ uc $name }->{ipmask} eq 'ARRAY' ) {
    foreach my $block ( grep { $_->isa('Net::Netmask') } @{ $peers->{ uc $name }->{ipmask} } ) {
    	return 1 if $block->match( $client_ip );
    }
  } 
  return 1 if ref $peers->{ uc $name }->{ipmask} eq 'SCALAR' and matches_mask( $peers->{ uc $name }->{ipmask}, $client_ip );
  return 0;
}

sub _state_send_credentials {
  my $self = shift;
  my $conn_id = shift || return;
  my $name = shift || return;
  return unless $self->_connection_exists( $conn_id );
  return unless $self->{config}->{peers}->{ uc $name };
  my $peer = $self->{config}->{peers}->{ uc $name };
  $self->{ircd}->send_output( { command => 'PASS', params => [ $peer->{rpass}, 'TS' ] }, $conn_id );
  $self->{ircd}->send_output( { command => 'CAPAB', params => [ join ' ', @{ $self->{config}->{capab} } ] }, $conn_id );
  my $rec = $self->{state}->{peers}->{ uc $self->server_name() };
  $self->{ircd}->send_output( { command => 'SERVER', params => [ $rec->{name}, $rec->{hops} + 1, $rec->{desc} ] }, $conn_id );
  $self->{ircd}->send_output( { command => 'SVINFO', params => [ 5, 5, 0, time() ] }, $conn_id );
  return 1;
}

sub _state_send_burst {
  my $self = shift;
  my $conn_id = shift || return;
  return unless $self->_connection_exists( $conn_id );
  my $server = $self->server_name();
  my $conn = $self->{state}->{conns}->{ $conn_id };
  my $burst = scalar grep { /^EOB$/i } @{ $conn->{capab} };
  my $invex = scalar grep { /^IE$/i } @{ $conn->{capab} };
  my $excepts = scalar grep { /^EX$/i } @{ $conn->{capab} };
  # Send SERVER burst
  $self->{ircd}->send_output( $_, $conn_id ) for $self->_state_server_burst( $server, $conn->{name} );
  # Send NICK burst
  foreach my $nick ( keys %{ $self->{state}->{users} } ) {
    my $record = $self->{state}->{users}->{ $nick };
    next if $record->{route_id} eq $conn_id;
    my $arrayref = [ $record->{nick}, $record->{hops} + 1, $record->{ts}, ( '+' . $record->{umode} ), $record->{auth}->{ident}, $record->{auth}->{hostname}, $record->{server}, $record->{ircname} ];
    $self->{ircd}->send_output( { command => 'NICK', params => $arrayref }, $conn_id );
  }
  # Send SJOIN+MODE burst
  foreach my $chan ( keys %{ $self->{state}->{chans} } ) {
    my $chanrec = $self->{state}->{chans}->{ $chan };
    my @nicks = map { $_->[1] }
		sort { $a->[0] cmp $b->[0] } 
		map { my $w = $_; $w =~ tr/@%+/ABC/; [ $w, $_ ]; } $self->_state_chan_list_prefixed( $chan );
    my $arrayref2 = [ $chanrec->{ts}, $chanrec->{name}, '+' . $chanrec->{mode}, ( $chanrec->{ckey} || () ), ( $chanrec->{climit} || () ), join ' ', @nicks ];
    $self->{ircd}->send_output( { prefix => $server, command => 'SJOIN', params => $arrayref2 }, $conn_id );
    # TODO: MODE burst
  }
  $self->{ircd}->send_output( { prefix => $server, command => 'EOB' }, $conn_id ) if $burst;
  return 1;
}

sub _state_server_burst {
  my $self = shift;
  my $peer = shift || return;
  my $targ = shift || return;
  return unless $self->_state_peer_exists( $peer ) and $self->_state_peer_exists( $targ );
  my $ref = [ ];
  $peer = $self->_state_peer_name( $peer );
  my $upeer = uc $peer; 
  my $utarg = uc $targ;
  foreach my $server ( keys %{ $self->{state}->{peers}->{ $upeer }->{peers} } ) {
	next if $server eq $utarg;
	my $rec = $self->{state}->{peers}->{ $server };
  	push @{ $ref }, { prefix => $peer, command => 'SERVER', params => [ $rec->{name}, $rec->{hops} + 1, $rec->{desc} ] };
	push @{ $ref }, $_ for $self->_state_server_burst( $rec->{name}, $targ );
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _state_server_links {
  my $self = shift;
  my $peer = shift || return;
  my $orig = shift || return;
  my $nick = shift || return;
  return unless $self->_state_peer_exists( $peer );
  my $ref = [ ];
  $peer = $self->_state_peer_name( $peer );
  my $upeer = uc $peer; 
  foreach my $server ( keys %{ $self->{state}->{peers}->{ $upeer }->{peers} } ) {
	my $rec = $self->{state}->{peers}->{ $server };
	push @{ $ref }, $_ for $self->_state_server_links( $rec->{name}, $orig, $nick );
  	push @{ $ref }, { prefix => $orig, command => '364', params => [ $nick, $rec->{name}, $peer, join( ' ', $rec->{hops}, $rec->{desc} ) ] };
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub _state_server_squit {
  my $self = shift;
  my $peer = shift || return;
  return unless $self->_state_peer_exists( $peer );
  my $ref = [ ];
  my $upeer = uc $peer;
  push @{ $ref }, $_ for keys %{ $self->{state}->{peers}->{ $upeer }->{users} };
  foreach my $server ( keys %{ $self->{state}->{peers}->{ $upeer }->{peers} } ) {
    push @{ $ref }, $_ for $self->_state_server_squit( $server );
  }
  delete $self->{state}->{peers}->{ $upeer };
  delete $self->{state}->{peers}->{ uc $self->server_name() }->{peers}->{ $upeer };
  return @{ $ref } if wantarray();
  return $ref;
}

sub _state_register_peer {
  my $self = shift;
  my $conn_id = shift || return;
  return unless $self->_connection_exists( $conn_id );
  my $record = $self->{state}->{conns}->{ $conn_id };
  $self->_state_send_credentials( $conn_id, $record->{name} ) unless $record->{cntr};
  $record->{burst} = $record->{registered} = 1;
  $record->{type} = 'p';
  $record->{route_id} = $conn_id;
  $record->{users} = { };
  $self->{state}->{peers}->{ uc $self->server_name() }->{peers}->{ uc $record->{name} } = $record;
  $self->{state}->{peers}->{ uc $record->{name} } = $record;
  $self->{ircd}->antiflood( $conn_id => 0 );
  $self->{ircd}->send_output( { prefix => $self->server_name(), command => 'SERVER', params => [ $record->{name}, $record->{hops} + 1, $record->{desc} ] }, grep { $_ ne $conn_id } $self->_state_connected_peers() );
  return 1;
}

sub _state_register_client {
  my $self = shift;
  my $conn_id = shift || return;
  return unless $self->_connection_exists( $conn_id );
  my $record = $self->{state}->{conns}->{ $conn_id };
  $record->{server} = $self->server_name();
  $record->{hops} = 0;
  $record->{route_id} = $conn_id;
  $record->{umode} = '';
  $record->{_ignore_i_umode} = 1;
  $record->{ts} = $record->{idle_time} = $record->{conn_time} = time();
  $record->{auth}->{ident} = '^' . $record->{user} unless $record->{auth}->{ident};
  $record->{auth}->{hostname} = $self->server_name() if $record->{socket}->[0] =~ /^127\./;
  $record->{auth}->{hostname} = $record->{socket}->[0] unless $record->{auth}->{hostname};
  $self->{state}->{users}->{ u_irc( $record->{nick} ) } = $record;
  $self->{state}->{peers}->{ uc( $record->{server} ) }->{users}->{ u_irc( $record->{nick} ) } = $record; 
  my $arrayref = [ $record->{nick}, $record->{hops} + 1, $record->{ts}, '+i', $record->{auth}->{ident}, $record->{auth}->{hostname}, $record->{server}, $record->{ircname} ];
  $self->{ircd}->send_output( { command => 'NICK', params => $arrayref }, $self->_state_connected_peers() );
  $self->_state_update_stats();
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

sub _state_user_ip {
  my $self = shift;
  my $nick = shift || return;
  return unless $self->_state_nick_exists( $nick ) and $self->_state_is_local_user( $nick );
  my $record = $self->{state}->{users}->{ u_irc $nick };
  return $record->{socket}->[0];
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
  my $record = $self->{state}->{users}->{ u_irc $nick };
  return 1 if defined ( $record->{chans}->{ u_irc $chan } );
  return 0;
}

sub _state_user_chan_mode {
  my $self = shift;
  my $nick = shift || return;
  my $chan = shift || return;
  return unless $self->_state_is_chan_member( $nick, $chan );
  return $self->{state}->{users}->{ u_irc $nick }->{chans}->{ u_irc $chan };
}

sub _state_is_chan_op {
  my $self = shift;
  my $nick = shift || return;
  my $chan = shift || return;
  return unless $self->_state_is_chan_member( $nick, $chan );
  my $record = $self->{state}->{users}->{ u_irc $nick };
  return 1 if $record->{chans}->{ u_irc $chan } =~ /o/;
  return 0;
}

sub _state_is_chan_hop {
  my $self = shift;
  my $nick = shift || return;
  my $chan = shift || return;
  return unless $self->_state_is_chan_member( $nick, $chan );
  my $record = $self->{state}->{users}->{ u_irc $nick };
  return 1 if $record->{chans}->{ u_irc $chan } =~ /h/;
  return 0;
}

sub _state_has_chan_voice {
  my $self = shift;
  my $nick = shift || return;
  my $chan = shift || return;
  return unless $self->_state_is_chan_member( $nick, $chan );
  my $record = $self->{state}->{users}->{ u_irc $nick };
  return 1 if $record->{chans}->{ u_irc $chan } =~ /v/;
  return 0;
}

sub _state_o_line {
  my $self = shift;
  my $nick = shift || return;
  my ($user,$pass) = @_;
  return unless $self->_state_nick_exists( $nick );
  return unless $user and $pass;
  my $ops = $self->{config}->{ops};
  return unless $ops->{ $user };
  return -1 unless $ops->{ $user }->{password} eq $pass;
  my $client_ip = $self->_state_user_ip( $nick );
  return unless $client_ip;
  return 1 if ( !$ops->{ $user }->{ipmask} and ( $client_ip and $client_ip =~ /^127\./ ) );
  return 0 unless $ops->{ $user }->{ipmask};
  if ( ref $ops->{ $user }->{ipmask} eq 'ARRAY' ) {
    foreach my $block ( grep { $_->isa('Net::Netmask') } @{ $ops->{ $user }->{ipmask} } ) {
    	return 1 if $block->match( $client_ip );
    }
  } 
  if ( ref $ops->{ $user }->{ipmask} eq 'SCALAR' ) {
    my $ipmask = $ops->{ $user }->{ipmask};
    $ipmask = quotemeta( $ipmask );
    $ipmask =~ s/\\\*/[\x01-\xFF]{0,}/g;
    $ipmask =~ s/\\\?/[\x01-\xFF]{1,1}/g;
    return 1 if $client_ip =~ /^$ipmask$/;
  }
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
  return $self->{config}->{ uc $value };
}

sub configure {
  my $self = shift;
  my $options;
  
  if ( ref $_[0] eq 'HASH' ) {
    $options = $_[0];
  } else {
    $options = { @_ };
  }

  $self->{config}->{ uc $_ } = $options->{ $_ } for keys %{ $options };

  $self->{config}->{CREATED} = time();
  $self->{config}->{CASEMAPPING} = 'rfc1459';
  $self->{config}->{SERVERNAME} = 'poco.server.irc' unless $self->{config}->{SERVERNAME};
  $self->{config}->{SERVERDESC} = 'Poco? POCO? POCO!' unless $self->{config}->{SERVERDESC};
  $self->{config}->{VERSION} = ref ( $self ) . '-' . $VERSION unless ( $self->{config}->{VERSION} );
  $self->{config}->{NETWORK} = 'poconet' unless $self->{config}->{NETWORK};
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
  $self->{config}->{MAXTARGETS} = 4 unless ( defined ( $self->{config}->{MAXTARGETS} ) and $self->{config}->{MAXTARGETS} > 4 );
  $self->{config}->{MAXBANS} = 30 unless ( defined ( $self->{config}->{MAXBANS} ) and $self->{config}->{MAXBANS} > 30 );
  $self->{config}->{MAXBANLENGTH} = 1024 unless ( defined ( $self->{config}->{MAXBANLENGTH} ) and $self->{config}->{MAXBANLENGTH} < 1024 );
  $self->{config}->{BANLEN} = $self->{config}->{USERLEN} + $self->{config}->{NICKLEN} + $self->{config}->{HOSTLEN} + 3;
  $self->{config}->{USERHOST_REPLYLEN} = $self->{config}->{USERLEN} + $self->{config}->{NICKLEN} + $self->{config}->{HOSTLEN} + 5;
  # TODO: Find some way to disable requirement for PoCo-Client-DNS and PoCo-Client-Ident
  $self->{config}->{AUTH} = 1 unless ( defined ( $self->{config}->{AUTH} ) and $self->{config}->{AUTH} eq '0' );
  $self->{config}->{ANTIFLOOD} = 1 unless ( defined ( $self->{config}->{ANTIFLOOD} ) and $self->{config}->{ANTIFLOOD} eq '0' );
  if ( ( not defined ( $self->{config}->{ADMIN} ) ) or ( ref $self->{config}->{ADMIN} ne 'ARRAY' ) or ( scalar ( @{ $self->{config}->{ADMIN} } ) != 3 ) ) {
    $self->{config}->{ADMIN}->[0] = 'Somewhere, Somewhere, Somewhere';
    $self->{config}->{ADMIN}->[1] = 'Some Institution';
    $self->{config}->{ADMIN}->[2] = 'someone@somewhere';
  }
  if ( ( not defined ( $self->{config}->{INFO} ) ) or ( ref $self->{config}->{INFO} eq 'ARRAY' ) or ( scalar ( @{ $self->{config}->{INFO} } ) >= 1 ) ) {
    $self->{config}->{INFO}->[0] = '# POE::Component::Server::IRC';
    $self->{config}->{INFO}->[1] = '#';
    $self->{config}->{INFO}->[2] = '# Author: Chris "BinGOs" Williams';
    $self->{config}->{INFO}->[3] = '#';
    $self->{config}->{INFO}->[4] = '# Filter-IRCD Written by Hachi';
    $self->{config}->{INFO}->[5] = '#';
    $self->{config}->{INFO}->[6] = '# This module may be used, modified, and distributed under the same';
    $self->{config}->{INFO}->[7] = '# terms as Perl itself. Please see the license that came with your Perl';
    $self->{config}->{INFO}->[8] = '# distribution for details.';
    $self->{config}->{INFO}->[9] = '#';
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
			412 => [ 0, "No text to send" ],
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
    map { ( uc $_, $self->{config}->{$_} ) } qw(MAXCHANNELS MAXTARGETS MAXBANS NICKLEN TOPICLEN KICKLEN CASEMAPPING NETWORK),
  };

  $self->{config}->{capab} = [ qw(QS EX IE HOPS KLN GLN EOB) ];

  return 1;
}

sub _send_output_to_client {
  my $self = shift;
  my $wheel_id = shift || return 0;
  my $nick = $self->client_nickname( $wheel_id );
  $nick = shift if $self->_connection_is_peer( $wheel_id );
  my $err = shift || return 0;
  return unless $self->_connection_exists( $wheel_id );
  SWITCH: {
    if ( ref $err eq 'HASH' ) {
	$self->{ircd}->send_output( $err, $wheel_id );
	last SWITCH;
    }
    if ( defined ( $self->{Error_Codes}->{ $err } ) ) {
	my $input = { command => $err, prefix => $self->server_name(), params => [ $nick ] };
	if ( $self->{Error_Codes}->{ $err }->[0] > 0 ) {
	   for ( my $i = 1; $i <= $self->{Error_Codes}->{ $err }->[0]; $i++ ) {
		push @{ $input->{params} }, shift;
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
  my $conn_id = shift;
  return unless $self->_state_chan_exists( $channel );
  # Get conn_ids for each of our peers.
  my $ref = [ ]; my $peers = { };
  $peers->{ $_ }++ for $self->_state_connected_peers();
  delete $peers->{ $conn_id } if $conn_id;
  push @{ $ref }, $self->_state_user_route( $_ ) for grep { $self->_state_is_local_user( $_ ) } $self->_state_chan_list( $channel );
  if ( scalar( keys %{ $peers} ) and $output->{command} ne 'JOIN' ) {
    my $full = $output->{prefix};
    my $nick = ( split /!/, $full )[0];
    my $output2 = { %{ $output } }; 
    $output2->{prefix} = $nick;
    $self->{ircd}->send_output( $output2, keys %{ $peers } );
  }
  $self->{ircd}->send_output( $output, @{ $ref } );
  return 1;
}

sub add_operator {
  my $self = shift;
  my $ref;
  if ( ref $_[0] eq 'HASH' ) {
    $ref = $_[0];
  } else {
    $ref = { @_ };
  }
  $ref->{ lc $_ } = delete $ref->{ $_ } for keys %{ $ref };

  unless ( $ref->{username} and $ref->{password} ) {
    warn "Not enough parameters\n";
    return;
  }

  my $record = $self->{state}->{peers}->{ uc $self->server_name() };
  my $user = delete $ref->{username};
  $self->{config}->{ops}->{ $user } = $ref;
  return 1;
}

sub add_peer {
  my $self = shift;
  my $parms;
  if ( ref $_[0] eq 'HASH' ) {
     $parms = $_[0];
  } else {
     $parms = { @_ };
  }
  $parms->{ lc $_ } = delete $parms->{ $_ } for keys %{ $parms };
  unless ( $parms->{name} and $parms->{pass} and $parms->{rpass} ) {
     warn "Not enough parameters specified\n";
     return;
  }
  $parms->{type} = 'c' unless $parms->{type} and lc( $parms->{type} ) eq 'r';
  $parms->{type} = lc $parms->{type};
  $parms->{rport} = 6667 if $parms->{type} eq 'r' and !$parms->{rport};
  foreach ( qw(sockport sockaddr) ) {
	$parms->{ $_ } = '*' unless $parms->{ $_ };
  }
  my $name = $parms->{name};
  $self->{config}->{peers}->{ uc $name } = $parms;
  return 1;
}

sub terminate_conn_error {
  my $self = shift;
  my $conn_id = shift || return;
  return unless $self->_connection_exists( $conn_id );
  my $msg = shift;
  $self->{ircd}->disconnect( $conn_id, $msg );
  $self->{ircd}->send_output( { command => 'ERROR', params => [ 'Closing Link: ' . $self->client_ip( $conn_id ) . ' (' . $msg . ')' ] }, $conn_id );
  return 1;
}

#####################
### API #############
#####################

sub daemon_server_kill {
  my $self = shift;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
     if ( !$count ) {
	last SWITCH;
     }
     if ( $self->_state_peer_exists( $args->[0] ) ) {
	last SWITCH;
     }
     if ( !$self->_state_nick_exists( $args->[0] ) ) {
	last SWITCH;
     }
     my $target = ( split /!/, $self->_state_user_full( $args->[0] ) )[0];
     my $comment = $args->[1] || '<No reason given>';
     my $conn_id = ( $args->[2] and $self->_connection_exists( $args->[2] ) ? $args->[2] : '' );
     if ( $self->_state_is_local_user( $target ) ) {
	my $route_id = $self->_state_user_route( $target );
	$self->{ircd}->send_output( { prefix => $server, command => 'KILL', params => [ $target, $comment ] }, $route_id );
	$self->{state}->{conns}->{ $route_id }->{killed} = 1;
	$self->terminate_conn_error( $route_id, "Killed ($server ($comment))" );
     } else {
	$self->{state}->{users}->{ u_irc $target }->{killed} = 1;
        $self->{ircd}->send_output( { prefix => $server, command => 'KILL', params => [ $target, "$server ($comment)" ] }, grep { !$conn_id || $_ ne $conn_id } $self->_state_connected_peers() );
	$self->{ircd}->send_output( @{ $self->_daemon_peer_quit( $target, "Killed ($server ($comment))" ) } );
     }
  }
  return @{ $ref } if wantarray();
  return $ref;
}

sub daemon_server_mode {
  my $self = shift;
  my $chan = shift;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    if ( !$self->_state_chan_exists( $chan ) ) {
	last SWITCH;
    }
    my $record = $self->{state}->{chans}->{ u_irc $chan };
    $chan = $record->{name};
    if ( $chan =~ /^\x2B/ ) {
	last SWITCH;
    }
    my $full = $server;
    my $parsed_mode = parse_mode_line( @{ $args } );
    while( my $mode = shift ( @{ $parsed_mode->{modes} } ) ) {
      my $arg;
      $arg = shift ( @{ $parsed_mode->{args} } ) if ( $mode =~ /^(\+[ohvklbIe]|-[ohvbIe])/ );
      if ( my ($flag,$char) = $mode =~ /^(\+|-)([ohv])/ ) {
	if ( $flag eq '+' and $record->{users}->{ u_irc $arg } !~ /$char/ ) {
	  # Update user and chan record
	  $arg = u_irc $arg;
	  next if ( $mode eq '+h' and $record->{users}->{ $arg } =~ /o/ );
	  if ( $char eq 'h' and $record->{users}->{ $arg } =~ /v/ ) {
	     $record->{users}->{ $arg } =~ s/v//g;
	  }
	  if ( $char eq 'o' and $record->{users}->{ $arg } =~ /h/ ) {
	     $record->{users}->{ $arg } =~ s/h//g;
	  }
	  $record->{users}->{ $arg }  = join('', sort split //, $record->{users}->{ $arg } . $char );
	  $self->{state}->{users}->{ $arg }->{chans}->{ u_irc $chan } = $record->{users}->{ $arg };
        }
	if ( $flag eq '-' and $record->{users}->{ u_irc $arg } =~ /$char/ ) {
	  # Update user and chan record
	  $arg = u_irc $arg;
	  $record->{users}->{ $arg } =~ s/$char//g;
	  $self->{state}->{users}->{ $arg }->{chans}->{ u_irc $chan } = $record->{users}->{ $arg };
        }
	next;
      }
      if ( $mode eq '+l' and $arg =~ /^\d+$/ and $arg > 0 ) {
	$record->{mode} = join('', sort split //, $record->{mode} . 'l' ) unless $record->{mode} =~ /l/;
	$record->{climit} = $arg;
	next;
      }
      if ( $mode eq '-l' and $record->{mode} =~ /l/ ) {
	$record->{mode} =~ s/l//g;
	delete $record->{climit};
	next;
      }
      if ( $mode eq '+k' and $arg ) {
	$record->{mode} = join('', sort split //, $record->{mode} . 'k' ) unless $record->{mode} =~ /k/;
	$record->{ckey} = $arg;
	next;
      }
      if ( $mode eq '-k' and $record->{mode} =~ /k/ ) {
	$record->{mode} =~ s/k//g;
	delete $record->{ckey};
	next;
      }
      # Bans
      if ( my ($flag) = $mode =~ /(\+|-)b/ ) {
	my $mask = parse_ban_mask( $arg );
	my $umask = u_irc $mask;
	if ( $flag eq '+' and !$record->{bans}->{ $umask } ) {
	  $record->{bans}->{ $umask } = [ $mask, ( $full || $server ), time() ];
	}
	if ( $flag eq '-' and $record->{bans}->{ $umask } ) {
	  delete $record->{bans}->{ $umask };
	}
	next;
      }
      # Invex
      if ( my ($flag) = $mode =~ /(\+|-)I/ ) {
	my $mask = parse_ban_mask( $arg );
	my $umask = u_irc $mask;
	if ( $flag eq '+' and !$record->{invex}->{ $umask } ) {
	   $record->{invex}->{ $umask } = [ $mask, ( $full || $server ), time() ];
	}
	if ( $flag eq '-' and $record->{invex}->{ $umask } ) {
	  delete $record->{invex}->{ $umask };
	}
	next;
      }
      # Exceptions
      if ( my ($flag) = $mode =~ /(\+|-)e/ ) {
	my $mask = parse_ban_mask( $arg );
	my $umask = u_irc $mask;
	if ( $flag eq '+' and !$record->{excepts}->{ $umask } ) {
	  $record->{excepts}->{ $umask } = [ $mask, ( $full || $server ), time() ];
	}
	if ( $flag eq '-' and $record->{excepts}->{ $umask } ) {
	  delete $record->{excepts}->{ $umask };
	}
	next;
      }
      # The rest should be argumentless.
      my ($flag,$char) = split //, $mode;
      if ( $flag eq '+' and $record->{mode} !~ /$char/ ) {
	$record->{mode} = join('', sort split //, $record->{mode} . $char );
	next;
      }
      if ( $flag eq '-' and $record->{mode} =~ /$char/ ) {
	$record->{mode} =~ s/$char//g;
	next;
      }
    } # while
    unshift @{ $args }, $record->{name};
    $self->{ircd}->send_output( { prefix => $server, command => 'MODE', params => $args, colonify => 0 }, $self->_state_connected_peers() );
    $self->{ircd}->send_output( { prefix => ( $full || $server ), command => 'MODE', params => $args, colonify => 0 }, map { $self->_state_user_route($_) } grep { $self->_state_is_local_user($_) } keys %{ $record->{users} } ); 
  } # SWITCH
  return @{ $ref } if wantarray();
  return $ref;
}

sub daemon_server_kick {
  my $self = shift;
  my $server = $self->server_name();
  my $ref = [ ]; my $args = [ @_ ]; my $count = scalar @{ $args };
  SWITCH: {
    if ( !$count or $count < 2 ) {
	last SWITCH;
    }
    my $chan = ( split /,/, $args->[0] )[0];
    my $who = ( split /,/, $args->[1] )[0];
    if ( !$self->_state_chan_exists( $chan ) ) {
	last SWITCH;
    }
    $chan = $self->_state_chan_name( $chan );
    if ( !$self->_state_nick_exists( $who ) ) {
	last SWITCH;
    }
    $who = ( split /!/, $self->_state_user_full( $who ) )[0];
    if ( !$self->_state_is_chan_member( $who, $chan ) ) {
	last SWITCH;
    }
    my $comment = $args->[2] || $who;
    $self->_send_output_to_channel( $chan, { prefix => $server, command => 'KICK', params => [ $chan, $who, $comment ] } );
    $who = u_irc $who; $chan = u_irc $chan;
    delete $self->{state}->{chans}->{ $chan }->{users}->{ $who };
    delete $self->{state}->{users}->{ $who }->{chans}->{ $chan };
    unless ( scalar keys %{ $self->{state}->{chans}->{ $chan  }->{users} } ) {
	delete $self->{state}->{chans}->{ $chan  };
    }
  }
  return @{ $ref } if wantarray();
  return $ref;
}

1;
