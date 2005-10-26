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
  	delete ( $self->{state}->{connections}->{ $conn_id } );
  }
  $self->{state}->{connections}->{ $conn_id }->{registered} = 0;
  $self->{state}->{connections}->{ $conn_id }->{type} = 'u';
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
  $self->_connection_register();
  return PCSI_EAT_NONE;
}

sub _default {
  my ($self,$ircd,$event) = splice @_, 0, 3;
  return PCSI_EAT_NONE unless ( $event =~ /^IRCD_cmd_/ );
  my ($conn_id,$input) = map { ${ $_ } } @_;

  return PCSI_EAT_NONE unless ( $self->_connection_exists( $conn_id ) );

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
		delete ( $input->{prefix} );
		$self->_cmd_from_client( $conn_id, $input );
		last SWITCH;
	}
  };

  return PCSI_EAT_NONE;
}

sub _auth_done {
  my ($self) = shift;
  my ($conn_id) = shift || return undef;

  unless ( $self->_connection_exists( $conn_id ) ) {
	return undef;
  }
  return $self->{state}->{connections}->{ $conn_id }->{auth};
}

sub _connection_exists {
  my ($self) = shift;
  my ($conn_id) = shift || return 0;

  unless ( defined ( $self->{state}->{connections}->{ $conn_id } ) ) {
	return 0;
  }
  return 1;
}

sub _connection_register {
  my ($self) = shift;
  my ($conn_id) = shift || return undef;

  unless ( $self->_connection_exists( $conn_id ) ) {
	return undef;
  }

  if ( my $auth = $self->_auth_done( $conn_id ) ) {
	if ( my $reg = $self->_reg_done( $conn_id ) ) {
	}
  }
  #$self->{state}->{connections}->{ $conn_id }->{registered};
}

sub _connection_registered {
  my ($self) = shift;
  my ($conn_id) = shift || return undef;

  unless ( $self->_connection_exists( $conn_id ) ) {
	return undef;
  }
  return $self->{state}->{connections}->{ $conn_id }->{registered};
}

sub _connection_is_peer {
  my ($self) = shift;
  my ($conn_id) = shift || return undef;

  unless ( $self->_connection_exists( $conn_id ) ) {
	return undef;
  }
}

sub _connection_is_client {
  my ($self) = shift;
  my ($conn_id) = shift || return undef;

  unless ( $self->_connection_exists( $conn_id ) ) {
	return undef;
  }
}

sub _cmd_from_unknown {
  my ($self,$conn_id,$input) = splice @_, 0, 3;

  my $cmd = $input->{command};
  my $params = $input->{params};
  SWITCH: {
	last SWITCH;
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
  my ($self,$conn_id,$input) = splice @_, 0, 3;

  my $cmd = $input->{command};
  my $params = $input->{params};
  SWITCH: {
	last SWITCH;
  }
  return 1;
}

#################
# State methods #
#################

sub _state_create {
  my ($self) = shift;

  $self->_state_delete();
  # Connection specific tables
  $self->{state}->{connections} = { };
  # IRC State specific
  $self->{state}->{users} = { };
  $self->{state}->{peers} = { };
  $self->{state}->{chans} = { };
  return 1;
}

sub _state_delete {
  my ($self) = shift;

  delete $self->{state};
  return 1;
}

sub server_name {
  return $_[0]->{config}->{ServerName};
}

sub client_nickname {
  my ($self) = shift;
  my ($wheel_id) = $_[0] || return undef;

  if ( $self->_connection_registered( $wheel_id ) ) {
  }
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

  $self->{config}->{ServerName} = 'poco.server.irc' unless ( $self->{config}->{ServerName} );
  $self->{config}->{ServerDesc} = 'Poco? POCO? POCO!' unless ( $self->{config}->{ServerDesc} );
  $self->{config}->{Version} = ref ( $self ) . '-' . $VERSION unless ( $self->{config}->{Version} );
  $self->{config}->{Network} = 'poconet' unless ( $self->{config}->{Network} );
  $self->{config}->{HOSTLEN} = 63 unless ( defined ( $self->{config}->{HOSTLEN} ) and $self->{config}->{HOSTLEN} > 63 );
  $self->{config}->{NICKLEN} = 9 unless ( defined ( $self->{config}->{NICKLEN} ) and $self->{config}->{NICKLEN} > 9 );
  $self->{config}->{USERLEN} = 10 unless ( defined ( $self->{config}->{USERLEN} ) and $self->{config}->{USERLEN} > 10 );
  $self->{config}->{REALLEN} = 50 unless ( defined ( $self->{config}->{REALLEN} ) and $self->{config}->{REALLEN} > 50 );
  $self->{config}->{TOPICLEN} = 80 unless ( defined ( $self->{config}->{TOPICLEN} ) and $self->{config}->{TOPICLEN} > 80 );
  $self->{config}->{CHANNELLEN} = 50 unless ( defined ( $self->{config}->{CHANNELLEN} ) and $self->{config}->{CHANNELLEN} > 50 );
  $self->{config}->{PASSWDLEN} = 20 unless ( defined ( $self->{config}->{PASSWDLEN} ) and $self->{config}->{PASSWDLEN} > 20 );
  $self->{config}->{KEYLEN} = 23 unless ( defined ( $self->{config}->{KEYLEN} ) and $self->{config}->{KEYLEN} > 23 );
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
			422 => [ 1, "MOTD File is missing" ],
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

  return 1;
}

sub _send_output_to_client {
  my ($self) = shift;
  my ($wheel_id) = shift || return 0;
  my ($err) = shift || return 0;

  SWITCH: {
    if ( not $self->_connection_exists( $wheel_id ) ) {
	last SWITCH;
    }
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

# Miscellaneous Subroutines

sub parse_mode_line {
  my ($hashref) = { };

  my ($count) = 0;
  foreach my $arg ( @_ ) {
	if ( $arg =~ /^(\+|-)/ or $count == 0 ) {
	   my ($action) = '+';
	   foreach my $char ( split (//,$arg) ) {
		if ( $char eq '+' or $char eq '-' ) {
		   $action = $char;
		} else {
		   push ( @{ $hashref->{modes} }, $action . $char );
		}
	   }
	 } else {
		push ( @{ $hashref->{args} }, $arg );
	 }
	 $count++;
  }
  return $hashref;
}

sub unparse_mode_line {
  my ($line) = $_[0] || return undef;

  my ($action); my ($return);
  foreach my $mode ( split(//,$line) ) {
	if ( $mode =~ /^(\+|-)$/ and ( ( not defined ( $action ) ) or $mode ne $action ) ) {
	  $return .= $mode;
	  $action = $mode;
	  next;
	} 
	$return .= $mode if ( $mode ne '+' and $mode ne '-' );
  }
  return $return;
}

sub validate_nickname {
  my ($nickname) = shift || return 0;

  if ( $nickname =~ /^[A-Za-z_0-9`\-^\|\\\{}\[\]]+$/ ) {
	return 1;
  }
  return 0;
}

sub validate_channelname {
  my ($channel) = shift || return 0;

  if ( $channel =~ /^(\x23|\x26|\x2B)/ and $channel !~ /(\x20|\x07|\x00|\x0D|\x0A|\x2C)+/ ) {
	return 1;
  }
  return 0;
}

sub u_irc {
  my ($value) = shift || return undef;

  $value =~ tr/a-z{}|^/A-Z[]\\~/;
  return $value;
}

sub timestring {
      my ($timeval) = shift || return 0;
      my $uptime = time() - $timeval;
  
      my $days = int $uptime / 86400;
      my $remain = $uptime % 86400;
      my $hours = int $remain / 3600;
      $remain %= 3600;
      my $mins = int $remain / 60;
      $remain %= 60;
      return sprintf("Server Up %d days, %2.2d:%2.2d:%2.2d",$days,$hours,$mins,$remain);
}

1;
