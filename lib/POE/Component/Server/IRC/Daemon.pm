# Author: Chris "BinGOs" Williams
#
# This module may be used, modified, and distributed under the same
# terms as Perl itself. Please see the license that came with your Perl
# distribution for details.
#
package POE::Component::Server::IRC::Daemon;

use POE::Component::Server::IRC::Plugin qw ( :ALL );
use Carp;
use vars qw($VERSION);

$VERSION = '0.31';

sub new {
  my ($package) = shift;
  croak "$package requires an even numbers of parameters\n" if @_ & 1;
  my %parms = @_;

  foreach my $key ( keys %parms ) {
	next if ( $key eq 'Config' );
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
  return $_[0]->{Config}->{ServerName};
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
     $self->{Config}->{ $option }  = $options->{ $option };
  }

  $self->{Config}->{ServerName} = 'poco.server.irc' unless ( $self->{Config}->{ServerName} );
  $self->{Config}->{ServerDesc} = 'Poco? POCO? POCO!' unless ( $self->{Config}->{ServerDesc} );
  $self->{Config}->{Version} = ref ( $self ) . '-' . $VERSION unless ( $self->{Config}->{Version} );
  $self->{Config}->{Network} = 'poconet' unless ( $self->{Config}->{Network} );
  $self->{Config}->{HOSTLEN} = 63 unless ( defined ( $self->{Config}->{HOSTLEN} ) and $self->{Config}->{HOSTLEN} > 63 );
  $self->{Config}->{NICKLEN} = 9 unless ( defined ( $self->{Config}->{NICKLEN} ) and $self->{Config}->{NICKLEN} > 9 );
  $self->{Config}->{USERLEN} = 10 unless ( defined ( $self->{Config}->{USERLEN} ) and $self->{Config}->{USERLEN} > 10 );
  $self->{Config}->{REALLEN} = 50 unless ( defined ( $self->{Config}->{REALLEN} ) and $self->{Config}->{REALLEN} > 50 );
  $self->{Config}->{TOPICLEN} = 80 unless ( defined ( $self->{Config}->{TOPICLEN} ) and $self->{Config}->{TOPICLEN} > 80 );
  $self->{Config}->{CHANNELLEN} = 50 unless ( defined ( $self->{Config}->{CHANNELLEN} ) and $self->{Config}->{CHANNELLEN} > 50 );
  $self->{Config}->{PASSWDLEN} = 20 unless ( defined ( $self->{Config}->{PASSWDLEN} ) and $self->{Config}->{PASSWDLEN} > 20 );
  $self->{Config}->{KEYLEN} = 23 unless ( defined ( $self->{Config}->{KEYLEN} ) and $self->{Config}->{KEYLEN} > 23 );
  $self->{Config}->{MAXRECIPIENTS} = 20 unless ( defined ( $self->{Config}->{MAXRECIPIENTS} ) and $self->{Config}->{MAXRECIPIENTS} > 20 );
  $self->{Config}->{MAXBANS} = 30 unless ( defined ( $self->{Config}->{MAXBANS} ) and $self->{Config}->{MAXBANS} > 30 );
  $self->{Config}->{MAXBANLENGTH} = 1024 unless ( defined ( $self->{Config}->{MAXBANLENGTH} ) and $self->{Config}->{MAXBANLENGTH} < 1024 );
  $self->{Config}->{BANLEN} = $self->{Config}->{USERLEN} + $self->{Config}->{NICKLEN} + $self->{Config}->{HOSTLEN} + 3;
  $self->{Config}->{USERHOST_REPLYLEN} = $self->{Config}->{USERLEN} + $self->{Config}->{NICKLEN} + $self->{Config}->{HOSTLEN} + 5;
  # TODO: Find some way to disable requirement for PoCo-Client-DNS and PoCo-Client-Ident
  $self->{Config}->{Auth} = 1 unless ( defined ( $self->{Config}->{Auth} ) and $self->{Config}->{Auth} eq '0' );
  $self->{Config}->{AntiFlood} = 1 unless ( defined ( $self->{Config}->{AntiFlood} ) and $self->{Config}->{AntiFlood} eq '0' );
  if ( ( not defined ( $self->{Config}->{Admin} ) ) or ( ref $self->{Config}->{Admin} ne 'ARRAY' ) or ( scalar ( @{ $self->{Config}->{Admin} } ) != 3 ) ) {
    $self->{Config}->{Admin}->[0] = 'Somewhere, Somewhere, Somewhere';
    $self->{Config}->{Admin}->[1] = 'Some Institution';
    $self->{Config}->{Admin}->[2] = 'someone@somewhere';
  }
  if ( ( not defined ( $self->{Config}->{Info} ) ) or ( ref $self->{Config}->{Info} eq 'ARRAY' ) or ( scalar ( @{ $self->{Config}->{Info} } ) >= 1 ) ) {
    $self->{Config}->{Info}->[0] = '# POE::Component::Server::IRC';
    $self->{Config}->{Info}->[1] = '#';
    $self->{Config}->{Info}->[2] = '# Author: Chris "BinGOs" Williams';
    $self->{Config}->{Info}->[3] = '#';
    $self->{Config}->{Info}->[4] = '# Filter-IRCD Written by Hachi';
    $self->{Config}->{Info}->[5] = '#';
    $self->{Config}->{Info}->[6] = '# This module may be used, modified, and distributed under the same';
    $self->{Config}->{Info}->[7] = '# terms as Perl itself. Please see the license that came with your Perl';
    $self->{Config}->{Info}->[8] = '# distribution for details.';
    $self->{Config}->{Info}->[9] = '#';
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
