# Author: Chris "BinGOs" Williams
#
# This module may be used, modified, and distributed under the same
# terms as Perl itself. Please see the license that came with your Perl
# distribution for details.
#
package POE::Component::Server::IRC;

use Date::Format;
use Socket;
use Carp;
use POE qw(Wheel::SocketFactory Wheel::ReadWrite Filter::Line Filter::IRCD Filter::Stackable);
use POE::Component::Client::DNS;
use POE::Component::Client::Ident;

use vars qw($VERSION);

$VERSION = '0.2';

use constant PCSI_REFCOUNT_TAG => "P::C::S::I registered";

our (@valid_commands) = qw(PASS NICK USER SERVER OPER QUIT SQUIT JOIN PART MODE TOPIC NAMES LIST INVITE KICK VERSION STATS LINKS TIME CONNECT TRACE ADMIN INFO WHO WHOIS WHOWAS KILL PING PONG ERROR AWAY REHASH RESTART SUMMON USERS WALLOPS USERHOST ISON MOTD LUSERS DIE);

our (@client_commands) = qw(PASS NICK USER QUIT JOIN NAMES PART MODE TOPIC KICK OPER SUMMON USERS WHO AWAY MOTD LUSERS VERSION INVITE USERHOST PING PONG WHOIS LIST ISON ADMIN INFO WHOWAS TIME WALLOPS STATS KILL);

our (@server_commands) = qw(WALLOPS);

our (@connection_commands) = qw(PASS NICK USER SERVER QUIT);

our (@reserved_channels) = qw(&CONNECTIONS &STATE);

our (@cmd_server) = map { 'cmd_server_' . $_ } qw (kick kill mode);
our (%cmd_server) = map { ( 'server_' . $_ => 'cmd_input' ) } qw (kick kill mode);

sub spawn {
  my ($package) = shift;
  croak "$package requires an even number of parameters" if @_ % 2;
  my (%args) = @_;

  unless ( $args{'Alias'} ) {
	croak "You must specify an Alias to $package->spawn";
  }

  my ($self) = $package->new(@_);

  my (@object_client_handlers) = map { 'ircd_client_' . lc } @client_commands;
  my (@object_server_handlers) = map { 'ircd_server_' . lc } @server_commands;
  my (@object_connection_handlers) = map { 'ircd_connection_' . lc } @connection_commands;

  POE::Session->create(
	object_states => [
		$self => { _start              => 'ircd_start',
			   _stop               => 'ircd_stop',
			   ircd_client_privmsg => 'ircd_client_message',
			   ircd_client_rehash  => 'ircd_client_o_cmds',
			   ircd_client_restart => 'ircd_client_o_cmds',
			   ircd_client_die     => 'ircd_client_o_cmds',
			   ircd_client_notice  => 'ircd_client_message',
			   shutdown            => 'ircd_shutdown' },
		$self => [ qw(got_hostname_response got_ip_response poll_connections client_registered auth_client register unregister configure add_operator add_listener accept_new_connection accept_failed connection_input connection_error connection_flushed set_motd ident_client_reply ident_client_error auth_done add_i_line sig_hup_rehash client_dispatcher client_ping cmd_input) ],
		$self => \@object_client_handlers,
		$self => \@object_server_handlers,
		$self => \@object_connection_handlers,
		$self => \%cmd_server,
		$self => \@cmd_server,
	],
	options => { trace => $self->{Debug} },
  );

  return $self;
}

sub new {
  my ($package) = shift;
  my (%args) = @_;

  my ($self) = { };
  $self->{Alias} = delete ( $args{'Alias'} );
  $self->{Debug} = 0;
  $self->{Debug} = $args{'Debug'} if ( defined ( $args{'Debug'} ) and $args{'Debug'} eq '1' );
  $self->{Config} = \%args;

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

  return bless $self, $package;
}

sub ircd_start {
  my ($kernel,$self) = @_[KERNEL,OBJECT];

  $kernel->sig( HUP => 'sig_hup_rehash' );
  $kernel->alias_set ( $self->{Alias} );

  $self->{StartTime} = time();

  $self->{filter} = POE::Filter::Stackable->new();

  $self->{ircd_filter} = POE::Filter::IRCD->new( DEBUG => $self->{Debug} );

  $self->{filter}->push(
    POE::Filter::Line->new( InputRegexp => '\015?\012', OutputLiteral => "\015\012" ),
    $self->{ircd_filter},
  );

  $self->{Ident_Client} = 'poco_' . $self->{Alias} . '_ident';
  $self->{Resolver} = 'poco_' . $self->{Alias} . '_resolver';
  POE::Component::Client::Ident->spawn ( $self->{Ident_Client} );
  $self->{ $self->{Resolver} } = POE::Component::Client::DNS->spawn( Alias => $self->{Resolver}, Timeout => 10 );

  $kernel->call ( $self->{Alias} => 'configure' );
  $kernel->delay ( 'poll_connections' => $self->lowest_ping_frequency() );
}

sub ircd_stop {
  # Probably need some cleanup code here.
  print "IRCD stopped\n";
}

sub ircd_shutdown {
  my ($kernel,$self) = @_[KERNEL,OBJECT];

  $kernel->call ( 'Ident-Client' => 'shutdown' ); 

  delete ( $self->{Clients} );

  $kernel->alias_remove ( $self->{Alias} );

  $kernel->delay ( 'poll_connections' => undef );
}

sub register {
  my ($kernel,$self,$sender,$session) = @_[KERNEL,OBJECT,SENDER,SESSION];

  $self->{sessions}->{$sender}->{'ref'} = $sender;
  unless ($self->{sessions}->{$sender}->{refcnt}++ or $session == $sender) {
      $kernel->refcount_increment($sender->ID(), PCSI_REFCOUNT_TAG);
  }
}

sub unregister {
  my ($kernel,$self,$sender,$session) = @_[KERNEL,OBJECT,SENDER,SESSION];

  if (--$self->{sessions}->{$sender}->{refcnt} <= 0) {
      delete $self->{sessions}->{$sender};
      unless ($session == $sender) {
        $kernel->refcount_decrement($sender->ID(), PCSI_REFCOUNT_TAG);
      }
  }
}

sub poll_connections {
  my ($kernel,$self) = @_[KERNEL,OBJECT];

  # Check each unknown connection
  foreach my $connection ( keys %{ $self->{Connections} } ) {
	my ($difference) = time() - $self->{Connections}->{ $connection }->{SeenTraffic};
	if ( $difference > 65 ) {
	   $self->{Connections}->{ $connection }->{INVALID_PASSWORD} = 1;
	   $self->{Connections}->{ $connection }->{Wheel}->put( { command => 'ERROR', params => [ 'Closing Link: ' . $self->client_nickname($connection) . '[' . ( $self->{Config}->{Auth} ? ( $self->{Connections}->{ $connection }->{Auth}->{Ident} ? $self->{Connections}->{ $connection }->{Auth}->{Ident} : 'unknown' ) : 'unknown' ) . '@' . ( $self->{Config}->{Auth} ? ( $self->{Connections}->{ $connection }->{Auth}->{HostName} ? $self->{Connections}->{ $connection }->{Auth}->{HostName} : $self->{Connections}->{ $connection }->{PeerAddr} ) : $self->{Connections}->{ $connection }->{PeerAddr} ) . '] (Ping timeout)' ] } );
	}
  }
  # Check each client
  foreach my $client ( keys %{ $self->{Clients} } ) {
    if ( defined ( $self->{Clients}->{ $client }->{SeenTraffic} ) ) {
	my ($difference) = time() - $self->{Clients}->{ $client }->{SeenTraffic};
	if ( $difference > ( 2 * ( defined ( $self->{Clients}->{ $client }->{PingFreq} ) ? $self->{Clients}->{ $client }->{PingFreq} : $self->lowest_ping_frequency() ) ) ) {
	   $kernel->post ( $self->{Alias} => 'ircd_client_quit' => { command => 'QUIT', params => [ 'Ping timeout ' . $difference . ' seconds' ] } => $client );
	} else {
	   $self->send_output_to_client( $client, { command => 'PING', params => [ $self->{Config}->{ServerName} ] } );
	}
    } else {
	$self->send_output_to_client( $client, { command => 'PING', params => [ $self->{Config}->{ServerName} ] } );
    }
  }
  # Check each server
  #foreach my $server ( keys %{ $self->{Servers} } ) {
  #}
  $kernel->delay ( 'poll_connections' => $self->lowest_ping_frequency() );
}

sub configure {
  my ($kernel,$self) = @_[KERNEL,OBJECT];
  my ($options);
  
  if ( ref $_[ARG0] eq 'HASH' ) {
    $options = $_[ARG0];
  } else {
    $options = { @_[ARG0 .. $#_] };
  }

  foreach my $option ( keys %{ $options } ) {
     $self->{Config}->{ $option }  = $options->{ $option };
  }

  $self->{Config}->{ServerName} = 'poco.server.irc' unless ( defined ( $self->{Config}->{ServerName} ) and $self->{Config}->{ServerName} );
  $self->{Config}->{ServerDesc} = 'Poco? POCO? POCO!' unless ( defined ( $self->{Config}->{ServerDesc} ) and $self->{Config}->{ServerDesc} );
  $self->{Config}->{Version} = ref ( $self ) . '-' . $VERSION unless ( defined ( $self->{Config}->{Version} ) and $self->{Config}->{Version} );
  $self->{Config}->{Network} = 'poconet' unless ( defined ( $self->{Config}->{Network} ) and $self->{Config}->{Network} );
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
}

sub set_motd {
  my ($kernel,$self) = @_[KERNEL,OBJECT];
  my ($options);
  
  if ( ref $_[ARG0] eq 'ARRAY' ) {
    $options = $_[ARG0];
  } else {
    $options = [ @_[ARG0 .. $#_] ];
  }

  if ( scalar ( @{ $options } ) > 0 ) {
	$self->{Config}->{MOTD} = $options;
  } else {
	delete ( $self->{Config}->{MOTD} );
  }
}

sub add_listener {
  my ($kernel,$self,$sender) = @_[KERNEL,OBJECT,SENDER];
  my ($params);

  if ( ref $_[ARG0] eq 'HASH' ) {
     $params = $_[ARG0];
  } else {
     $params = { @_[ARG0 .. $#_] };
  }

  unless ( defined ( $params->{Port} ) and not defined ( $self->{Listeners}->{ $params->{Port} } ) ) {
	croak "No Port specified or there is a listener already defined on the port specified";
  }

  $params->{PingFreq} = 60 unless ( defined ( $params->{PingFreq} ) and $params->{PingFreq} >= 30 and $params->{PingFreq} <= 360 );

  my ($wheel) = POE::Wheel::SocketFactory->new (
	BindPort => $params->{Port},
	( $params->{BindAddr} ? ( BindAddr => $params->{BindAddr} ) : () ),
	Reuse    => 'on',
	( $params->{ListenQueue} ? ( ListenQueue => $params->{ListenQueue} ) : () ),
	SuccessEvent => 'accept_new_connection',
	FailureEvent => 'accept_failed',
  );

  $params->{Port} = (unpack_sockaddr_in( $wheel->getsockname ))[0];

  foreach ( keys %{ $params } ) {
	next if ( $_ eq 'Port' );
	$self->{Listeners}->{ $params->{Port} }->{$_} = $params->{$_};
  }

  $self->{Listeners}->{ $params->{Port} }->{Wheel} = $wheel;
  $self->{Listener_Wheels}->{$wheel->ID()} = $params->{Port};

  if ( defined ( $params->{SuccessEvent} ) ) {
	$kernel->post( $sender => $params->{SuccessEvent} => $params->{Port} );
  }
}

sub add_operator {
  my ($kernel,$self) = @_[KERNEL,OBJECT];
  my ($params);

  if ( ref $_[ARG0] eq 'HASH' ) {
     $params = $_[ARG0];
  } else {
     $params = { @_[ARG0 .. $#_] };
  }

  unless ( defined ( $params->{UserName} ) and defined ( $params->{Password} ) and $params->{UserName} and $params->{Password} ) {
	croak "No UserName or Password specified";
  }

  $self->{Operators}->{ $params->{UserName} } = $params;
}

sub add_i_line {
  my ($kernel,$self) = @_[KERNEL,OBJECT];
  my ($params);

  if ( ref $_[ARG0] eq 'HASH' ) {
     $params = $_[ARG0];
  } else {
     $params = { @_[ARG0 .. $#_] };
  }

  foreach my $param ( qw(TargetAddr HostAddr Port) ) {
    $params->{ $param } = '*' unless ( defined ( $params->{ $param } ) and $params->{ $param } ne '' );
  }
  push ( @{ $self->{I_Lines} }, $params );
}

sub accept_failed {
  my ($kernel,$self,$wheel_id) = @_[KERNEL,OBJECT,ARG3];

  my ($port) = $self->{Listener_Wheels}->{$wheel_id};

  delete ( $self->{Listener_Wheels}->{$wheel_id} );
  delete ( $self->{Listeners}->{$port} );
}

sub accept_new_connection {
  my ($kernel,$self,$socket,$peeraddr,$peerport,$wheel_id) = @_[KERNEL,OBJECT,ARG0 .. ARG3];
  $peeraddr = inet_ntoa($peeraddr);

  my ($wheel) = POE::Wheel::ReadWrite->new (
	Handle => $socket,
	Filter => $self->{filter},
	InputEvent => 'connection_input',
	ErrorEvent => 'connection_error',
	FlushedEvent => 'connection_flushed',
  );

  $self->{Connections}->{ $wheel->ID() }->{Wheel} = $wheel;
  $self->{Connections}->{ $wheel->ID() }->{Socket} = $socket;
  $self->{Connections}->{ $wheel->ID() }->{PeerAddr} = $peeraddr;
  $self->{Connections}->{ $wheel->ID() }->{PeerPort} = $peerport;
  $self->{Connections}->{ $wheel->ID() }->{SockAddr} = inet_ntoa( (unpack_sockaddr_in( getsockname $socket ))[1] );
  $self->{Connections}->{ $wheel->ID() }->{SockPort} = $self->{Listener_Wheels}->{ $wheel_id };
  $self->{Connections}->{ $wheel->ID() }->{IdleTime} = time();
  $self->{Connections}->{ $wheel->ID() }->{SeenTraffic} = time();
  $self->{Connections}->{ $wheel->ID() }->{ProperNick} = '*';

  if ( defined ( $self->{Listeners}->{ $self->{Listener_Wheels}->{ $wheel_id } }->{PingFreq} ) ) {
	$self->{Connections}->{ $wheel->ID() }->{PingFreq} = $self->{Listeners}->{ $self->{Listener_Wheels}->{ $wheel_id} }->{PingFreq};
  }
  if ( $self->{Config}->{Auth} ) {
	$kernel->post ( $self->{Alias} => 'auth_client' => $wheel->ID() );
  }
  $self->send_output_to_channel( '&CONNECTIONS', { command => 'NOTICE', prefix => $self->server_name(), params => [ '&CONNECTIONS', "Connection from $peeraddr to " . $self->{Listener_Wheels}->{ $wheel_id } ] } );
}

sub connection_error {
  my ($kernel,$self,$errstr,$wheel_id) = @_[KERNEL,OBJECT,ARG2,ARG3];

  SWITCH: {
    if ( $self->client_exists($wheel_id) ) {
	if ( not defined ( $self->{Clients}->{ $wheel_id }->{QUIT} ) ) {
	  $self->{Clients}->{ $wheel_id }->{ERROR} = 1;
	  $kernel->call ( $self->{Alias} => 'ircd_client_quit' => { command => 'QUIT', params => [ $errstr ] } => $wheel_id );
	}
	last SWITCH;
    }
    if ( defined ( $self->{Servers}->{ $wheel_id } ) ) {
	$kernel->post ( $self->{Alias} => 'ircd_server_squit' => { command => 'SQUIT', params => [ $errstr ] } => $wheel_id );
	last SWITCH;
    }
    delete ( $self->{Connections}->{ $wheel_id } );
  }
}

sub connection_input {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( defined ( $self->{Connections}->{ $wheel_id } ) and $input->{command} !~ /^(SERVER|NICK|PASS|USER|QUIT)$/ ) {
	$self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => '451', prefix => $self->{Config}->{ServerName}, params => [ $self->{Connections}->{ $wheel_id }->{ProperNick}, 'You have not registered' ] } );
	last SWITCH;
    }
    if ( defined ( $self->{Connections}->{ $wheel_id } ) and $input->{command} =~ /^(SERVER|NICK|PASS|USER|QUIT)$/ ) {
	$self->{Connections}->{ $wheel_id }->{SeenTraffic} = time();
  	$self->{Cmd_Usage}->{ $input->{command} }++;
	$kernel->post ( $self->{Alias} => 'ircd_connection_' . lc ( $input->{command} ) => $input => $wheel_id );
	last SWITCH;
    }
    if ( defined ( $self->{Servers}->{ $wheel_id } ) ) {
  	$self->{Cmd_Usage}->{ $input->{command} }++;
	$kernel->post ( $self->{Alias} => 'ircd_server_' . lc ( $input->{command} ) => $input => $wheel_id );
	last SWITCH;
    }
    # Okay check that it is a valid command
    if ( validate_command( $input->{command} ) ) {
  	$self->{Cmd_Usage}->{ $input->{command} }++;
	my ($current_time) = time();
	SWITCH2: {
	  if ( ( not $self->client_exists( $wheel_id ) ) or defined ( $self->{Clients}->{ $wheel_id }->{FLOODED} ) ) {
		last SWITCH2;
	  }
    	  $self->{Clients}->{ $wheel_id }->{SeenTraffic} = time();
          if ( $input->{command} eq 'PRIVMSG' or $input->{command} eq 'NOTICE' ) {
       		$self->{Clients}->{ $wheel_id }->{IdleTime} = time();
          }
	  if ( not defined ( $self->{Clients}->{ $wheel_id }->{PING} ) ) {
		$self->{Clients}->{ $wheel_id }->{PING} = $kernel->delay_set ( 'client_ping' => $self->lowest_ping_frequency() => $wheel_id );
	  } else {
		$kernel->alarm_adjust ( $self->{Clients}->{ $wheel_id }->{PING} => $self->lowest_ping_frequency() );
	  }
	  # AntiFlood off ? or an IRCop
	  if ( $self->is_operator($self->client_nickname($wheel_id)) or ( not $self->{Config}->{AntiFlood} ) ) {
		$kernel->post ( $self->{Alias} => 'ircd_client_' . lc ( $input->{command} ) => $input => $wheel_id );
		last SWITCH2;
	  }
	  if ( ( not defined ( $self->{Clients}->{ $wheel_id }->{Timer} ) ) or $self->{Clients}->{ $wheel_id }->{Timer} < $current_time ) {
		$self->{Clients}->{ $wheel_id }->{Timer} = $current_time;
		$kernel->post ( $self->{Alias} => 'ircd_client_' . lc ( $input->{command} ) => $input => $wheel_id );
		last SWITCH2;
	  }
	  if ( $self->{Clients}->{ $wheel_id }->{Timer} <= ( $current_time + 10 ) ) {
		$self->{Clients}->{ $wheel_id }->{Timer} += 1;
		push ( @{ $self->{Clients}->{ $wheel_id }->{MsgQ} }, $input );
		push ( @{ $self->{Clients}->{ $wheel_id }->{Alarms} }, $kernel->alarm_set( 'client_dispatcher' => $self->{Clients}->{ $wheel_id }->{Timer} => $wheel_id ) );
		last SWITCH2;
	  }
	  # Flood Alert!!!!!
	  $self->{Clients}->{ $wheel_id }->{FLOODED} = 1;
	  $kernel->call( $self->{Alias} => 'ircd_client_quit' => { command => 'QUIT', params => [ 'Excess Flood' ] } => $wheel_id );
	}
    } else {
	$self->send_output_to_client( $wheel_id, '421', $input->{command} );
    }
  }
}

sub client_dispatcher {
  my ($kernel,$self,$wheel_id) = @_[KERNEL,OBJECT,ARG0];

  SWITCH: {
    if ( ( not $self->client_exists( $wheel_id ) ) or defined ( $self->{Clients}->{ $wheel_id }->{FLOODED} ) ) {
	last SWITCH;
    }
    my ($input) = shift ( @{ $self->{Clients}->{ $wheel_id }->{MsgQ} } );
    if ( defined ( $input ) ) {
	$kernel->post( $self->{Alias} => 'ircd_client_' . lc ( $input->{command} ) => $input => $wheel_id );
    }
  }
}

sub client_ping {
  my ($kernel,$self,$wheel_id) = @_[KERNEL,OBJECT,ARG0];

  SWITCH: {
    if ( ( not $self->client_exists( $wheel_id ) ) or defined ( $self->{Clients}->{ $wheel_id }->{FLOODED} ) ) {
	last SWITCH;
    }
    delete ( $self->{Clients}->{ $wheel_id }->{PING} );
    my ($difference) = time() - $self->{Clients}->{ $wheel_id }->{SeenTraffic};
    if ( $difference > 180 ) {
	   $kernel->post ( $self->{Alias} => 'ircd_client_quit' => { command => 'QUIT', params => [ 'Ping timeout ' . $difference . ' seconds' ] } => $wheel_id );
	   last SWITCH;
    }
    $self->{Clients}->{ $wheel_id }->{Wheel}->put( { command => 'PING', params => [ $self->{Config}->{ServerName} ] } );
    $self->{Clients}->{ $wheel_id }->{PING} = $kernel->delay_set ( 'client_ping' => $self->lowest_ping_frequency() => $wheel_id );
  }
}

sub connection_flushed {
  my ($kernel,$self,$wheel_id) = @_[KERNEL,OBJECT,ARG0];

  SWITCH: {
    if ( defined ( $self->{Connections}->{ $wheel_id } ) and defined ( $self->{Connections}->{ $wheel_id }->{INVALID_PASSWORD} ) ) {
  	delete ( $self->{Connections}->{ $wheel_id } );
	last SWITCH;
    }
    if ( $self->client_exists( $wheel_id ) and defined ( $self->{Clients}->{ $wheel_id }->{QUIT} ) ) {
	delete ( $self->{Clients}->{ $wheel_id } );
	last SWITCH;
    }
    if ( $self->client_exists( $wheel_id ) and defined ( $self->{Clients}->{ $wheel_id }->{LOCAL_KILL} ) ) {
	delete ( $self->{Clients}->{ $wheel_id } );
	last SWITCH;
    }
    if ( $self->client_exists( $wheel_id ) and defined ( $self->{Clients}->{ $wheel_id }->{FLOODED} ) ) {
	delete ( $self->{Clients}->{ $wheel_id } );
	last SWITCH;
    }
  }
}

sub auth_client {
  my ($kernel,$self,$wheel_id) = @_[KERNEL,OBJECT,ARG0];
  my ($socket) = $self->{Connections}->{ $wheel_id }->{Socket};

  my ($peeraddress) = inet_ntoa( (unpack_sockaddr_in( getpeername $socket ))[1] );
  my ($peerport) = (unpack_sockaddr_in( getpeername $socket ))[0];
  my ($sockaddress) = inet_ntoa( (unpack_sockaddr_in( getsockname $socket ))[1] );
  my ($sockport) = (unpack_sockaddr_in( getsockname $socket ))[0];

  $self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => 'NOTICE', params => [ 'AUTH', '*** Checking Ident' ] } );
  $self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => 'NOTICE', params => [ 'AUTH', '*** Checking Hostname' ] } );
  if ( $peeraddress !~ /^127\./ ) {
    my ($response) = $self->{ $self->{Resolver} }->resolve( event => 'got_hostname_response', host => $peeraddress, context => { wheel => $wheel_id, peeraddr => $peeraddress }, type => 'PTR' );
    if ( defined ( $response ) ) {
	$kernel->post ( $self->{Alias} => 'got_hostname_response' => $response );
    }
  } else {
	$self->{Connections}->{ $wheel_id }->{Auth}->{HostName} = $self->{Config}->{ServerName};
	$self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => 'NOTICE', params => [ 'AUTH', '*** Found your hostname' ] } );
  }
  
  $kernel->post ( $self->{Ident_Client} => query => PeerAddr => $peeraddress, PeerPort => $peerport, SockAddr => $sockaddress, SockPort => $sockport, BuggyIdentd => 1, TimeOut => 10 );
  $self->{Ident_Lookups}->{ join(':',($peeraddress,$peerport,$sockaddress,$sockport)) } = $wheel_id;
}

sub ircd_connection_nick {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];
  my ($nickname) = $input->{params}->[0];
  $nickname = substr($nickname,0,$self->{Config}->{NICKLEN}) if ( defined ( $nickname ) and length($nickname) > $self->{Config}->{NICKLEN} );

  SWITCH: {
    if ( not defined ( $self->{Connections}->{ $wheel_id } ) ) {
	last SWITCH;
    }
    if ( not defined ( $nickname ) or $nickname eq "" ) {
	$self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => '431', prefix => $self->{Config}->{ServerName}, params => [ 'No nickname given' ] } );
	last SWITCH;
    }
    if ( not validate_nickname($nickname) ) {
	$self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => '432', prefix => $self->{Config}->{ServerName}, params => [ $nickname, 'Erroneus nickname' ] } );
	last SWITCH;
    }
    if ( $self->nick_exists($nickname) and not ( $self->{Connections}->{ $wheel_id }->{NickName} eq u_irc ( $nickname ) ) ) {
	$self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => '433', prefix => $self->{Config}->{ServerName}, params => [ $nickname, 'Nickname is already in use' ] } );
	last SWITCH;
    }
    if ( $self->client_exists( $wheel_id ) and $self->nick_exists($nickname) and not ( $self->{Clients}->{ $wheel_id }->{NickName} eq u_irc ( $nickname ) ) ) {
	$self->{Clients}->{ $wheel_id }->{Wheel}->put( { command => '433', prefix => $self->{Config}->{ServerName}, params => [ $nickname, 'Nickname is already in use' ] } );
	last SWITCH;
    }
    # We have to check whether the user has used a USER command already for the purposes of registering. *sigh*
    if ( defined ( $self->{Connections}->{ $wheel_id }->{UserName} ) ) {
	$self->{Connections}->{ $wheel_id }->{NickName} = u_irc ( $nickname );
  	$self->{Connections}->{ $wheel_id }->{ProperNick} = $nickname;
	$kernel->post ( $self->{Alias} => 'auth_done' => $wheel_id );
	last SWITCH;
    }
    $self->{Connections}->{ $wheel_id }->{NickName} = u_irc ( $nickname );
    $self->{Connections}->{ $wheel_id }->{ProperNick} = $nickname;
  }
}

sub ircd_connection_user {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not defined ( $self->{Connections}->{ $wheel_id } ) ) {
	last SWITCH;
    }
    if ( defined ( $self->{Connections}->{ $wheel_id }->{UserName} ) ) {
	$self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => '462', prefix => $self->{Config}->{ServerName}, params => [ $self->{Connections}->{ $wheel_id }->{ProperNick}, 'You may not reregister' ] } );
	last SWITCH;
    }
    if ( not defined ( $input->{params} ) or scalar( @{ $input->{params} } ) < 4 ) {
	$self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => '461', prefix => $self->{Config}->{ServerName}, params => [ $self->{Connections}->{ $wheel_id }->{ProperNick}, $input->{command}, 'Not enough parameters' ] } );
	last SWITCH;
    }
    $self->{Connections}->{ $wheel_id }->{UserName} = '^' . $input->{params}->[0];
    $self->{Connections}->{ $wheel_id }->{UserName} = substr ( $input->{params}->[0],0,$self->{Config}->{USERLEN} ) if ( length ( $input->{params}->[0] ) > $self->{Config}->{USERLEN} );
    $self->{Connections}->{ $wheel_id }->{RealName} = $input->{params}->[3];
    $self->{Connections}->{ $wheel_id }->{RealName} = substr ( $input->{params}->[3],0,$self->{Config}->{REALLEN} ) if ( length ( $input->{params}->[3] ) > $self->{Config}->{REALLEN} );
    if ( defined ( $self->{Connections}->{ $wheel_id }->{NickName} ) ) {
	$kernel->post ( $self->{Alias} => 'auth_done' => $wheel_id );
    }
  }
}

sub ircd_connection_quit {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not defined ( $self->{Connections}->{ $wheel_id } ) ) {
	last SWITCH;
    }
    $self->{Connections}->{ $wheel_id }->{INVALID_PASSWORD} = 1;
    $self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => 'ERROR', params => [ 'Closing Link: ' . $self->{Connections}->{ $wheel_id }->{ProperNick} . '[' . $self->{Connections}->{ $wheel_id }->{UserName} . '@' . $self->{Connections}->{ $wheel_id }->{PeerAddr} . '] (Quit: ' . $input->{params}->[0] . ')' ] } );
  }
}

sub ircd_connection_pass {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not defined ( $self->{Connections}->{ $wheel_id } ) ) {
	last SWITCH;
    }
    if ( not defined ( $input->{params}->[0] ) or $input->{params}->[0] eq "" ) {
	$self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => '461', prefix => $self->{Config}->{ServerName}, params => [ $self->{Connections}->{ $wheel_id }->{ProperNick}, $input->{command}, 'Not enough parameters' ] } );
	last SWITCH;
    }
    $self->{Connections}->{ $wheel_id }->{GotPwd} = $input->{params}->[0];
  }
}

sub ircd_connection_server {
}

sub auth_done {
  my ($kernel,$self,$wheel_id) = @_[KERNEL,OBJECT,ARG0];

  SWITCH: {
    if ( not defined ( $self->{Connections}->{ $wheel_id } ) ) {
	last SWITCH;
    }
    if ( not $self->{Config}->{Auth} ) {
  	$kernel->post ( $self->{Alias} => 'client_registered' => $wheel_id );
	last SWITCH;
    }
    # Check if both checks have finished.
    if ( defined ( $self->{Connections}->{ $wheel_id }->{Auth}->{HostName} ) and defined ( $self->{Connections}->{ $wheel_id }->{Auth}->{Ident} ) and defined ( $self->{Connections}->{ $wheel_id }->{NickName} ) and defined ( $self->{Connections}->{ $wheel_id }->{UserName} ) ) {
  	$kernel->post ( $self->{Alias} => 'client_registered' => $wheel_id );
	last SWITCH;
    }
  }
}

sub got_hostname_response {
    my ($kernel,$self) = @_[KERNEL,OBJECT];
    my $response = $_[ARG0];
    my ($wheel_id) = $response->{context}->{wheel};

    SWITCH: {
    if ( not defined ( $self->{Connections}->{ $wheel_id } ) ) {
	last SWITCH;
    }
    if ( defined ( $response->{response} ) ) {
      my @answers = $response->{response}->answer();

      if ( scalar ( @answers ) == 0 ) {
	# Send NOTICE to client of failure.
	$self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => 'NOTICE', params => [ 'AUTH', "*** Couldn\'t look up your hostname" ] } ) unless ( defined ( $self->{Connections}->{ $wheel_id } ) and defined ( $self->{Connections}->{ $wheel_id }->{Auth}->{HostName} ) );
	$self->{Connections}->{ $wheel_id }->{Auth}->{HostName} = '';
	$kernel->post ( $self->{Alias} => 'auth_done' => $wheel_id );
      }

      foreach my $answer (@answers) {
	my ($context) = $response->{context};
	$context->{hostname} = $answer->rdatastr();
	if ( $context->{hostname} =~ /\.$/ ) {
	   chop($context->{hostname});
	}
	my ($query) = $self->{ $self->{Resolver} }->resolve( event => 'got_ip_response', host => $answer->rdatastr(), context => $context, type => 'A' );
	if ( defined ( $query ) ) {
	   $kernel->post ( $self->{Alias} => 'got_ip_response' => $query );
	}
      }
    } else {
	# Send NOTICE to client of failure.
	$self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => 'NOTICE', params => [ 'AUTH', "*** Couldn\'t look up your hostname" ] } ) unless ( defined ( $self->{Connections}->{ $wheel_id } ) and defined ( $self->{Connections}->{ $wheel_id }->{Auth}->{HostName} ) );
	$self->{Connections}->{ $wheel_id }->{Auth}->{HostName} = '';
	$kernel->post ( $self->{Alias} => 'auth_done' => $wheel_id );
    }
    }
}

sub got_ip_response {
    my ($kernel,$self) = @_[KERNEL,OBJECT];
    my $response = $_[ARG0];
    my ($wheel_id) = $response->{context}->{wheel};

    SWITCH: {
    if ( not defined ( $self->{Connections}->{ $wheel_id } ) ) {
	last SWITCH;
    }
    if ( defined ( $response->{response} ) ) {
      my @answers = $response->{response}->answer();
      my ($peeraddress) = $response->{context}->{peeraddr};
      my ($hostname) = $response->{context}->{hostname};

      if ( scalar ( @answers ) == 0 ) {
	# Send NOTICE to client of failure.
	$self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => 'NOTICE', params => [ 'AUTH', "*** Couldn\'t look up your hostname" ] } ) unless ( defined ( $self->{Connections}->{ $wheel_id } ) and defined ( $self->{Connections}->{ $wheel_id }->{Auth}->{HostName} ) );
	$self->{Connections}->{ $wheel_id }->{Auth}->{HostName} = '';
	$kernel->post ( $self->{Alias} => 'auth_done' => $wheel_id );
      }

      foreach my $answer (@answers) {
	if ( $answer->rdatastr() eq $peeraddress and ( defined ( $self->{Connections}->{ $wheel_id } ) and not ( defined ( $self->{Connections}->{ $wheel_id }->{Auth}->{HostName} ) ) ) ) {
	   if ( length ( $hostname ) > $self->{Config}->{HOSTLEN} ) {
	     $self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => 'NOTICE', params => [ 'AUTH', '*** Your hostname is too long, ignoring hostname' ] } );
	     $self->{Connections}->{ $wheel_id }->{Auth}->{HostName} = $self->{Clients}->{ $wheel_id }->{PeerAddr};
	   } else {
	     $self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => 'NOTICE', params => [ 'AUTH', '*** Found your hostname' ] } );
	     $self->{Connections}->{ $wheel_id }->{Auth}->{HostName} = $hostname;
	     $kernel->post ( $self->{Alias} => 'auth_done' => $wheel_id );
	   }
	} else {
	   $self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => 'NOTICE', params => [ 'AUTH', '*** Your forward and reverse DNS do not match' ] } ) unless ( defined ( $self->{Connections}->{ $wheel_id } ) and defined ( $self->{Connections}->{ $wheel_id }->{Auth}->{HostName} ) );
	}
      }
    } else {
	# Send NOTICE to client of failure.
	$self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => 'NOTICE', params => [ 'AUTH', "*** Couldn\'t look up your hostname" ] } ) unless ( defined ( $self->{Connections}->{ $wheel_id } ) and defined ( $self->{Connections}->{ $wheel_id }->{Auth}->{HostName} ) );
	$self->{Connections}->{ $wheel_id }->{Auth}->{HostName} = '';
	$kernel->post ( $self->{Alias} => 'auth_done' => $wheel_id );
    }
    }
}

sub ident_client_reply {
  my ($kernel,$self,$ref,$opsys,$other) = @_[KERNEL,OBJECT,ARG0,ARG1,ARG2];
  my ($reference) = join(':',($ref->{PeerAddr},$ref->{PeerPort},$ref->{SockAddr},$ref->{SockPort}));

  if ( defined ( $self->{Ident_Lookups}->{ $reference } ) ) {
    my ($wheel_id) = delete ( $self->{Ident_Lookups}->{ $reference } );

    if ( defined ( $self->{Connections}->{ $wheel_id } ) ) {
      if ( uc ( $opsys ) ne 'OTHER' ) {
	$self->{Connections}->{ $wheel_id }->{Auth}->{Ident} = $other;
      } else {
	$self->{Connections}->{ $wheel_id }->{Auth}->{Ident} = '';
      }
      $self->{Connections}->{ $wheel_id }->{Wheel}->put ( { command => 'NOTICE', params => [ 'AUTH', "*** Got Ident response" ] } );
      $kernel->post ( $self->{Alias} => 'auth_done' => $wheel_id );
    }
  }
}

sub ident_client_error {
  my ($kernel,$self,$ref,$error) = @_[KERNEL,OBJECT,ARG0,ARG1];
  my ($reference) = join(':',($ref->{PeerAddr},$ref->{PeerPort},$ref->{SockAddr},$ref->{SockPort}));

  if ( defined ( $self->{Ident_Lookups}->{ $reference } ) ) {
    my ($wheel_id) = delete ( $self->{Ident_Lookups}->{ $reference } );
    
    if ( defined ( $self->{Connections}->{ $wheel_id } ) ) {
      $self->{Connections}->{ $wheel_id }->{Auth}->{Ident} = '';
      $self->{Connections}->{ $wheel_id }->{Wheel}->put ( { command => 'NOTICE', params => [ 'AUTH', "*** No Ident response" ] } );
      $kernel->post ( $self->{Alias} => 'auth_done' => $wheel_id );
    }
  }
}

sub ircd_client_oper {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( ( not defined ( $input->{params}->[0] ) or $input->{params}->[0] eq "" ) or ( not defined ( $input->{params}->[1] ) or $input->{params}->[1] eq "" ) ) {
	$self->send_output_to_client($wheel_id,'461',$input->{command});
	last SWITCH;
    }
    if ( not defined ( $self->{Operators}->{ $input->{params}->[0] } ) or $self->{Operators}->{ $input->{params}->[0] }->{Password} ne $input->{params}->[1] ) {
	$self->send_output_to_client($wheel_id,'464');
	last SWITCH;
    }
    if ( not $self->client_matches_o_line($wheel_id,$input->{params}->[0]) ) {
	$self->send_output_to_client($wheel_id,'491');
	last SWITCH;
    }
    if ( my $reply = $self->state_user_oper($nickname) ) {
        $self->send_output_to_client( $wheel_id, { command => '381', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), 'You are now an IRC operator' ] } );
        $self->send_output_to_client( $wheel_id, { command => 'MODE', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $reply ] } );
    }
  }
}

sub ircd_client_nick {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $input->{params}->[0];
    my ($whom) = $self->nick_long_form($self->client_nickname($wheel_id));
    $nickname = substr($nickname,0,$self->{Config}->{NICKLEN}) if ( length($nickname) > $self->{Config}->{NICKLEN} );
    if ( my $result = $self->state_nick_change($self->client_nickname($wheel_id),$nickname) ) {
	if ( $result eq '1' ) {
		$self->send_output_to_common( $wheel_id, { command => 'NICK', prefix => $whom, params => [ $nickname ] } );
	} else {
		$self->send_output_to_client($wheel_id,$result,$nickname);
	}
    }
  }
}

sub ircd_client_user {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    $self->send_output_to_client($wheel_id,'462');
  }
}

sub ircd_client_pass {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    $self->send_output_to_client($wheel_id,'462');
  }
}

sub ircd_client_part {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( not defined ( $input->{params}->[0] ) or $input->{params}->[0] eq "" ) {
	$self->send_output_to_client($wheel_id,'461',$input->{command});
	last SWITCH;
    }
    foreach my $channel ( split (/,/,$input->{params}->[0]) ) {
      if ( not validate_channelname ( $channel ) ) {
	$self->send_output_to_client($wheel_id,'403',$channel);
	last SWITCH;
      }
      if ( not $self->is_channel_member($channel,$nickname) ) {
	$self->send_output_to_client($wheel_id,'442',$channel);
	last SWITCH;
      }
      $self->send_output_to_channel($channel, { command => 'PART', prefix => $self->nick_long_form($nickname), params => [ $self->channel_name($channel), ( defined ( $input->{params}->[1] ) ? $input->{params}->[1] : () ) ] });
      $self->state_channel_part($channel,$nickname);
    }
  }
}

sub ircd_client_quit {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  if ( $self->client_exists( $wheel_id ) ) {
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    $self->send_output_to_common( $wheel_id, { command => 'QUIT', prefix => $self->nick_long_form($nickname), params => [ ( $input->{params}->[0] ? $input->{params}->[0] : "Quit" ) ] } );
    $self->send_output_to_client( $wheel_id, { command => 'ERROR', params => [ 'Closing Link: ' . $self->proper_nickname($nickname) . '[' . $self->{State}->{by_nickname}->{ $nickname }->{UserName} . '@' . $self->{State}->{by_nickname}->{ $nickname }->{HostName} . '] ' . ' ( Quit: ' . ( $input->{params}->[0] ? $input->{params}->[0] : '""' ) . ')' ] } ) unless ( defined ( $self->{Clients}->{ $wheel_id }->{ERROR} ) );
    # Remove client from STATE table
    $self->state_user_quit($wheel_id);
    delete ( $self->{Clients}->{ $wheel_id }->{MsgQ} );
    while ( my $alarm = shift ( @{ $self->{Clients}->{ $wheel_id }->{Alarms} } ) ) {
	$kernel->alarm_remove( $alarm );
    }
    if ( my $alarm_id = delete ( $self->{Clients}->{ $wheel_id }->{PING} ) ) {
	$kernel->alarm_remove ( $alarm_id );
    }
    if ( defined ( $self->{Clients}->{ $wheel_id }->{ERROR} ) ) {
	delete ( $self->{Clients}->{ $wheel_id } );
    } else {
      $self->{Clients}->{ $wheel_id }->{QUIT} = 1;
    }
  } else {
    delete ( $self->{Connections}->{ $wheel_id } );
  }
}

sub ircd_client_join {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];
  my (@channels); my (@channel_keys);

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    if ( not defined ( $input->{params}->[0] ) or $input->{params}->[0] eq "" ) {
	$self->send_output_to_client($wheel_id,'461',$input->{command});
	last SWITCH;
    }
    if ( $input->{params}->[0] eq '0' ) {
	if ( scalar ( $self->nick_channel_list( $self->client_nickname($wheel_id) ) ) > 0 ) {
	  $kernel->post ( $self->{Alias} => 'ircd_client_part' => { command => 'PART', params => [ join(',',$self->nick_channel_list($self->client_nickname($wheel_id))) ] } => $wheel_id );
	}
	last SWITCH;
    }
    @channels = split (/,/,$input->{params}->[0]) if ( defined ( $input->{params}->[0] ) );
    @channel_keys = split (/,/,$input->{params}->[1]) if ( defined ( $input->{params}->[1] ) );
    for ( my $i = 0; $i <= $#channels; $i++ ) {
	SWITCH2: {
	  if ( $channels[$i] eq '0' ) {
	     last SWITCH2;
	  }
	  if ( not validate_channelname ( $channels[$i] ) ) {
	     $self->send_output_to_client($wheel_id,'403',$channels[$i]);
	     last SWITCH2;
	  }
	  # This is just here for completeness. By default there are no limits on the number of channels a user
	  # can JOIN
	  if ( defined ( $self->{Config}->{MAXCHANNELS} ) and scalar ( keys %{ $self->{State}->{by_nickname}->{ $self->{Clients}->{ $wheel_id }->{NickName} }->{Channels} } ) >= $self->{Config}->{MAXCHANNELS} ) {
	     $self->send_output_to_client($wheel_id,'405',$channels[$i]);
	     last SWITCH2;
	  }
	  # Channel has a key? Has the user given us a valid key?
	  if ( $self->is_channel_mode_set($channels[$i],'k') and ( not defined ( $channel_keys[$i] ) or ( defined ( $channel_keys[$i] ) and $channel_keys[$i] ne $self->channel_key($channels[$i]) ) ) ) {
	     $self->send_output_to_client($wheel_id,'475',$channels[$i]);
	     last SWITCH2;
	  }
	  # Channel is full?
	  if ( $self->is_channel_mode_set($channels[$i],'l') and scalar ( keys %{ $self->{State}->{Channels}->{ u_irc ( $channels[$i] ) }->{Members} } ) >= $self->channel_limit($channels[$i]) ) {
	     $self->send_output_to_client($wheel_id,'471',$channels[$i]);
	     last SWITCH2;
	  }
	  # Channel invite only? And the user isn't INVITEd
	  if ( $self->is_channel_mode_set($channels[$i],'i') and not $self->user_invited_to_channel($channels[$i],$self->{Clients}->{ $wheel_id }->{NickName}) ) {
	     $self->send_output_to_client($wheel_id,'473',$channels[$i]);
	     last SWITCH2;
	  }
	  # User banned on the channel?
	  if ( $self->is_user_banned_from_channel($self->{Clients}->{ $wheel_id }->{NickName},$channels[$i]) ) {
	     #ERR_BANNEDFROMCHAN
	     $self->send_output_to_client($wheel_id,'474',$channels[$i]);
	     last SWITCH2;
	  }
	  # Okay JOIN the channel
          if ( $self->state_channel_join($channels[$i],$self->client_nickname($wheel_id)) ) {
		$self->send_output_to_channel( $channels[$i], { command => 'JOIN', prefix => $self->nick_long_form($self->client_nickname($wheel_id)), params => [ $channels[$i] ] } );
	        if ( $self->channel_topic($channels[$i]) ) {
	      		$kernel->post ( $self->{Alias} => 'ircd_client_topic' => { command => 'TOPIC', params => [ $channels[$i] ] } => $wheel_id );
	  	}
	  	$kernel->post ( $self->{Alias} => 'ircd_client_names' => { command => 'NAMES', params => [ $channels[$i] ] } => $wheel_id );
	  }
	}
    }
  }
}

sub ircd_client_invite {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( ( not defined ( $input->{params}->[0] ) or $input->{params}->[0] eq "" ) or ( not defined ( $input->{params}->[1] ) or $input->{params}->[1] eq "" ) ) {
	#ERR_NEEDMOREPARAMS
	$self->send_output_to_client($wheel_id,'461',$input->{command});
	last SWITCH;
    }
    if ( not $self->nick_exists($input->{params}->[0]) ) {
	#ERR_NOSUCHNICK
	$self->send_output_to_client($wheel_id,'401',$input->{params}->[0]);
	last SWITCH;
    }
    if ( $self->is_nick_on_channel($input->{params}->[0],$input->{params}->[1]) ) {
	#ERR_USERONCHANNEL
	$self->send_output_to_client($wheel_id,'443',$self->proper_nickname($input->{params}->[0]),$self->channel_name($input->{params}->[1]));
	last SWITCH;
    }
    if ( $self->channel_exists($input->{params}->[1]) and not $self->is_nick_on_channel($nickname,$input->{params}->[1]) ) {
	#ERR_NOTONCHANNEL
	$self->send_output_to_client($wheel_id,'442',$self->channel_name($input->{params}->[1]));
	last SWITCH;
    }
    if ( $self->is_channel_mode_set($input->{params}->[1],'i') and not $self->is_channel_operator($input->{params}->[1],$nickname) ) {
	#ERR_CHANOPRIVSNEEDED
	$self->send_output_to_client($wheel_id,'482',$self->channel_name($input->{params}->[1]));
	last SWITCH;
    }
    #RPL_INVITING
    $self->send_output_to_client( $wheel_id, { command => '341', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->channel_name($input->{params}->[1]), $self->proper_nickname($input->{params}->[0]) ] } );
    if ( my $client_wheel = $self->is_my_client($input->{params}->[0]) ) {
	# Our client \o/
	$self->send_output_to_client( $client_wheel, { command => 'INVITE', prefix => $self->nick_long_form($nickname), params => [ $self->proper_nickname($input->{params}->[0]), ':' . $input->{params}->[1] ] } );
	$self->{State}->{by_nickname}->{  u_irc ( $input->{params}->[0] ) }->{Invites}->{ u_irc ( $input->{params}->[1] ) } = 1 unless ( not validate_channelname ( $input->{params}->[1] ) );
    } else {
	# TODO: forward INVITE to appropriate server.
    }
  }
}

sub ircd_client_kick {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];
  my (@channels); my (@nicknames);

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( not defined ( $input->{params}->[0] ) or $input->{params}->[0] eq "" ) {
	$self->send_output_to_client($wheel_id,'461',$input->{command});
	last SWITCH;
    }
    @channels = split (/,/,$input->{params}->[0]) if ( defined ( $input->{params}->[0] ) );
    @nicknames = split (/,/,$input->{params}->[1]) if ( defined ( $input->{params}->[1] ) );
    if ( scalar ( @channels ) != scalar ( @nicknames ) and scalar ( @channels ) != 1 ) {
	$self->send_output_to_client($wheel_id,'461',$input->{command});
	last SWITCH;
    }
    my ($comment) = ( ( defined ( $input->{params}->[2] ) and $input->{params}->[2] ne "" ) ? $input->{params}->[2] : $self->{State}->{by_nickname}->{ $nickname }->{NickName} );
    for ( my $i = 0; $i <= $#channels; $i++ ) {
	SWITCH2: {
	  if ( not validate_channelname ( $channels[$i] ) ) {
		$self->send_output_to_client($wheel_id,'403',$channels[$i]);
		last SWITCH2;
	  }
	  if ( ( not $self->channel_exists($channels[$i]) ) or ( not $self->is_nick_on_channel($nickname,$channels[$i]) ) ) {
		$self->send_output_to_client($wheel_id,'442',$channels[$i]);
		last SWITCH2;
	  }
	  if ( not $self->is_channel_operator($channels[$i],$nickname) ) {
		$self->send_output_to_client($wheel_id,'482',$self->channel_name($channels[$i]));
		last SWITCH2;
	  }
	  my ($victims);
	  if ( scalar ( @channels ) == 1 and scalar ( @nicknames ) > 1 ) {
	    $victims = \@nicknames;
	  } else {
	    $victims = [ $nicknames[$i] ];
	  }
	  foreach my $victim ( @{ $victims } ) {
	    SWITCH22: {
	      if ( not $self->is_nick_on_channel($victim,$channels[$i]) ) {
		$self->send_output_to_client($wheel_id,'441',$victim,$self->channel_name($channels[$i]));
		last SWITCH22;
	      }
	      # KICK message to all channel members
	      $self->send_output_to_channel( $channels[$i], { command => 'KICK', prefix => $self->nick_long_form($nickname), params => [ $self->channel_name( $channels[$i] ), $self->proper_nickname( $victim ), $comment ] } );
	      $self->state_channel_part($channels[$i],$victim);
	    }
	  }
	}
    }
  }
}

sub ircd_client_names {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  # TODO: Rework this SWITCH so that we aren't duplicating code.

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->client_nickname($wheel_id);
    my ($reply_prefix) = ":" . $self->server_name() . " 353 " . $nickname . ' ';
    my ($reply_length) = length ( $reply_prefix ) + 3;
    if ( not defined ( $input->{params} ) or $input->{params}->[0] eq "" ) {
	# User wants to see everything
	my (@replies);
	foreach my $channel ( $self->list_channels() ) {
	  if ( $self->is_channel_visible_to_nickname($channel,$nickname) ) {
	    my ($stuff) = '=';
	    $stuff = '@' if ( $self->is_channel_mode_set($channel,'s') );
	    $stuff = '*' if ( $self->is_channel_mode_set($channel,'p') );
	    # Need to make sure that the reply is not longer than 510 chars
	    $self->send_output_to_client( $wheel_id, { command => '353', prefix => $self->server_name(), params => [ $nickname, $stuff, $channel, $user ] } );
	  }
	}
	foreach my $user ( $self->users_not_on_channels() ) {
	  if ( $self->is_nickname_visible($user) ) {
	    $self->send_output_to_client( $wheel_id, { command => '353', prefix => $self->server_name(), params => [ $nickname, '=', '*', $user ] } );
	  }
	}
	$self->send_output_to_client( $wheel_id, { command => '366', prefix => $self->server_name(), params => [ $nickname, '*', 'End of NAMES list' ] } );
	last SWITCH;
    }
    foreach my $channel ( split (/,/,$input->{params}->[0]) ) {
	  if ( $self->is_channel_visible_to_nickname($channel,$nickname) ) {
	    my ($stuff) = '=';
	    $stuff = '@' if ( $self->is_channel_mode_set($channel,'s') );
	    $stuff = '*' if ( $self->is_channel_mode_set($channel,'p') );
	    # Need to make sure that the reply is not longer than 510 chars
	    $self->send_output_to_client( $wheel_id, { command => '353', prefix => $self->server_name(), params => [ $nickname, $stuff, $channel, join(' ',$self->channel_members($channel)) ] } );
	  }
	  $self->send_output_to_client( $wheel_id, { command => '366', prefix => $self->server_name(), params => [ $nickname, $channel, 'End of NAMES list' ] } );
    }
  }
}

sub ircd_client_mode {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    if ( ( not defined ( $input->{params} ) ) or $input->{params}->[0] eq "" ) {
	$self->send_output_to_client($wheel_id,'461',$input->{command});
	last SWITCH;
    }
    if ( $input->{params}->[0] !~ /^(\x23|\x26|\x2B)/ and u_irc ( $input->{params}->[0] ) ne $self->{Clients}->{ $wheel_id }->{NickName} ) {
	$self->send_output_to_client($wheel_id,'502');
	last SWITCH;
    }
    if ( $input->{params}->[0] !~ /^(\x23|\x26|\x2B)/ and u_irc ( $input->{params}->[0] ) eq $self->{Clients}->{ $wheel_id }->{NickName} ) {
	SWITCH2: {
	  if ( ( not defined ( $input->{params}->[1] ) ) or $input->{params}->[1] eq "" ) {
	    $self->send_output_to_client( $wheel_id, { command => '221', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), '+' . ( defined ( $self->{State}->{by_nickname}->{ $self->{Clients}->{ $wheel_id }->{NickName} }->{UMode} ) ? $self->{State}->{by_nickname}->{ $self->{Clients}->{ $wheel_id }->{NickName} }->{UMode} : "" ) ] } );
	    last SWITCH2;
	  }
	  my ($reply,$errply) = $self->state_user_mode($self->client_nickname($wheel_id),@{ $input->{params} }[1 .. $#{ $input->{params} } ]);
	  $self->send_output_to_client($wheel_id,'501') if ( defined ( $errply ) );
	  $self->send_output_to_client( $wheel_id, { command => 'MODE', prefix => $self->client_nickname($wheel_id), params => [ $self->client_nickname($wheel_id), ':' . unparse_mode_line ( $reply ) ] } ) if ( defined ( $reply ) );
	}
	last SWITCH;
    }
    if ( $input->{params}->[0] =~ /^(\x23|\x26|\x2B)/ and not $self->channel_exists($input->{params}->[0]) ) {
	$self->send_output_to_client($wheel_id,'403',$input->{params}->[0]);
	last SWITCH;
    }
    SWITCH3: {
      if ( $input->{params}->[0] =~ /^\x2B/ ) {
	$self->send_output_to_client($wheel_id,'477',$self->channel_name($input->{params}->[0]));
	last SWITCH3;
      }
      if ( ( not defined ( $input->{params}->[1] ) or $input->{params}->[1] eq "" ) and not $self->is_channel_member($input->{params}->[0],$self->client_nickname($wheel_id)) ) {
	$self->send_output_to_client( $wheel_id, { command => '324', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->channel_name( $input->{params}->[0] ), '+' . ( $self->channel_mode( $input->{params}->[0] ) ? $self->channel_mode( $input->{params}->[0] ) : "" ) ] } );
	$self->send_output_to_client( $wheel_id, { command => '329', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->channel_name( $input->{params}->[0] ), $self->channel_created( $input->{params}->[0] ) ] } );
	last SWITCH3;
      }
      if ( not defined ( $input->{params}->[1] ) or $input->{params}->[1] eq "" ) {
	$self->send_output_to_client( $wheel_id, { command => '324', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->channel_name( $input->{params}->[0] ), '+' . ( $self->channel_mode( $input->{params}->[0] ) ? $self->channel_mode( $input->{params}->[0] ) : "" ), ( $self->channel_key( $input->{params}->[0]) ? $self->channel_key($input->{params}->[0]) : () ), ( $self->channel_limit($input->{params}->[0]) ? $self->channel_limit($input->{params}->[0]) : () ) ] } );
	$self->send_output_to_client( $wheel_id, { command => '329', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->channel_name( $input->{params}->[0] ), $self->channel_created( $input->{params}->[0] ) ] } );
	last SWITCH3;
      }
      if ( $input->{params}->[0] =~ /^(\x23|\x26|\x2B)/ and scalar ( @{ $input->{params} } ) <= 2 and ( $input->{params}->[1] =~ /^b/ or $input->{params}->[1] =~ /^\+b/ ) ) {
	foreach my $ban ( $self->channel_bans( $input->{params}->[0] ) ) {
	  $self->send_output_to_client( $wheel_id, { command => '367', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->channel_name( $input->{params}->[0] ), $ban ] } );
	}
	$self->send_output_to_client( $wheel_id, { command => '368', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->channel_name( $input->{params}->[0] ), 'End of channel ban list' ] } );
	last SWITCH3;
      }
      if ( $input->{params}->[0] =~ /^(\x23|\x26|\x2B)/ and ( not $self->is_channel_operator($input->{params}->[0],$self->{Clients}->{ $wheel_id }->{NickName}) ) ) {
	$self->send_output_to_client($wheel_id,'482',$input->{params}->[0]);
	last SWITCH3;
      }
      my ($parsed_mode) = parse_mode_line( @{ $input->{params} }[1 .. $#{ $input->{params} } ] );
      my ($reply); my (@reply_args); my ($errply);
      while ( my $mode = shift ( @{ $parsed_mode->{modes} } ) ) {
	if ( $mode !~ /[boviklntmps]/ ) {
	   (undef,$errply) = split (//,$mode) if ( not defined ( $errply ) );
	   next;
	}
	if ( $input->{params}->[0] =~ /^#/ and $mode =~ /a/ ) {
	   (undef,$errply) = split (//,$mode) if ( not defined ( $errply ) );
	   next;
	}
	my ($arg);
	$arg = shift ( @{ $parsed_mode->{args} } ) if ( $mode =~ /^(\+[ovklb]|-[ovb])/ );
	SWITCH33: {
	  if ( $mode =~ /^(\+|-)([ov])/ and not defined ( $arg ) ) {
		last SWITCH33;
	  }
	  if ( $mode =~ /^\+[lk]/ and not defined ( $arg ) ) {
		$self->send_output_to_client($wheel_id,'461',$input->{command} . ' ' . $mode);
		last SWITCH33;
	  }
	  if ( $mode =~ /^(\+|-)([ov])/ and not $self->nick_exists($arg) ) {
		$self->send_output_to_client($wheel_id,'401',$arg);
		last SWITCH33;
	  }
	  if ( $mode =~ /^(\+|-)([ov])/ and not $self->is_nick_on_channel($arg,$input->{params}->[0]) ) {
		$self->send_output_to_client($wheel_id,'441',$input->{params}->[0],$arg);
		last SWITCH33;
	  }
	  if ( $mode =~ /^(\+|-)([ov])/ and $self->state_channel_member($input->{params}->[0],$mode,$arg) ) {
		$reply .= $mode;
		push ( @reply_args, $arg );
		last SWITCH33;
	  }
	  if ( $mode eq '+b' and not defined ( $arg ) ) {
		foreach my $ban ( $self->channel_bans( $input->{params}->[0] ) ) {
	  	  $self->send_output_to_client( $wheel_id, { command => '367', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->channel_name( $input->{params}->[0] ), $ban ] } );
		}
		$self->send_output_to_client( $wheel_id, { command => '368', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->channel_name( $input->{params}->[0] ), 'End of channel ban list' ] } );
		last SWITCH33;
	  }
	  if ( $mode eq '-b' and not defined ( $arg ) ) {
		last SWITCH33;
	  }
	  my (@status) = $self->state_channel_mode($input->{params}->[0],$mode,$arg);
	  $reply .= $status[0] if ( defined ( $status[0] ) );
	  push(@reply_args,$status[1]) if ( defined ( $status[1] ) );
	}
      }
      $self->send_output_to_client($wheel_id,'472',$errply,$self->channel_name($input->{params}->[0])) if ( defined ( $errply ) );
      $reply .= ' ' . join(' ',@reply_args) if ( scalar ( @reply_args ) > 0 );
      $self->send_output_to_channel( $input->{params}->[0], { command => 'MODE', prefix => $self->nick_long_form($self->client_nickname($wheel_id)), params => [ $self->channel_name( $input->{params}->[0] ), unparse_mode_line ( $reply ) ] } ) if ( defined ( $reply ) );
    }
  }
}

sub ircd_client_topic {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( not defined ( $input->{params}->[0] ) or $input->{params}->[0] eq "" ) {
	$self->send_output_to_client($wheel_id,'461',$input->{command});
	last SWITCH;
    }
    if ( not $self->is_channel_member($input->{params}->[0],$nickname) ) {
	$self->send_output_to_client($wheel_id,'442',$input->{params}->[0]);
	last SWITCH;
    }
    if ( ( not defined ( $input->{params}->[1] ) ) and my $topic = $self->channel_topic($input->{params}->[0]) ) {
	$self->send_output_to_client( $wheel_id, { command => '332', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->channel_name( $input->{params}->[0] ), $topic->[0] ] } );
	$self->send_output_to_client( $wheel_id, { command => '333', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->channel_name( $input->{params}->[0] ), $topic->[1], $topic->[2] ] } );
	last SWITCH;
    }
    if ( ( not defined ( $input->{params}->[1] ) ) and ( not $self->channel_topic($input->{params}->[0]) ) ) {
	$self->send_output_to_client( $wheel_id, { command => '331', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->channel_name( $input->{params}->[0] ), 'No topic is set' ] } );
	last SWITCH;
    }
    if ( defined ( $input->{params}->[1] ) and $self->is_channel_mode_set($input->{params}->[0],'t') and not $self->is_channel_operator($input->{params}->[0],$nickname) ) {
	$self->send_output_to_client($wheel_id,'482',$self->channel_name($input->{params}->[0]));
	last SWITCH;
    }
    # Got this far so set, change or unset the TOPIC.
    $self->state_topic_set( @{ $input->{params} } );
    $self->state_topic_set_by( $input->{params}->[0], $self->client_nickname($wheel_id) );
    $self->send_output_to_channel( $input->{params}->[0], { command => 'TOPIC', prefix => $self->nick_long_form($nickname), params => [ $self->channel_name( $input->{params}->[0] ), ( $input->{params}->[1] ? $input->{params}->[1] : ':' ) ] } );
  }
}

sub ircd_client_o_cmds {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( not $self->is_operator( $nickname ) ) {
	#ERR_NOPRIVILEGES
	$self->send_output_to_client($wheel_id,'481');
 	last SWITCH;
    }
    $input->{prefix} = $self->nick_long_form( $nickname );
    foreach my $session ( keys %{ $self->{sessions} } ) {
	$kernel->post ( $session => 'ircd_cmd_' . lc ( $input->{command} ) => $input );
    }
    if ( $input->{command} eq 'REHASH' ) {
	$self->send_output_to_client( $wheel_id, { command => '382', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), 'ircd.conf :Rehashing' ] } );
    }
  }
}

sub sig_hup_rehash {
  my ($kernel,$self) = @_[KERNEL,OBJECT];

    foreach my $session ( keys %{ $self->{sessions} } ) {
	$kernel->post ( $session => 'ircd_cmd_rehash' => { command => 'REHASH', prefix => $self->server_name() } );
    }
    $kernel->sig_handled();
}

sub ircd_client_kill {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( not $self->is_operator( $nickname ) ) {
	#ERR_NOPRIVILEGES
	$self->send_output_to_client($wheel_id,'481');
 	last SWITCH;
    }
    if ( ( not defined ( $input->{params}->[0] ) or $input->{params}->[0] eq "" ) or ( not defined ( $input->{params}->[1] ) or $input->{params}->[1] eq "" ) ) {
	#ERR_NEEDMOREPARAMS
	$self->send_output_to_client($wheel_id,'461',$input->{command});
	last SWITCH;
    }
    if ( $self->is_server_me($input->{params}->[0],$wheel_id) or $self->server_exists($input->{params}->[0]) ) {
	#ERR_CANTKILLSERVER
	$self->send_output_to_client($wheel_id,'483');
	last SWITCH;
    }
    if ( not $self->nick_exists($input->{params}->[0]) ) {
	#ERR_NOSUCHNICK
	$self->send_output_to_client($wheel_id,'401',$input->{params}->[0]);
	last SWITCH;
    }
    # Valid kill from an operator. Work out if local or remote kill.
    my ($victim) = u_irc ( $input->{params}->[0] );
    my ($comment) = $input->{params}->[1];

    if ( my $victim_wheel = $self->is_my_client($victim) ) {
	$self->send_output_to_client( $victim_wheel, { command => 'KILL', prefix => $self->nick_long_form($nickname), params => [ $self->proper_nickname($victim), $self->server_name() . '!' . $self->proper_nickname($nickname) . ' (' . $comment . ')' ] } );
	$self->{Clients}->{ $victim_wheel }->{LOCAL_KILL} = 1;
	$self->send_output_to_client( $victim_wheel, { command => 'ERROR', params => [ 'Closing Link: ' . $self->proper_nickname($victim) . '[' . $self->{State}->{by_nickname}->{ $victim }->{UserName} . '@' . $self->{State}->{by_nickname}->{ $victim }->{HostName} . '] ' . $self->proper_nickname($nickname) . ' (Local kill by ' . $self->proper_nickname($nickname) . ' (' . $comment . '))' ] } );
    	$self->send_output_to_common( $victim_wheel, { command => 'QUIT', prefix => $self->nick_long_form($victim), params => [ 'Local kill by ' . $self->proper_nickname($nickname) . ' (' . $comment . ')' ] } );
	$self->state_user_quit($victim_wheel);
    }
    # Send KILL message to each connected server
  }
}

sub ircd_client_wallops {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( not $self->is_operator( $nickname ) ) {
	#ERR_NOPRIVILEGES
	$self->send_output_to_client($wheel_id,'481');
 	last SWITCH;
    }
    if ( ( not defined ( $input->{params}->[0] ) ) or $input->{params}->[0] eq "" ) {
	#ERR_NEEDMOREPARAMS
	$self->send_output_to_client($wheel_id,'461',$input->{command});
 	last SWITCH;
    }
    foreach my $cl_wid ( keys %{ $self->{Clients} } ) {
	if ( $self->has_wallops( $self->{Clients}->{ $cl_wid }->{NickName} ) ) {
	  $self->send_output_to_client( $cl_wid, { command => 'WALLOPS', prefix => $self->nick_long_form($nickname), params => [ $input->{params}->[0] ] } );
	}
    }
    # TODO: Send WALLOPS to all connected servers.
  }
}

sub ircd_client_message {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( not defined ( $input->{params}->[0] ) or $input->{params}->[0] eq "" ) {
	#ERR_NORECIPIENT
	$self->send_output_to_client($wheel_id,'411',$input->{command});
	last SWITCH;
    }
    if ( not defined ( $input->{params}->[1] ) or $input->{params}->[1] eq "" ) {
	#ERR_NOTEXTTOSEND
	$self->send_output_to_client($wheel_id,'412');
	last SWITCH;
    }
    foreach my $recipient ( split (/,/,$input->{params}->[0]) ) {
      SWITCH2: {
	if ( ( not $self->channel_exists($recipient) ) and ( not $self->nick_exists($recipient) ) ) {
	  #ERR_NOSUCHNICK
	  $self->send_output_to_client($wheel_id,'401',$recipient);
	  last SWITCH2;
	}
	if ( $self->channel_exists($recipient) and ( ( $self->is_channel_mode_set($recipient,'n') and not $self->is_channel_member($recipient,$nickname) ) or ( $self->is_channel_mode_set($recipient,'m') and not ( $self->is_channel_operator($recipient,$nickname) or $self->has_channel_voice($recipient,$nickname) ) ) ) or ( $self->is_user_banned_from_channel($nickname,$recipient) ) ) {
	  #ERR_CANNOTSENDTOCHAN
	  $self->send_output_to_client($wheel_id,'404',$recipient);
	  last SWITCH2;
	}
	if ( $self->nick_exists($recipient) ) {
	  if ( my $recipient_wheel = $self->is_my_client($recipient) ) {
	    $self->send_output_to_client( $recipient_wheel, { command => $input->{command}, prefix => $self->nick_long_form($nickname), params => [ $recipient, $input->{params}->[1] ] } );
	    if ( $self->is_user_away($recipient) and $input->{command} ne 'NOTICE' ) {
		#RPL_AWAY
		$self->send_output_to_client( $wheel_id, { command => '301', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->proper_nickname( $recipient ), $self->{State}->{by_nickname}->{ u_irc ( $recipient ) }->{Away} ] } );
	    }
	  } else {
	    # TODO: Send in the right direction.
	  }
	  last SWITCH2;
	}
        foreach my $member ( keys %{ $self->{State}->{Channels}->{ u_irc ( $recipient ) }->{Members} } ) {
	  if ( my $member_wheel = $self->is_my_client($member) and $member ne $nickname ) {
	    $self->send_output_to_client( $member_wheel, { command => $input->{command}, prefix => $self->nick_long_form($nickname), params => [ $self->channel_name( $recipient ), ( $input->{params}->[1] =~ /^:/ ? ':' . $input->{params}->[1] : $input->{params}->[1] ) ] } );
	  } else {
		#TODO: Work out direction to send it.
	  }
        }
        # Send to appropriate servers.
      }
    }
  }
}

sub ircd_client_summon {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    $self->send_output_to_client($wheel_id,'445');
  }
}

sub ircd_client_users {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    $self->send_output_to_client($wheel_id,'446');
  }
}

sub ircd_client_who {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    # Does the first parameter contain a wildcard ( ie. * and/or ? ).
    if ( ( defined ( $input->{params}->[0] ) and $input->{params}->[0] ne "" ) and $self->contains_wildcard($input->{params}->[0]) ) {
	foreach my $member ( $self->nicks_match_wildcard($input->{params}->[0]) ) {
	  my (@reply);
	  next unless ( $self->is_nickname_visible($member) ); 
	  $reply[0] = $self->client_nickname($wheel_id);
	  $reply[1] = '*';
	  $reply[2] = $self->{State}->{by_nickname}->{ $member }->{UserName};
	  $reply[3] = $self->{State}->{by_nickname}->{ $member }->{HostName};
	  $reply[4] = $self->{State}->{by_nickname}->{ $member }->{ServerName};
	  $reply[5] = $self->{State}->{by_nickname}->{ $member }->{NickName};
	  $reply[6] = ( $self->is_user_away($member) ? "G" : "H" ) . ( $self->is_operator($member) ? '*' : '' );
	  $reply[7] = $self->{State}->{by_nickname}->{ $member }->{HopCount};
	  $reply[7] .= ' ' . $self->{State}->{by_nickname}->{ $member }->{RealName} if ( defined ( $self->{State}->{by_nickname}->{ $member }->{RealName} ) );
	  $self->send_output_to_client( $wheel_id, { command => '352', prefix => $self->server_name(), params => \@reply } ) unless ( defined ( $input->{params}->[1] ) and ( $input->{params}->[1] eq 'o' and not $self->is_operator($member) ) );
	}
	$self->send_output_to_client( $wheel_id, { command => '315', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $input->{params}->[0], 'End of WHO list' ] } );
	last SWITCH;
    }
    # Target must be a valid channel or bogus.
    if ( $self->channel_exists($input->{params}->[0]) and $self->is_channel_visible_to_nickname($input->{params}->[0],$nickname) ) {
	foreach my $member ( $self->channel_list( $input->{params}->[0] ) ) {
	  my (@reply);
	  $reply[0] = $self->client_nickname($wheel_id);
	  $reply[1] = $self->{State}->{Channels}->{ u_irc ( $input->{params}->[0] ) }->{ChannelName};
	  $reply[2] = $self->{State}->{by_nickname}->{ $member }->{UserName};
	  $reply[3] = $self->{State}->{by_nickname}->{ $member }->{HostName};
	  $reply[4] = $self->{State}->{by_nickname}->{ $member }->{ServerName};
	  $reply[5] = $self->{State}->{by_nickname}->{ $member }->{NickName};
	  $reply[6] = ( $self->is_user_away($member) ? "G" : "H" ) . ( $self->is_operator($member) ? '*' : '' ) . ( $self->is_channel_operator($input->{params}->[0],$member) ? '@' : ( $self->has_channel_voice($input->{params}->[0],$member) ? '+' : '' ) );
	  $reply[7] = $self->{State}->{by_nickname}->{ $member }->{HopCount};
	  $reply[7] .= ' ' . $self->{State}->{by_nickname}->{ $member }->{RealName} if ( defined ( $self->{State}->{by_nickname}->{ $member }->{RealName} ) );
	  $self->send_output_to_client( $wheel_id, { command => '352', prefix => $self->server_name(), params => \@reply } ) unless ( defined ( $input->{params}->[1] ) and ( $input->{params}->[1] eq 'o' and not $self->is_operator($member) ) );
	}
	$self->send_output_to_client( $wheel_id, { command => '315', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->channel_name( $input->{params}->[0] ), 'End of WHO list' ] } );
	last SWITCH;
    }
    # Fall back position send RPL_ENDOFWHO
    #RPL_ENDOFWHO
    $self->send_output_to_client( $wheel_id, { command => '315', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $input->{params}->[0], 'End of WHO list' ] } );
  }
}

sub ircd_client_whois {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( ( not defined ( $input->{params}->[0] ) ) or $input->{params}->[0] eq "" ) {
	#ERR_NONICKNAMEGIVEN
	$self->send_output_to_client($wheel_id,'431');
	last SWITCH;
    }
    if ( ( scalar ( @{ $input->{params} } ) >= 2 ) and ( u_irc ( $input->{params}->[0] ) eq u_irc ( $input->{params}->[1] ) ) and $self->nick_exists($input->{params}->[0]) ) {
	$input->{params}->[0] = $self->{State}->{by_nickname}->{ u_irc ( $input->{params}->[0] ) }->{ServerName};
    }
    if ( ( scalar ( @{ $input->{params} } ) >= 2 ) and ( not $self->is_server_me($input->{params}->[0],$wheel_id) ) and ( not $self->server_exists($input->{params}->[0]) ) and ( u_irc ( $input->{params}->[0] ) ne u_irc ( $input->{params}->[1] ) ) ) {
	#ERR_NOSUCHSERVER
	$self->send_output_to_client($wheel_id,'402',$input->{params}->[0]);
	last SWITCH;
    }
    if ( ( scalar ( @{ $input->{params} } ) >= 2 ) and ( not $self->is_server_me($input->{params}->[0],$wheel_id) ) and ( $self->server_exists($input->{params}->[0]) or u_irc ( $input->{params}->[0] ) eq u_irc ( $input->{params}->[1] ) ) ) {
	# TODO: Forward request to appropriate server
	last SWITCH;
    }
    my (@masks); my ($endofwhois);
    if ( defined ( $input->{params}->[0] ) and $input->{params}->[0] ne "" ) {
	$endofwhois = $input->{params}->[0];
    }
    if ( defined ( $input->{params}->[1] ) and $input->{params}->[1] ne "" ) {
	$endofwhois = $input->{params}->[1];
    }
    @masks = split(/,/,$endofwhois);
    foreach my $mask ( @masks ) {
	my ($targets);
	if ( $self->contains_wildcard($mask) ) {
	  $targets = [ $self->nicks_match_wildcard($mask) ];
	} else {
	  $targets->[0] = $mask;
	  if ( not $self->nick_exists($mask) ) {
		#ERR_NOSUCHNICK
		$self->send_output_to_client($wheel_id,'401',$mask);
		next;
	  }
	}
	foreach my $whois ( @{ $targets } ) {
	  #RPL_WHOISUSER
	  my ($whois_nick) = $self->{State}->{by_nickname}->{ u_irc ( $whois ) }->{NickName};
      	  $self->send_output_to_client( $wheel_id, { command => '311', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $whois_nick, $self->{State}->{by_nickname}->{u_irc ( $whois ) }->{UserName}, $self->{State}->{by_nickname}->{u_irc ( $whois ) }->{HostName}, '*', ( $self->{State}->{by_nickname}->{ u_irc ( $whois ) }->{RealName} ? $self->{State}->{by_nickname}->{ u_irc ( $whois ) }->{RealName} : ':' ) ] } );
	  #RPL_WHOISCHANNELS
	  my (@whoischannels);
	  foreach my $channel ( keys %{ $self->{State}->{by_nickname}->{ u_irc ( $whois ) }->{Channels} } ) {
	    if ( $self->is_channel_visible_to_nickname($channel,$nickname) ) {
		push ( @whoischannels, ( $self->is_channel_operator($channel,$whois) ? '@' : ( $self->has_channel_voice($channel,$whois) ? '+' : '' ) ) . $self->{State}->{Channels}->{ $channel }->{ChannelName} );
	    }
	  }
	  $self->send_output_to_client( $wheel_id, { command => '319', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->{State}->{by_nickname}->{ u_irc ( $whois) }->{NickName}, join(' ',@whoischannels) ] } ) if ( scalar ( @whoischannels ) > 0 );
	  #RPL_WHOISSERVER
	  $self->send_output_to_client( $wheel_id, { command => '312', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->{State}->{by_nickname}->{ u_irc ( $whois) }->{NickName}, ( $self->{State}->{by_nickname}->{ u_irc ( $whois ) }->{Wheel} ? $self->{Config}->{ServerName} : $self->{State}->{by_nickname}->{ u_irc ( $whois ) }->{Server} ), ( $self->is_my_client($whois) ? $self->server_description() : $self->{State}->{Servers}->{ $self->{State}->{by_nickname}->{ u_irc ( $whois ) }->{Server} }->{Description} ) ] } );
	  #RPL_AWAY
	  $self->send_output_to_client( $wheel_id, { command => '301', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->{State}->{by_nickname}->{ u_irc ( $whois) }->{NickName}, $self->{State}->{by_nickname}->{ u_irc ( $whois ) }->{Away} ] } ) if ( $self->is_user_away($whois) );
	  #RPL_WHOISOPERATOR
	  $self->send_output_to_client( $wheel_id, { command => '313', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->{State}->{by_nickname}->{ u_irc ( $whois) }->{NickName}, 'is an IRC operator' ] } ) if ( $self->is_operator($whois) );
	  #RPL_WHOISIDLE
	  $self->send_output_to_client( $wheel_id, { command => '317', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->{State}->{by_nickname}->{ u_irc ( $whois) }->{NickName}, ( time() - $self->{Clients}->{ $self->{State}->{by_nickname}->{ u_irc ( $whois ) }->{Wheel} }->{IdleTime} ), $self->{Clients}->{ $self->{State}->{by_nickname}->{ u_irc ( $whois ) }->{Wheel} }->{SignOn}, 'seconds idle, signon time' ] } ) if ( defined ( $self->{State}->{by_nickname}->{ u_irc ( $whois ) }->{Wheel} ) );
	}
    }
    #RPL_ENDOFWHOIS
    $self->send_output_to_client( $wheel_id, { command => '318', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $endofwhois, 'End of WHOIS list' ] } );
  }
}

sub ircd_client_whowas {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( ( not defined ( $input->{params} ) ) or $input->{params}->[0] eq "" ) {
	#ERR_NONICKNAMEGIVEN
	$self->send_output_to_client($wheel_id,'431');
	last SWITCH;
    }
    if ( scalar ( @{ $input->{params} } ) == 3 and ( not $self->is_server_me($input->{params}->[2],$wheel_id) ) and ( not $self->server_exists($input->{params}->[2]) ) ) {
	#ERR_NOSUCHSERVER
	$self->send_output_to_client($wheel_id,'402',$input->{params}->[0]);
	last SWITCH;
    }
    if ( scalar ( @{ $input->{params} } ) == 3 and ( not $self->is_server_me($input->{params}->[2],$wheel_id) ) and ( $self->server_exists($input->{params}->[2]) ) ) {
	# TODO: Forward request to appropriate server
	last SWITCH;
    }
    foreach my $nick ( split(/,/,$input->{params}->[0]) ) {
	#ERR_WASNOSUCHNICK
	$self->send_output_to_client($wheel_id,'406',$nick);
    }
    #RPL_ENDOFWHOWAS
    $self->send_output_to_client( $wheel_id, { command => '369', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $input->{params}->[0], 'End of WHOWAS' ] } );
  }
}

sub ircd_client_away {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( ( not defined ( $input->{params}->[0] ) ) or $input->{params}->[0] eq "" ) {
	#RPL_UNAWAY
	$self->send_output_to_client( $wheel_id, { command => '305', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), 'You are no longer marked as being away' ] } );
	delete ( $self->{State}->{by_nickname}->{ $nickname }->{Away} );
	if ( $self->is_user_away($nickname) ) {
	  $self->{State}->{by_nickname}->{ $nickname }->{UMode} =~ s/a//;
	  # TODO: Send MODE change to other servers
	}
	last SWITCH;
    }
    #RPL_NOWAWAY
    $self->send_output_to_client( $wheel_id, { command => '306', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), 'You have been marked as being away' ] } );
    if ( not $self->is_user_away($nickname) ) {
	$self->{State}->{by_nickname}->{ $nickname }->{UMode} .= 'a';
	$self->{State}->{by_nickname}->{ $nickname }->{UMode} = join('',split(//,$self->{State}->{by_nickname}->{ $nickname }->{UMode}));
	# TODO: Send MODE change to other servers
    }
    $self->{State}->{by_nickname}->{ $nickname }->{Away} = $input->{params}->[0];
  }
}

sub ircd_client_motd {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( ( ( not defined ( $input->{params}->[0] ) or $input->{params}->[0] eq "" ) or uc ( $input->{params}->[0] ) eq uc ( $self->{Config}->{ServerName} ) ) and defined ( $self->{Config}->{MOTD} ) ) {
	#RPL_MOTDSTART
	$self->send_output_to_client( $wheel_id, { command => '375', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), '- ' . $self->{Config}->{ServerName} . ' Message of the day - ' ] } );
	foreach my $line ( @{ $self->{Config}->{MOTD} } ) {
		#RPL_MOTD
		$self->send_output_to_client( $wheel_id, { command => '372', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), '- ' . $line ] } );
	}
	#RPL_ENDOFMOTD
	$self->send_output_to_client( $wheel_id, { command => '376', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), 'End of MOTD command' ] } );
	last SWITCH;
    }
    if ( ( ( not defined ( $input->{params}->[0] ) or $input->{params}->[0] eq "" ) or uc ( $input->{params}->[0] ) eq uc ( $self->{Config}->{ServerName} ) ) and not defined ( $self->{Config}->{MOTD} ) ) {
	#ERR_NOMOTD
	$self->send_output_to_client($wheel_id,'422');
	last SWITCH;
    }
    if ( ( defined ( $input->{params}->[0] ) and $input->{params}->[0] ne "" ) and not $self->server_exists($input->{params}->[0]) ) {
	#ERR_NOSUCHSERVER
	$self->send_output_to_client($wheel_id,'402',$input->{params}->[0]);
	last SWITCH;
    }
    # TODO: Pass MOTD request to target server to deal with.
  }
}

sub ircd_client_lusers {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    # Number of clients
    my ($rpl_luserclient) = 'There are ' . scalar ( keys %{ $self->{State}->{by_nickname} } ) . ' users and ' . scalar ( keys %{ $self->{State}->{Services} } ) . ' services on ' . ( scalar ( keys %{ $self->{State}->{Servers} } ) + 1 ) . ' servers';
    $self->send_output_to_client( $wheel_id, { command => '251', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $rpl_luserclient ] } );
    # Number of operators. Hmmm better way of doing this is to track ops as they join, oper, deop or quit.
    my ($no_of_ops) = 0;
    foreach my $user ( keys %{ $self->{State}->{by_nickname} } ) {
	if ( $self->is_operator($user) ) {
	   $no_of_ops++;
	}
    }
    $self->send_output_to_client( $wheel_id, { command => '252', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $no_of_ops, 'operator(s) online' ] } ) if ( $no_of_ops > 0 );
    # Number of channels
    if ( scalar ( keys %{ $self->{State}->{Channels} } ) > 0 ) {
       $self->send_output_to_client( $wheel_id, { command => '254', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), scalar ( keys %{ $self->{State}->{Channels} } ), 'channels formed' ] } );
    }
    my ($rpl_luserme) = 'I have ' . scalar ( keys %{ $self->{Clients} } ) . ' clients and ' . scalar ( keys %{ $self->{Servers} } ) . ' servers';
    $self->send_output_to_client( $wheel_id, { command => '255', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $rpl_luserme ] } );
  }
}

sub ircd_client_version {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( ( not defined ( $input->{params}->[0] ) or $input->{params}->[0] eq "" ) or uc ( $input->{params}->[0] ) eq uc ( $self->{Config}->{ServerName} ) ) {
	#RPL_VERSION
	$self->send_output_to_client( $wheel_id, { command => '351', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->{Config}->{Version}, $self->{Config}->{ServerName} ] } );
	last SWITCH;
    }
    if ( ( defined ( $input->{params}->[0] ) and $input->{params}->[0] ne "" ) and not $self->server_exists($input->{params}->[0]) ) {
	#ERR_NOSUCHSERVER
	$self->send_output_to_client($wheel_id,'402',$input->{params}->[0]);
	last SWITCH;
    }
    # TODO: Send VERSION request to the appropriate server
  }
}

sub ircd_client_time {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( defined ( $input->{params} ) and scalar ( @{ $input->{params} } ) >= 1 and ( not $self->is_server_me($input->{params}->[0],$wheel_id) ) and ( not $self->server_exists($input->{params}->[0]) ) ) {
	#ERR_NOSUCHSERVER
	$self->send_output_to_client($wheel_id,'402',$input->{params}->[0]);
	last SWITCH;
    }
    if ( defined ( $input->{params} ) and scalar ( @{ $input->{params} } ) >= 1 and ( not $self->is_server_me($input->{params}->[0],$wheel_id) ) and ( $self->server_exists($input->{params}->[0]) ) ) {
	# TODO: Forward request to appropriate server
	last SWITCH;
    }
    #RPL_TIME
    $self->send_output_to_client( $wheel_id, { command => '391', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->server_name(), $self->current_time() ] } );
  }
}

sub ircd_client_userhost {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( ( not defined ( $input->{params}->[0] ) ) or $input->{params}->[0] eq "" ) {
	#ERR_NEEDMOREPARAMS
	$self->send_output_to_client($wheel_id,'461',$input->{command});
 	last SWITCH;
    }
    my (@reply);
    foreach my $nick ( @{ $input->{params} } ) {
	if ( $self->nick_exists($nick) ) {
	  push ( @reply, $self->{State}->{by_nickname}->{ u_irc ( $nick ) }->{NickName} . ( $self->is_operator($nick) ? '*' : '' ) . '=' . ( $self->is_user_away($nick) ? '-' : '+' ) . $self->{State}->{by_nickname}->{ u_irc ( $nick ) }->{UserName} . '@' . $self->{State}->{by_nickname}->{ u_irc ( $nick ) }->{HostName} );
	}
    }
    $self->send_output_to_client( $wheel_id, { command => '302', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), ( scalar ( @reply ) > 0 ? join(' ',@reply) : ':' ) ] } );
  }
}

sub ircd_client_ping {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( ( not defined ( $input->{params}->[0] ) ) or $input->{params}->[0] eq "" ) {
	$self->send_output_to_client($wheel_id,'409');
	last SWITCH;
    }
    if ( ( defined ( $input->{params}->[0] ) and $input->{params}->[0] ne "" ) and ( defined ( $input->{params}->[1] ) and not $self->server_exists($input->{params}->[1]) ) and not $self->is_server_me($input->{params}->[1],$wheel_id) ) {
	$self->send_output_to_client($wheel_id,'402',$input->{params}->[1]);
	last SWITCH;
    }
    if ( ( ( defined ( $input->{params}->[0] ) ) and $input->{params}->[0] ne "" ) and ( defined ( $input->{params}->[1] ) and $input->{params}->[1] ne "" ) and ( not $self->is_server_me($input->{params}->[1],$wheel_id) ) ) {
	# TODO: Forward the PING to the appropriate server.
	# Replace $input->{params}->[0] with the user's nickname.
	last SWITCH;
    }
    $self->send_output_to_client( $wheel_id, { command => 'PONG', params => [ ( defined ( $input->{params}->[1] ) ? $input->{params}->[1] : $self->server_name() ), ':' . $input->{params}->[0] ] } );
  }
}

sub ircd_client_pong {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( ( not defined ( $input->{params}->[0] ) ) or $input->{params}->[0] eq "" ) {
	$self->send_output_to_client($wheel_id,'409');
	last SWITCH;
    }
    if ( ( ( defined ( $input->{params}->[0] ) ) and $input->{params}->[0] ne "" ) and ( defined ( $input->{params}->[1] ) and ( ( not $self->server_exists($input->{params}->[1]) ) and $input->{params}->[1] ne $self->{Clients}->{ $wheel_id }->{SockAddr} ) ) ) {
	$self->send_output_to_client($wheel_id,'402',$input->{params}->[1]);
	last SWITCH;
    }
    if ( ( ( defined ( $input->{params}->[0] ) ) and $input->{params}->[0] ne "" ) and ( defined ( $input->{params}->[1] ) and $input->{params}->[1] ne "" ) and ( uc ( $input->{params}->[1] ) ne uc ( $self->{Config}->{ServerName} ) and $input->{params}->[1] ne $self->{Clients}->{ $wheel_id }->{SockAddr} ) ) {
	# TODO: Forward the PING to the appropriate server.
	# Replace $input->{params}->[0] with the user's nickname.
	last SWITCH;
    }
    # TBH: We have already dealt with updating {SeenTraffic} in connection_input so nothing to do here.
  }
}

sub ircd_client_list {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( defined ( $input->{params} ) and scalar ( @{ $input->{params} } ) >= 2 and ( not $self->is_server_me($input->{params}->[1],$wheel_id) ) and ( not $self->server_exists($input->{params}->[1]) ) ) {
	#ERR_NOSUCHSERVER
	$self->send_output_to_client($wheel_id,'402',$input->{params}->[1]);
	last SWITCH;
    }
    if ( defined ( $input->{params} ) and scalar ( @{ $input->{params} } ) >= 2 and ( not $self->is_server_me($input->{params}->[1],$wheel_id) ) and ( $self->server_exists($input->{params}->[1]) ) ) {
	# TODO: Forward request to appropriate server
	last SWITCH;
    }
    my (@channels);
    if ( defined ( $self->{params}->[0] ) and $self->{params}->[0] ne "" ) {
	@channels = split(/,/,$input->{params}->[0]);
    } else {
	@channels = keys %{ $self->{State}->{Channels} };
    }
    foreach my $channel ( @channels ) {
	if ( $self->channel_exists($channel) and $self->is_channel_visible_to_nickname($channel,$nickname) ) {
	  #RPL_LIST
	  $self->send_output_to_client( $wheel_id, { command => '322', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->channel_name( $channel ), scalar ( keys %{ $self->{State}->{Channels}->{ u_irc ( $channel ) }->{Members} } ), ( $self->{State}->{Channels}->{ u_irc ( $channel ) }->{Topic} ? $self->{State}->{Channels}->{ u_irc ( $channel ) }->{Topic} : ':' ) ] } );
	}
    }
    #RPL_ENDOFLIST
    $self->send_output_to_client( $wheel_id, { command => '323', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), 'End of LIST' ] } );
  }
}

sub ircd_client_admin {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( defined ( $input->{params} ) and scalar ( @{ $input->{params} } ) >= 1 and ( not $self->is_server_me($input->{params}->[0],$wheel_id) ) and ( not $self->server_exists($input->{params}->[0]) ) ) {
	#ERR_NOSUCHSERVER
	$self->send_output_to_client($wheel_id,'402',$input->{params}->[0]);
	last SWITCH;
    }
    if ( defined ( $input->{params} ) and scalar ( @{ $input->{params} } ) >= 1 and ( not $self->is_server_me($input->{params}->[0],$wheel_id) ) and ( $self->server_exists($input->{params}->[0]) ) ) {
	# TODO: Forward request to appropriate server
	last SWITCH;
    }
    if ( ( not defined ( $self->{Config}->{Admin} ) ) or scalar ( @{ $self->{Config}->{Admin} } ) == 0 ) {
	$self->send_output_to_client($wheel_id,'423',$self->server_name());
	last SWITCH;
    }
    #RPL_ADMINME
    $self->send_output_to_client( $wheel_id, { command => '256', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->server_name(), 'Administrative Info' ] } );
    #RPL_ADMINLOC1
    $self->send_output_to_client( $wheel_id, { command => '257', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->{Config}->{Admin}->[0] ] } );
    #RPL_ADMINLOC2
    $self->send_output_to_client( $wheel_id, { command => '258', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->{Config}->{Admin}->[1] ] } );
    #RPL_ADMINEMAIL
    $self->send_output_to_client( $wheel_id, { command => '259', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->{Config}->{Admin}->[2] ] } );
  }
}

sub ircd_client_stats {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( scalar ( @{ $input->{params} } ) > 1 and $input->{params}->[1] ne '' and ( not $self->is_server_me($input->{params}->[1],$wheel_id) ) and ( not $self->server_exists($input->{params}->[1]) ) ) {
	#ERR_NOSUCHSERVER
	$self->send_output_to_client($wheel_id,'402',$input->{params}->[1]);
	last SWITCH;
    }
    if ( scalar ( @{ $input->{params} } ) > 1 and $input->{params}->[1] ne '' and ( not $self->is_server_me($input->{params}->[1],$wheel_id) ) and ( $self->server_exists($input->{params}->[1]) ) ) {
	# TODO: Forward request to the appropriate server
	last SWITCH;
    }
    my ($query) = '*';
    if ( $input->{params}->[0] =~ /^([lmou])/ ) {
	$query = $1;
	SWITCH2: {
	  if ( $query eq 'm' ) {
		#RPL_STATSCOMMANDS
		foreach my $cmd ( keys %{ $self->{Cmd_Usage} } ) {
		  $self->send_output_to_client( $wheel_id, { command => '212', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $cmd, $self->{Cmd_Usage}->{ $cmd } ] } );
		}
		last SWITCH2;
	  }
	  if ( $query eq 'u' ) {
	        $self->send_output_to_client( $wheel_id, { command => '242', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), timestring($self->{StartTime}) ] } );
	  }
	}
    }
    $self->send_output_to_client( $wheel_id, { command => '219', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $query, 'End of STATS report' ] } );
  }
}

sub ircd_client_info {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( defined ( $input->{params} ) and scalar ( @{ $input->{params} } ) >= 1 and ( not $self->is_server_me($input->{params}->[0],$wheel_id) ) and ( not $self->server_exists($input->{params}->[0]) ) ) {
	#ERR_NOSUCHSERVER
	$self->send_output_to_client($wheel_id,'402',$input->{params}->[0]);
	last SWITCH;
    }
    if ( defined ( $input->{params} ) and scalar ( @{ $input->{params} } ) >= 1 and ( not $self->is_server_me($input->{params}->[0],$wheel_id) ) and ( $self->server_exists($input->{params}->[0]) ) ) {
	# TODO: Forward request to appropriate server
	last SWITCH;
    }
    foreach my $infoline ( @{ $self->{Config}->{Info} } ) {
	#RPL_INFO
	$self->send_output_to_client( $wheel_id, { command => '371', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), ( $infoline =~ / / ? $infoline : ':' . $infoline ) ] } );
    }
    #RPL_ENDOFINFO
    $self->send_output_to_client( $wheel_id, { command => '374', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), 'End of INFO list' ] } );
  }
}

sub ircd_client_ison {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( scalar ( @{ $input->{params} } ) == 0 ) {
	#ERR_NEEDMOREPARAMS
	$self->send_output_to_client($wheel_id,'461',$input->{command});
	last SWITCH;
    }
    my (@reply);
    foreach my $query ( @{ $input->{params} } ) {
	if ( $self->nick_exists($query) ) {
	  push ( @reply, $self->{State}->{by_nickname}->{ u_irc ( $query ) }->{NickName} );
	}
    }
    $self->send_output_to_client( $wheel_id, { command => '303', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), ( scalar ( @reply ) > 0 ? join(' ',@reply) : ':' ) ] } );
  }
}

sub client_registered {
  my ($kernel,$self,$wheel_id) = @_[KERNEL,OBJECT,ARG0];

  my ($numeric) = $self->generate_client_numeric();
  my ($result) = $self->client_matches_i_line( $wheel_id );
  SWITCH: {
    if ( not defined ( $self->{Connections}->{ $wheel_id } ) ) {
	last SWITCH;
    }
    if ( $result == 0 ) {
	# ERROR :Closing Link: Flibble[chris@192.168.1.89] (Unauthorized connection)
	$self->{Connections}->{ $wheel_id }->{INVALID_PASSWORD} = 1;
	$self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => 'ERROR', params => [ 'Closing Link: ' . $self->client_nickname($wheel_id) . '[' . $self->{Connections}->{ $wheel_id }->{UserName} . '@' . $self->{Connections}->{ $wheel_id }->{PeerAddr} . '] (Unauthorised connection)' ] } );
	last SWITCH;
    }
    if ( $result == -1 ) {
	$self->{Connections}->{ $wheel_id }->{INVALID_PASSWORD} = 1;
	$self->{Connections}->{ $wheel_id }->{Wheel}->put( { command => '464', prefix => $self->{Config}->{ServerName}, params => [ $self->client_nickname($wheel_id), 'Password incorrect' ] } );
	last SWITCH;
    }
    if ( $self->state_client_registered($wheel_id) ) {
      my ($nickname) = $self->client_nickname($wheel_id);
      $self->send_output_to_client( $wheel_id, { command => '001', prefix => $self->server_name(), params => [ $nickname, 'Welcome to ' . $self->irc_network() . ' Internet Relay Chat Network ' . $self->nick_long_form($nickname) ] } );
      $self->send_output_to_client( $wheel_id, { command => '002', prefix => $self->server_name(), params => [ $nickname, 'Your host is ' . $self->server_name() . ' running ' . $self->server_version() ] } );
      $self->send_output_to_client( $wheel_id, { command => '003', prefix => $self->server_name(), params => [ $nickname, 'This server was created ' . $self->server_created() ] } );
      $self->send_output_to_client( $wheel_id, { command => '004', prefix => $self->server_name, params => [ $nickname, $self->server_name(), $self->server_version(), 'aiow', 'ablkmnopstv' ] } );
      $kernel->post ( $self->{Alias} => 'ircd_client_motd' => { command => 'MOTD' } => $wheel_id );
      $kernel->post ( $self->{Alias} => 'ircd_client_lusers' => { command => 'LUSERS' } => $wheel_id );
      if ( not defined ( $self->{Clients}->{ $wheel_id }->{PING} ) ) {
	$self->{Clients}->{ $wheel_id }->{PING} = $kernel->delay_set ( 'client_ping' => $self->lowest_ping_frequency() => $wheel_id );
      } else {
	$kernel->alarm_adjust ( $self->{Clients}->{ $wheel_id }->{PING} => $self->lowest_ping_frequency() );
      }
      # TODO: Announce new client to other servers.
    }
  }
}

sub server_registered {
  my ($kernel,$self,$wheel_id) = @_[KERNEL,OBJECT,ARG0];
}

sub ircd_server_wallops {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    foreach my $cl_wid ( keys %{ $self->{Clients} } ) {
	if ( $self->has_wallops( $self->{Clients}->{ $cl_wid }->{NickName} ) ) {
	  $self->{Clients}->{ $cl_wid }->{Wheel}->put( $input );
	}
    }
    # TODO: Send WALLOPS to all connected servers.
  }
}

# Our API with other sessions. So they can create nicks and interact with channels and stuff.

sub validate_sender {
  my ($self) = shift;
  my ($sender) = shift || return 0;
  my ($nickname) = u_irc ( shift ) || return 0;

  if ( not defined ( $self->{Sessions}->{ $sender } ) ) {
	return 0;
  }
  if ( defined ( $self->{Sessions}->{ $sender }->{ $nickname } ) ) {
	return 1;
  }
  return 0;
}

sub cmd_input {
  my ($kernel,$self,$sender,$state) = @_[KERNEL,OBJECT,SENDER,STATE];

  SWITCH: {
    if ( $state =~ /^SERVER_/i ) {
	my ($input) = $self->{ircd_filter}->get([ join ( ' ',uc ( (split(/_/,$state))[1] ),@_[ARG0..$#_] ) ]);
	$kernel->call( $self->{Alias} => 'cmd_' . $state => $sender => $input );
	last SWITCH;
    }
    if ( $state eq 'client_register' ) {
	$kernel->call( $self->{Alias} => 'cmd_client_register' => $sender => @_[ARG0..$#_] );
	last SWITCH;
    }
    # Everything else requires that the sender has registered a client
    if ( $self->validate_sender($sender,$_[ARG0]) ) {
	$kernel->call( $self->{Alias} => 'cmd_' . $state => $sender => $self->{ircd_filter}->put([ join ( ' ', $_[ARG0], (split(/_/,$state))[1], @_[ARG1..$#_] ) ]) );
	last SWITCH;
    }
  }
}

sub cmd_server_mode {
  my ($kernel,$self,$sender,$inputarg) = @_[KERNEL,OBJECT,ARG0,ARG1];

  my ($input) = shift(@$inputarg);
  SWITCH: {
    if ( not $self->channel_exists($input->{params}->[0]) ) {
	last SWITCH;
    }
    my ($parsed_mode) = parse_mode_line( @{ $input->{params} }[1 .. $#{ $input->{params} } ] );
    my ($current); my ($reply); my (@reply_args); my ($errply);
    $current = $self->channel_mode( $input->{params}->[0] );
    while ( my $mode = shift ( @{ $parsed_mode->{modes} } ) ) {
	if ( $mode !~ /[aboviklntmps]/ ) {
	   (undef,$errply) = split (//,$mode) if ( not defined ( $errply ) );
	   next;
	}
	my ($arg);
	$arg = shift ( @{ $parsed_mode->{args} } ) if ( $mode =~ /^(\+[ovklb]|-[ovb])/ );
	SWITCH33: {
	  if ( $mode =~ /^(\+|-)([ov])/ and not defined ( $arg ) ) {
		last SWITCH33;
	  }
	  if ( $mode =~ /^\+[lk]/ and not defined ( $arg ) ) {
		last SWITCH33;
	  }
	  if ( $mode =~ /^(\+|-)([ov])/ and not $self->nick_exists($arg) ) {
		last SWITCH33;
	  }
	  if ( $mode =~ /^(\+|-)([ov])/ and not $self->is_nick_on_channel($arg,$input->{params}->[0]) ) {
		last SWITCH33;
	  }
	  if ( $mode =~ /^(\+|-)([ov])/ ) {
		my ($flag) = $1; my ($char) = $2;
		if ( $flag eq '+' ) {
		   $self->{State}->{Channels}->{ u_irc ( $input->{params}->[0] ) }->{Members}->{ u_irc ( $arg ) } .= $char unless ( $self->{State}->{Channels}->{ u_irc ( $input->{params}->[0] ) }->{Members}->{ u_irc ( $arg ) } =~ /$char/ );
		} else {
		   $self->{State}->{Channels}->{ u_irc ( $input->{params}->[0] ) }->{Members}->{ u_irc ( $arg ) } =~ s/$char//;
		}
		$self->{State}->{by_nickname}->{ u_irc ( $arg ) }->{Channels}->{ u_irc ( $input->{params}->[0] ) } = $self->{State}->{Channels}->{ u_irc ( $input->{params}->[0] ) }->{Members}->{ u_irc ( $arg ) };
		$reply .= $mode;
		push ( @reply_args, $arg );
		last SWITCH33;
	  }
	  if ( $mode eq '+k' ) {
		$current .= 'k' unless ( defined ( $current ) and $current =~ /k/ );
		# TODO: Validate the channel key given.
		$self->{State}->{Channels}->{ u_irc ( $input->{params}->[0] ) }->{ChanKey} = $arg;
		$reply .= $mode;
		push ( @reply_args, $arg );
		last SWITCH33;
	  }
	  if ( $mode eq '+l' ) {
		if ( $arg =~ /[0-9]+/ and $arg > 0 ) {
		  $current .= 'l' unless ( $current =~ /l/ );
		  $self->{State}->{Channels}->{ u_irc ( $input->{params}->[0] ) }->{ChanLimit} = $arg;
		  $reply .= $mode;
		  push ( @reply_args, $arg );
		}
		last SWITCH33;
	  }
	  if ( $mode eq '+b' and not defined ( $arg ) ) {
		last SWITCH33;
	  }
	  if ( $mode eq '+b' ) {
		# Parse Banmask given and sanity check it.
		$arg =~ s/\x2a{2,}/\x2a/g;
		my (@ban); my ($remainder);
		if ( $arg !~ /\x21/ and $arg =~ /\x40/ ) {
			$remainder = $arg;
		} else {
			($ban[0],$remainder) = split (/\x21/,$arg,2);
		}
		$remainder =~ s/\x21//g if ( defined ( $remainder ) );
		@ban[1..2] = split (/\x40/,$remainder,2) if ( defined ( $remainder ) );
		$ban[2] =~ s/\x40//g if ( defined ( $ban[2] ) );
		for ( my $i = 0; $i <= 2; $i++ ) {
		   if ( ( not defined ( $ban[$i] ) ) or $ban[$i] eq '' ) {
			$ban[$i] = '*';
		   }
		}
		$arg = $ban[0] . '!' . $ban[1] . '@' . $ban[2];
		$self->{State}->{Channels}->{ u_irc ( $input->{params}->[0] ) }->{Bans}->{ $arg } = $self->nick_long_form($self->{Clients}->{ $wheel_id }->{NickName});
		$reply .= $mode;
		push ( @reply_args, $arg );
		last SWITCH33;
	  }
	  if ( $mode eq '-b' and not defined ( $arg ) ) {
		last SWITCH33;
	  }
	  if ( $mode eq '-b' ) {
		# Parse Banmask given and sanity check it.
		$arg =~ s/\x2a{2,}/\x2a/g;
		my (@ban); my ($remainder);
		if ( $arg !~ /\x21/ and $arg =~ /\x40/ ) {
			$remainder = $arg;
		} else {
			($ban[0],$remainder) = split (/\x21/,$arg,2);
		}
		$remainder =~ s/\x21//g if ( defined ( $remainder ) );
		@ban[1..2] = split (/\x40/,$remainder,2) if ( defined ( $remainder ) );
		$ban[2] =~ s/\x40//g if ( defined ( $ban[2] ) );
		for ( my $i = 0; $i <= 2; $i++ ) {
		   if ( ( not defined ( $ban[$i] ) ) or $ban[$i] eq '' ) {
			$ban[$i] = '*';
		   }
		}
		$arg = $ban[0] . '!' . $ban[1] . '@' . $ban[2];
	 	if ( defined ( $self->{State}->{Channels}->{ u_irc ( $input->{params}->[0] ) }->{Bans}->{ $arg } ) ) {
	 	  delete ( $self->{State}->{Channels}->{ u_irc ( $input->{params}->[0] ) }->{Bans}->{ $arg } );
		}
		$reply .= $mode;
		push ( @reply_args, $arg );
		last SWITCH33;
	  }
	  if ( $mode =~ /^\+([A-Za-z])$/ ) {
		$current .= $1 unless ( defined ( $current ) and $current =~ /$1/ );
		$reply .= $mode;
		last SWITCH33;
	  }
	  if ( $mode =~ /^-([A-Za-z])$/ ) {
		$current =~ s/$1//;
		$reply .= $mode;
		last SWITCH33;
	  }
	}
    }
    if ( defined ( $current ) and $current ne "" ) {
	          $current = join('',sort split(//,$current));
		  $self->{State}->{Channels}->{ u_irc ( $input->{params}->[0] ) }->{Mode} = $current;
    } else {
		  delete ( $self->{State}->{Channels}->{ u_irc ( $input->{params}->[0] ) }->{Mode} );
    }
    $reply .= ' ' . join(' ',@reply_args) if ( scalar ( @reply_args ) > 0 );
    $self->send_output_to_channel( $input->{params}->[0], { command => 'MODE', prefix => $self->server_name(), params => [ $self->channel_name( $input->{params}->[0] ), unparse_mode_line ( $reply ) ] } ) if ( defined ( $reply ) );
  }
}

sub cmd_server_kill {
  my ($kernel,$self,$sender,$inputarg) = @_[KERNEL,OBJECT,ARG0,ARG1];

  my ($input) = shift(@$inputarg);
  SWITCH: {
    if ( ( not defined ( $input->{params}->[0] ) or $input->{params}->[0] eq "" ) or ( not defined ( $input->{params}->[1] ) or $input->{params}->[1] eq "" ) ) {
	last SWITCH;
    }
    if ( $self->is_server_me($input->{params}->[0],$wheel_id) or $self->server_exists($input->{params}->[0]) ) {
	last SWITCH;
    }
    if ( not $self->nick_exists($input->{params}->[0]) ) {
	last SWITCH;
    }
    # Valid kill from an operator. Work out if local or remote kill.
    my ($victim) = u_irc ( $input->{params}->[0] );
    my ($comment) = $input->{params}->[1] || 'Server KILL';

    if ( my $victim_wheel = $self->is_my_client($victim) ) {
	$self->send_output_to_client( $victim_wheel, { command => 'KILL', prefix => $self->server_name(), params => [ $self->proper_nickname($victim), $self->server_name() . ' (' . $comment . ')' ] } );
	$self->{Clients}->{ $victim_wheel }->{LOCAL_KILL} = 1;
	$self->send_output_to_client( $victim_wheel, { command => 'ERROR', params => [ 'Closing Link: ' . $self->proper_nickname($victim) . '[' . $self->{State}->{by_nickname}->{ $victim }->{UserName} . '@' . $self->{State}->{by_nickname}->{ $victim }->{HostName} . '] ' . $self->server_name() . ' (Local kill by ' . $self->server_name() . ' (' . $comment . '))' ] } );
        $self->send_output_to_common( $victim_wheel, { command => 'QUIT', prefix => $self->nick_long_form($victim), params => [ 'Local kill by ' . $self->server_name() . ' (' . $comment . ')' ] } );
	$self->state_user_quit( $victim_wheel );
    }
    # Send KILL message for client to each server connection we have defined.
  }
}

sub cmd_server_kick {
  my ($kernel,$self,$sender,$inputarg) = @_[KERNEL,OBJECT,ARG0,ARG1];

  my ($input) = shift(@$inputarg);
  SWITCH: {
    if ( not defined ( $input->{params}->[0] ) or $input->{params}->[0] eq "" ) {
	last SWITCH;
    }
    @channels = split (/,/,$input->{params}->[0]) if ( defined ( $input->{params}->[0] ) );
    @nicknames = split (/,/,$input->{params}->[1]) if ( defined ( $input->{params}->[1] ) );
    if ( scalar ( @channels ) != scalar ( @nicknames ) and scalar ( @channels ) != 1 ) {
	last SWITCH;
    }
    my ($comment) = ( defined ( $input->{params}->[2] ) and $input->{params}->[2] ne "" ? $input->{params}->[2] : $self->server_name() );
    for ( my $i = 0; $i <= $#channels; $i++ ) {
	SWITCH2: {
	  if ( not validate_channelname ( $channels[$i] ) ) {
		last SWITCH2;
	  }
	  if ( not $self->channel_exists($channels[$i]) ) {
		last SWITCH2;
	  }
	  my ($victims);
	  if ( scalar ( @channels ) == 1 and scalar ( @nicknames ) > 1 ) {
	    $victims = \@nicknames;
	  } else {
	    $victims = [ $nicknames[$i] ];
	  }
	  foreach my $victim ( @{ $victims } ) {
	    SWITCH22: {
	      if ( not $self->is_nick_on_channel($victim,$channels[$i]) ) {
		last SWITCH22;
	      }
	      # KICK message to all channel members
	      $self->send_output_to_channel( $channels[$i], { command => 'KICK', prefix => $self->server_name(), params => [ $self->channel_name( $channels[$i] ), $self->proper_nickname( $victim ), $comment ] } );
	      $self->state_channel_part($channels[$i],$victim);
	    }
	  }
	}
    }
  }
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

sub validate_command {
  my ($command) = uc ( $_[0] )  || return 0;

  if ( scalar grep { $_ eq $command } @valid_commands ) {
	return 1;
  }
  if ( $command eq 'PRIVMSG' or $command eq 'NOTICE' ) {
	return 1;
  }
  return 0;
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

# Base64 P10 Stylee functions

# Convert decimal to Base64 optionally provide the length of the Base64 returned
sub dectobase64 {
  my ($number) = shift || 0;
  my ($output) = shift || 2;
  my ($numeric) = "";

  if ($number == 0) {
    for (my $i = length($numeric); $i < $output; $i++) {
      $numeric = "A" . $numeric;
    }
    return $numeric;
  }

  my ($b64chars) = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]";
  my (@d2b64) = split(//,$b64chars);

  my (@convert); my ($g); my ($r);

  LOOP: while (1) {
    $g = $number / 64;
    $r = $number % 64;
    if ($g >= 64) {
        $number = $g;
        push(@convert,$r);
    } else {
        push(@convert,$r);
        push(@convert,int $g);
        last LOOP;
    }
  }
  foreach (reverse @convert) {
    $numeric .= $d2b64[$_];
  }
  for (my $i = length($numeric); $i < $output; $i++) {
    $numeric = "A" . $numeric;
  }
  return $numeric;
}

# Convert from Base64 to decimal
sub base64todec {
  my ($numeric) = shift || return undef;

  my ($b64chars) = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]";
  my (@d2b64) = split(//,$b64chars);
  my (%b642d) = ();
  for (my $i = 0; $i <= $#d2b64; $i++) {
    $b642d{$d2b64[$i]} = $i;
  }

  my (@numeric) = reverse split(//,$numeric);
  my ($number) = 0;

  for (my $i=0; $i <= $#numeric; $i++) {
        $number += (64**$i) * $b642d{$numeric[$i]};
  }
  return $number;
}

# Convoluted method to convert from IP quad to Base64 /me *sighs*
sub inttobase64 {
  my ($quad) = shift || return undef;

  return dectobase64(hex(int2hex(dotq2int($quad))));
}

# The following two functions are taken from :-
# http://www.math.ucla.edu/~jimc/jvtun
# Copyright � 2003 by James F. Carter.  2003-08-02, Perl-5.8.0

sub dotq2int {
    my @dotq = split /[.\/]/, $_[0];
    push(@dotq, 32) if @dotq == 4;
    my($ip) = unpack("N", pack("C4", splice(@dotq, 0, 4)));
    my($mask) = (@dotq > 1) ? unpack("N", pack("C4", @dotq)) :
        $dotq[0] ? ~((1 << (32-$dotq[0]))-1) : 0;

    ($ip, $mask);
}

sub int2hex {
    sprintf("%08X", $_[0]);
}

# Dispatch output to registered sessions

sub dispatch_to_sessions {
  my ($self) = shift;
  my ($output) = shift || return 0;

  foreach my $session ( keys %{ $self->{sessions} } ) {
	$poe_kernel->post( $session => 'ircd_' . lc ( $output->{command} ) => $output->{prefix} => @{ $output->{params} } );
  }
}

# Dispatch output to client

sub send_output_to_client {
  my ($self) = shift;
  my ($wheel_id) = shift || return 0;
  my ($err) = shift || return 0;

  SWITCH: {
    if ( not $self->client_exists( $wheel_id ) ) {
	last SWITCH;
    }
    if ( ref $err eq 'HASH' ) {
	$self->{Clients}->{ $wheel_id }->{Wheel}->put ( $err );
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
	$self->{Clients}->{ $wheel_id }->{Wheel}->put( $input );
    }
  }
  return 1;
}

# Dispatch output to all channel members

sub send_output_to_channel {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($output) = $_[1] || return 0;

  SWITCH: {
    if ( not $self->channel_exists($channel) ) {
	last SWITCH;
    }
    if ( ref $output ne 'HASH' ) {
	last SWITCH;
    }
    foreach my $member ( $self->channel_list( $channel ) ) {
	if ( my $member_wheel = $self->is_my_client($member) ) {
	  $self->send_output_to_client( $member_wheel, $output );
	} else {
	  # FIX: create sub send_output_to_servers_channel
	}
    }
    $self->dispatch_to_sessions( $output );
    return 1;
  }
  return 0;
}

sub send_channel_message {
  my ($self) = shift;
  my ($wheel_id) = shift || return 0;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($output) = $_[1] || return 0;
  my ($nickname) = u_irc ( $self->client_nickname($wheel_id) );

  SWITCH: {
    if ( not $self->channel_exists($channel) ) {
	last SWITCH;
    }
    if ( ref $output ne 'HASH' ) {
	last SWITCH;
    }
    foreach my $member ( $self->channel_list( $channel ) ) {
	if ( my $member_wheel = $self->is_my_client($member) and $member ne $nickname ) {
	  $self->send_output_to_client( $member_wheel, $output );
	} else {
	  # FIX: create sub send_output_to_servers_channel
	}
    }
    return 1;
  }
}

# for QUIT and NICK messages

sub send_output_to_common {
  my ($self) = shift;
  my ($wheel_id) = shift || return 0;
  my ($output) = $_[0] || return 0;

  if ( ( not $self->client_exists( $wheel_id ) ) or ref $output ne 'HASH' ) {
	return 0;
  }
  my (%common);
  if ( defined ( $output->{command} ) and uc ( $output->{command} ) ne 'QUIT' ) {
	$self->send_output_to_client( $wheel_id, $output );
  }
  foreach my $channel ( $self->nick_channel_list( $self->client_nickname($wheel_id) ) ) {
     foreach my $member ( $self->channel_list($channel) ) {
	next if ( $member eq u_irc ( $self->client_nickname($wheel_id) ) );
	if ( my $member_wheel = $self->is_my_client($member) ) {
	   $self->send_output_to_client( $member_wheel, $output );
	}
     }
  }
  return 1;
}

# Various object methods for altering the STATE

sub state_client_registered {
  my ($self) = shift;
  my ($wheel_id) = $_[0] || return 0;

  if ( not defined ( $self->{Connections}->{ $wheel_id } ) ) {
	return 0;
  }
  delete ( $self->{Clients}->{ $wheel_id } );
  foreach my $value ( keys %{ $self->{Connections}->{ $wheel_id } } ) {
	$self->{Clients}->{ $wheel_id }->{ $value } = $self->{Connections}->{ $wheel_id }->{ $value };
  }
  delete ( $self->{Connections}->{ $wheel_id } );
  $self->{Clients}->{ $wheel_id }->{SignOn} = time();
  my ($nickname) = $self->{Clients}->{ $wheel_id }->{ProperNick};
  $self->{State}->{by_nickname}->{ u_irc ( $nickname ) }->{NickName} = $nickname;
  if ( defined ( $self->{Clients}->{ $wheel_id }->{Auth}->{Ident} ) and $self->{Clients}->{ $wheel_id }->{Auth}->{Ident} ne '' ) {
      $self->{State}->{by_nickname}->{ u_irc ( $nickname ) }->{UserName} = $self->{Clients}->{ $wheel_id }->{Auth}->{Ident};
  } else {
      $self->{State}->{by_nickname}->{ u_irc ( $nickname ) }->{UserName} = $self->{Clients}->{ $wheel_id }->{UserName};
  }
  if ( defined ( $self->{Clients}->{ $wheel_id }->{Auth}->{HostName} ) and $self->{Clients}->{ $wheel_id }->{Auth}->{HostName} ne '' and $self->{Clients}->{ $wheel_id }->{PeerAddr} !~ /^127\./ ) {
      $self->{State}->{by_nickname}->{ u_irc ( $nickname ) }->{HostName} = $self->{Clients}->{ $wheel_id }->{Auth}->{HostName};
  } else {
      $self->{State}->{by_nickname}->{ u_irc ( $nickname ) }->{HostName} = ( $self->{Clients}->{ $wheel_id }->{PeerAddr} =~ /^127\./ ? $self->{Config}->{ServerName} : $self->{Clients}->{ $wheel_id }->{PeerAddr} );
  }
  $self->{State}->{by_nickname}->{ u_irc ( $nickname ) }->{RealName} = $self->{Clients}->{ $wheel_id }->{RealName};
  $self->{State}->{by_nickname}->{ u_irc ( $nickname ) }->{Wheel} = $wheel_id;
  $self->{State}->{by_nickname}->{ u_irc ( $nickname ) }->{ServerName} = $self->server_name();
  $self->{State}->{by_nickname}->{ u_irc ( $nickname ) }->{HopCount} = 0;
  $self->{State}->{by_nickname}->{ u_irc ( $nickname ) }->{TimeStamp} = $self->{Clients}->{ $wheel_id }->{SignOn};
  return 1;
}

sub state_user_quit {
  my ($self) = shift;
  my ($wheel_id) = $_[0] || return 0;

  if ( not $self->client_exists($wheel_id) ) {
	return 0;
  }
  my ($nickname) = u_irc ( $self->client_nickname($wheel_id) );
  foreach my $channel ( $self->nick_channel_list($nickname) ) {
	$self->state_channel_part($channel,$nickname);
  }
  delete ( $self->{State}->{by_nickname}->{ $nickname } );
}

sub state_nick_change {
  my ($self) = shift;
  my ($oldnick) = u_irc ( $_[0] ) || return undef;
  my ($nickname) = $_[1] || return '431';

  if ( not $nickname ) {
	return '431';
  }
  if ( not validate_nickname($nickname) ) {
	return '432';
  }
  if ( $self->nick_exists($nickname) and $oldnick ne u_irc ( $nickname ) ) {
	return '433';
  }
  if ( $self->proper_nickname($oldnick) eq $nickname ) {
	return undef;
  }
  if ( $oldnick eq u_irc ( $nickname ) ) {
	$self->{State}->{by_nickname}->{ $oldnick }->{NickName} = $nickname;
	return 1;
  }
  $self->{Clients}->{ $self->is_my_client($oldnick) }->{NickName} = u_irc ( $nickname );
  my $record = delete ( $self->{State}->{by_nickname}->{ $oldnick } );
  $record->{NickName} = $nickname;
  $record->{TimeStamp} = time();
  foreach my $channel ( keys %{ $record->{Channels} } ) {
	$self->{State}->{Channels}->{ $channel }->{Members}->{ u_irc ( $nickname ) } = delete ( $self->{State}->{Channels}->{ $channel }->{Members}->{ $oldnick } );
  }
  $self->{State}->{by_nickname}->{ u_irc ( $nickname ) } = $record;
  return 1;
}

sub state_topic_set {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($topic) = $_[1] || return 0;

  if ( not $self->channel_exists($channel) ) {
	return 0;
  }
  if ( $topic eq "" ) {
    delete ( $self->{State}->{Channels}->{ $channel }->{Topic} );
    delete ( $self->{State}->{Channels}->{ $channel }->{TopicBy} );
    delete ( $self->{State}->{Channels}->{ $channel }->{TopicWhen} );
  } else {
    $topic = substr( $topic,0,$self->{Config}->{TOPICLEN} ) if ( length ($topic) > $self->{Config}->{TOPICLEN} );
    $self->{State}->{Channels}->{ $channel }->{Topic} = $topic;
  }
  return 1;
}

sub state_topic_set_by {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($nickname) = u_irc ( $_[1] ) || return 0;

  if ( ( not $self->channel_exists($channel) ) or ( not $self->nick_exists($nickname) ) ) {
	return 0;
  }
  $self->{State}->{Channels}->{ $channel }->{TopicBy} = $self->nick_long_form($nickname);
  $self->{State}->{Channels}->{ $channel }->{TopicWhen} = time();
  return 1;
}

sub state_channel_join {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($nickname) = u_irc ( $_[1] ) || return 0;

  if ( not $self->nick_exists($nickname) ) {
	return 0;
  }
  if ( $self->channel_exists($channel) and $self->is_channel_member($channel,$nickname) ) {
	return 0;
  }
  my ($mode) = '';
  if ( ( not $self->channel_exists($channel) ) and ( not $self->is_reserved_channel($channel) ) and $channel !~ /^\x2B/ ) {
	$self->{State}->{Channels}->{ $channel }->{ChannelName} = $_[0];
	$self->{State}->{Channels}->{ $channel }->{TimeStamp} = time();
	$mode = 'o';
  }
  if ( ( not $self->channel_exists($channel) ) and $channel =~ /^\x2B/ ) {
	$self->{State}->{Channels}->{ $channel }->{ChannelName} = $_[0];
	$self->{State}->{Channels}->{ $channel }->{TimeStamp} = time();
  }
  if ( my $channelname = $self->is_reserved_channel($channel) ) {
	$self->{State}->{Channels}->{ $channel }->{ChannelName} = $channelname;
	$self->{State}->{Channels}->{ $channel }->{TimeStamp} = $self->{StartTime};
	$self->{State}->{Channels}->{ $channel }->{Mode} = 'mnt';
  }
  $self->{State}->{Channels}->{ $channel }->{Members}->{ $nickname } = $mode;
  $self->{State}->{by_nickname}->{ $nickname }->{Channels}->{ $channel } = $mode;
  $self->state_del_invite($channel,$nickname);
  return 1;
}

sub state_channel_part {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($nickname) = u_irc ( $_[1] ) || return 0;

  if ( ( not $self->channel_exists($channel) ) or ( not $self->nick_exists($nickname) ) ) {
	return 0;
  }
  delete ( $self->{State}->{Channels}->{ u_irc ( $channel ) }->{Members}->{$nickname} );
  delete ( $self->{State}->{by_nickname}->{ $nickname }->{Channels}->{ u_irc ( $channel ) } );
  if ( $self->is_channel_empty($channel) ) {
	delete ( $self->{State}->{Channels}->{ u_irc ( $channel ) } );
  }
  return 1;
}

sub state_channel_mode {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return undef;
  my ($mode) = $_[1] || return undef;
  my ($arg) = $_[2];
  my (@reply);

  if ( not $self->channel_exists($channel) ) {
	return undef;
  }
  my ($current) = $self->channel_mode( $channel );
  SWITCH33: {
	  if ( $mode eq '+k' and ( defined ( $arg ) and $arg ne '' ) ) {
		$current .= 'k' unless ( defined ( $current ) and $current =~ /k/ );
		# TODO: Validate the channel key given.
		$self->{State}->{Channels}->{ $channel }->{ChanKey} = $arg;
		push(@reply,$mode,$arg);
		last SWITCH33;
	  }
	  if ( $mode eq '+l' and ( defined ( $arg ) and $arg ne '' ) ) {
		if ( $arg =~ /[0-9]+/ and $arg > 0 ) {
		  $current .= 'l' unless ( defined ( $current ) and $current =~ /l/ );
		  $self->{State}->{Channels}->{ $channel }->{ChanLimit} = $arg;
		  push(@reply,$mode,$arg);
		}
		last SWITCH33;
	  }
	  if ( $mode eq '-k' ) {
		$current =~ s/k// unless ( ( not defined ( $current ) ) or $current !~ /k/ );
		my ( $result ) = delete ( $self->{State}->{Channels}->{ $channel }->{ChanKey} );
		if ( $result ) {
		   push(@reply,$mode,$arg);
		}
		last SWITCH33;
	  }
	  if ( $mode eq '-l' ) {
		$current =~ s/l// unless ( ( not defined ( $current ) ) or $current !~ /l/ );
		my ( $result ) = delete ( $self->{State}->{Channels}->{ $channel }->{ChanLimit} );
		if ( $result ) {
		   push(@reply,$mode,$arg);
		}
		last SWITCH33;
	  }
	  if ( $mode eq '-b' and ( defined ( $arg ) and $arg ne '' ) ) {
		# Parse Banmask given and sanity check it.
		$arg =~ s/\x2a{2,}/\x2a/g;
		my (@ban); my ($remainder);
		if ( $arg !~ /\x21/ and $arg =~ /\x40/ ) {
			$remainder = $arg;
		} else {
			($ban[0],$remainder) = split (/\x21/,$arg,2);
		}
		$remainder =~ s/\x21//g if ( defined ( $remainder ) );
		@ban[1..2] = split (/\x40/,$remainder,2) if ( defined ( $remainder ) );
		$ban[2] =~ s/\x40//g if ( defined ( $ban[2] ) );
		for ( my $i = 0; $i <= 2; $i++ ) {
		   if ( ( not defined ( $ban[$i] ) ) or $ban[$i] eq '' ) {
			$ban[$i] = '*';
		   }
		}
		$arg = $ban[0] . '!' . $ban[1] . '@' . $ban[2];
		my ( $result ) = delete ( $self->{State}->{Channels}->{ $channel }->{Bans}->{ $arg } );
		if ( $result ) {
		   push(@reply,$mode,$arg);
		}
		last SWITCH33;
	  }
	  if ( $mode eq '+b' and ( defined ( $arg ) and $arg ne '' ) ) {
		# Parse Banmask given and sanity check it.
		$arg =~ s/\x2a{2,}/\x2a/g;
		my (@ban); my ($remainder);
		if ( $arg !~ /\x21/ and $arg =~ /\x40/ ) {
			$remainder = $arg;
		} else {
			($ban[0],$remainder) = split (/\x21/,$arg,2);
		}
		$remainder =~ s/\x21//g if ( defined ( $remainder ) );
		@ban[1..2] = split (/\x40/,$remainder,2) if ( defined ( $remainder ) );
		$ban[2] =~ s/\x40//g if ( defined ( $ban[2] ) );
		for ( my $i = 0; $i <= 2; $i++ ) {
		   if ( ( not defined ( $ban[$i] ) ) or $ban[$i] eq '' ) {
			$ban[$i] = '*';
		   }
		}
		$arg = $ban[0] . '!' . $ban[1] . '@' . $ban[2];
		if ( not defined ( $self->{State}->{Channels}->{ $channel }->{Bans}->{ $arg } ) ) {
		   $self->{State}->{Channels}->{ $channel }->{Bans}->{ $arg } = time();
		   push(@reply,$mode,$arg);
		}
		last SWITCH33;
	  }
	  if ( $mode =~ /^\+([A-Za-z])$/ ) {
		$current .= $1 unless ( defined ( $current ) and $current =~ /$1/ );
		push(@reply,$mode,$arg);
		last SWITCH33;
	  }
	  if ( $mode =~ /^-([A-Za-z])$/ ) {
		$current =~ s/$1//;
		push(@reply,$mode,$arg);
		last SWITCH33;
	  }
  }
  if ( ( not defined ( $current ) ) or $current eq '' ) {
	delete ( $self->{State}->{Channels}->{ $channel }->{Mode} );
  } else {
	$current = join('',sort split(//,$current));
	$self->{State}->{Channels}->{ $channel }->{Mode} = $current;
  }
  return @reply;
}

sub state_channel_member {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return undef;
  my ($mode) = $_[1] || return undef;
  my ($arg) = $_[2] || return undef;

  if ( ( not $self->channel_exists($channel) ) or ( not $self->nick_exists($arg) ) or ( not $self->is_channel_member($channel,$arg) ) ) {
	return undef;
  }
  if ( $mode =~ /^(\+|-)([ov])/ ) {
	my ($flag) = $1; my ($char) = $2;
	if ( $flag eq '+' ) {
	   $self->{State}->{Channels}->{ $channel }->{Members}->{ u_irc ( $arg ) } .= $char unless ( $self->{State}->{Channels}->{ $channel }->{Members}->{ u_irc ( $arg ) } =~ /$char/ );
	} else {
	   $self->{State}->{Channels}->{ $channel }->{Members}->{ u_irc ( $arg ) } =~ s/$char//;
	}
	$self->{State}->{by_nickname}->{ u_irc ( $arg ) }->{Channels}->{ $channel } = $self->{State}->{Channels}->{ $channel }->{Members}->{ u_irc ( $arg ) };
	return ( $mode, $arg );
  }
}

sub state_channel_key {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($chankey) = $_[1];

  if ( not $self->channel_exists($channel) ) {
	return 0;
  }
  if ( ( not defined ( $chankey ) ) or $chankey eq '' ) {
	delete ( $self->{State}->{Channels}->{ $channel }->{ChanKey} );
	return 1;
  }
  $self->{State}->{Channels}->{ $channel }->{ChanKey} = $chankey;
  return 1;
}

sub state_channel_limit {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($chanlimit) = $_[1];

  if ( not $self->channel_exists($channel) ) {
	return 0;
  }
  if ( ( not defined ( $chanlimit ) ) or $chanlimit eq '' ) {
	delete ( $self->{State}->{Channels}->{ $channel }->{ChanLimit} );
	return 1;
  }
  $self->{State}->{Channels}->{ $channel }->{ChanLimit} = $chanlimit;
  return 1;
}

sub state_add_invite {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($nickname) = u_irc ( $_[1] ) || return 0;

  if ( ( not $self->channel_exists($channel) ) or ( not $self->nick_exists($nickname) ) ) {
	return 0;
  }
  $self->{State}->{by_nickname}->{ $nickname }->{Invites}->{ $channel } = 1;
  return 1;
}

sub state_del_invite {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($nickname) = u_irc ( $_[1] ) || return 0;

  if ( ( not $self->channel_exists($channel) ) or ( not $self->nick_exists($nickname) ) ) {
	return 0;
  }
  delete ( $self->{State}->{by_nickname}->{ $nickname }->{Invites}->{ $channel } );
  return 1;
}

sub state_user_oper {
  my ($self) = shift;
  my ($nickname) = u_irc ( $_[0] ) || return undef;

  if ( not $self->nick_exists($nickname) ) {
	return undef;
  }
  my ($reply) = '+o';
  $self->{State}->{by_nickname}->{ $nickname }->{UMode} .= 'o';
  if ( $self->{State}->{by_nickname}->{ $nickname }->{UMode} !~ /w/ ) {
      $self->{State}->{by_nickname}->{ $nickname }->{UMode} .= 'w';
      $reply .= 'w';
  }
  $self->{State}->{by_nickname}->{ $nickname }->{UMode} = join('',sort(split(//,$self->{State}->{by_nickname}->{ $nickname }->{UMode})));
  return $reply;
}

sub state_user_mode {
  my ($self) = shift;
  my ($nickname) = u_irc ( $_[0] ) || return undef;

  if ( not $self->nick_exists($nickname) ) {
	return undef;
  }
  my ($parsed_mode) = parse_mode_line( @_[1 .. $#_] );
  my ($reply); my ($errply);
  my ( $current );
  $current = $self->{State}->{by_nickname}->{ $nickname }->{UMode} if ( defined ( $self->{State}->{by_nickname}->{ $nickname }->{UMode} ) );
  while ( my $mode = shift ( @{ $parsed_mode->{modes} } ) ) {
	next if ( $mode eq '+o' );
	if ( $mode !~ /[oiw]/ ) {
	   $errply = 1;
	   next;
	}
	if ( $mode =~ /^(\+|-)([A-Za-z])$/ ) {
		my ($flag) = $1; my ($char) = $2;
		SWITCH22: {
		  if ( $flag eq '+' and ( not defined ( $current ) or $current !~ /$char/ ) ) {
			$reply .= $mode;
			$current .= $char;
			last SWITCH22;
		  }
		  if ( $flag eq '-' and ( defined ( $current ) and $current =~ /$char/ ) ) {
			$reply .= $mode;
			$current =~ s/$char//;
			last SWITCH22;
		  }
		}
	}
  }
  if ( defined ( $current ) and $current ne "" ) {
          $current = join('',sort split(//,$current));
	  $self->{State}->{by_nickname}->{ $nickname }->{UMode} = $current;
  } else {
	  delete ( $self->{State}->{by_nickname}->{ $nickname }->{UMode} );
  }
  return ($reply,$errply);
}

# Various object methods for querying the STATE

sub channel_exists {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;

  if ( defined ( $self->{State}->{Channels}->{ $channel } ) ) {
	return 1;
  }
  return 0;
}

sub channel_name {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return undef;

  if ( not $self->channel_exists($channel) ) {
	return undef;
  }
  return $self->{State}->{Channels}->{ $channel }->{ChannelName};
}

sub channel_created {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return undef;

  if ( not $self->channel_exists($channel) ) {
	return undef;
  }
  return $self->{State}->{Channels}->{ $channel }->{TimeStamp};
}

sub is_channel_empty {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;

  if ( not $self->channel_exists($channel) ) {
	return 0;
  }
  if ( scalar ( keys %{ $self->{State}->{Channels}->{ $channel }->{Members} } ) == 0 ) {
	return 1;
  }
  return 0;
}

sub channel_members {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return undef;
  my (@values);
  
  if ( not $self->channel_exists($channel) ) {
	return 0;
  }
  foreach ( keys %{ $self->{State}->{Channels}->{ $channel }->{Members} } ) {
	my ($nick) = $self->{State}->{by_nickname}->{ $_ }->{NickName};
	if ( $self->is_channel_operator($channel,$_)  ) {
		push ( @values, '@' . $nick );
	} elsif ( $self->has_channel_voice($channel,$_) ) {
		push ( @values, '+' . $nick );
	} else {
		push ( @values, $nick );
	}
  }
  return @values;
}

sub channel_list {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return undef;
  
  if ( not $self->channel_exists($channel) ) {
	return undef;
  }
  return keys %{ $self->{State}->{Channels}->{ $channel }->{Members} };
}

sub channel_bans {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return undef;
  
  if ( not $self->channel_exists($channel) ) {
	return undef;
  }
  return keys %{ $self->{State}->{Channels}->{ $channel }->{Bans} };
}

sub is_channel_operator {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($nickname) = u_irc ( $_[1] ) || return 0;

  if ( not $self->channel_exists($channel) ) {
	return 0;
  }
  if ( $self->{State}->{Channels}->{ $channel }->{Members}->{ $nickname } =~ /o/ ) {
	return 1;
  }
  return 0;
}

sub has_channel_voice {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($nickname) = u_irc ( $_[1] ) || return 0;

  if ( not $self->channel_exists($channel) ) {
	return 0;
  }
  if ( $self->{State}->{Channels}->{ $channel }->{Members}->{ $nickname } =~ /v/ ) {
	return 1;
  }
  return 0;
}

sub channel_topic {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return undef;

  if ( not $self->channel_exists($channel) ) {
	return undef;
  }
  if ( not defined ( $self->{State}->{Channels}->{ $channel }->{Topic} ) ) {
	return undef;
  }
  return [ $self->{State}->{Channels}->{ $channel }->{Topic}, $self->{State}->{Channels}->{ $channel }->{TopicBy}, $self->{State}->{Channels}->{ $channel }->{TopicWhen} ];
}

sub is_operator {
  my ($self) = shift;
  my ($nickname) = u_irc ( $_[0] ) || return 0;

  if ( not $self->nick_exists($nickname) ) {
	return 0;
  }
  if ( defined ( $self->{State}->{by_nickname}->{ $nickname }->{UMode} ) and $self->{State}->{by_nickname}->{ $nickname }->{UMode}  =~ /o/ ) {
	return 1;
  }
  return 0;
}

sub list_channels {
  my ($self) = shift;
  my (@values);

  foreach ( keys %{ $self->{State}->{Channels} } ) {
	push ( @values, $self->{State}->{Channels}->{ $_ }->{ChannelName} );
  }
  return @values;
}

sub is_channel_member {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($nickname) = u_irc ( $_[1] ) || return 0;

  if ( ( not $self->channel_exists($channel) ) or ( not $self->nick_exists($nickname) ) ) {
	return 0;
  }
  if ( defined ( $self->{State}->{Channels}->{ $channel }->{Members}->{ $nickname } ) ) {
	return 1;
  }
  return 0;
}

sub is_channel_mode_set {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($mode) = $_[1] || return 0;

  unless ( length ($mode) == 1 ) {
	return 0;
  }

  if ( not $self->channel_exists($channel) ) {
	return 0;
  }
  if ( defined ( $self->{State}->{Channels}->{ $channel }->{Mode} ) and $self->{State}->{Channels}->{ $channel }->{Mode} =~ /$mode/ ) {
	return 1;
  }
  return 0;
}

sub channel_mode {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return undef;

  if ( not $self->channel_exists($channel) ) {
	return undef;
  }
  return $self->{State}->{Channels}->{ $channel }->{Mode};
}

sub channel_limit {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return undef;

  if ( not $self->channel_exists($channel) ) {
	return undef;
  }
  return $self->{State}->{Channels}->{ $channel }->{ChanLimit};
}

sub channel_key {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return undef;

  if ( not $self->channel_exists($channel) ) {
	return undef;
  }
  return $self->{State}->{Channels}->{ $channel }->{ChanKey};
}

sub is_user_banned_from_channel {
  my ($self) = shift;
  my ($nickname) = u_irc ( $_[0] ) || return 0;
  my ($channel) = u_irc ( $_[1] ) || return 0;
  my ($fulluser) = u_irc ( $self->nick_long_form($nickname) );

  if ( not $self->channel_exists($channel) ) {
	return 0;
  }
  if ( ( not defined ( $self->{State}->{Channels}->{ $channel }->{Bans} ) ) or scalar ( keys %{ $self->{State}->{Channels}->{ $channel }->{Bans} } ) == 0 ) {
	return 0;
  }
  foreach my $ban ( keys %{ $self->{State}->{Channels}->{ $channel }->{Bans} } ) {
    # From RFC ? == [\x01-\xFF]{1,1} * == [\x01-\xFF]* @ would be \x2A
    $ban = u_irc ( $ban );
    $ban =~ s/\*/[\x01-\xFF]{0,}/g;
    $ban =~ s/\?/[\x01-\xFF]{1,1}/g;
    $ban =~ s/\@/\x40/g;
    if ( $fulluser =~ /^$ban$/ ) {
	return 1;
    }
  }
  return 0;
}

sub is_channel_visible_to_nickname {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($nickname) = u_irc ( $_[1] ) || return 0;

  if ( not $self->channel_exists($channel) ) {
	return 0;
  }
  if ( $self->is_channel_member($channel,$nickname) ) {
	return 1;
  }
  if ( ( not $self->is_channel_mode_set($channel,'s') ) and ( not $self->is_channel_mode_set($channel,'p') ) and ( not $self->is_channel_mode_set($channel,'a') ) ) {
	return 1;
  }
  return 0;
}

sub is_nickname_visible {
  my ($self) = shift;
  my ($nickname) = u_irc ( $_[0] ) || return 0;

  if ( not $self->nick_exists($nickname) ) {
	return 0;
  }
  if ( ( not defined ( $self->{State}->{by_nickname}->{ $nickname }->{UMode} ) ) or $self->{State}->{by_nickname}->{ $nickname }->{UMode} !~ /i/ ) {
	return 1;
  }
  return 0;
}

sub users_not_on_channels {
  my ($self) = shift;
  my (@values);

  foreach ( keys %{ $self->{State}->{by_nickname} } ) {
    if ( not defined ( $self->{State}->{by_nickname}->{ $_ }->{Channels} ) or scalar( keys %{ $self->{State}->{by_nickname}->{ $_ }->{Channels} } ) == 0 ) {
	push ( @values, $self->{State}->{by_nickname}->{ $_ }->{NickName} );
    }
  }
  return @values;
}

sub nick_exists {
  my ($self) = shift;
  my ($nickname) = u_irc ( $_[0] ) || return 0;

  if ( defined ( $self->{State}->{by_nickname}->{ $nickname } ) ) {
	return 1;
  }
  return 0;
}

sub nick_channel_list {
  my ($self) = shift;
  my ($nickname) = u_irc ( $_[0] ) || return undef;

  if ( not $self->nick_exists($nickname) ) {
	return undef;
  }
  return keys %{ $self->{State}->{by_nickname}->{ $nickname }->{Channels} };
}

sub is_user_away {
  my ($self) = shift;
  my ($nickname) = u_irc ( $_[0] ) || return 0;

  if ( not $self->nick_exists($nickname) ) {
	return 0;
  }
  if ( defined ( $self->{State}->{by_nickname}->{ $nickname }->{UMode} ) and $self->{State}->{by_nickname}->{ $nickname }->{UMode} =~ /a/ ) {
	return 1;
  }
  return 0;
}

sub has_wallops {
  my ($self) = shift;
  my ($nickname) = u_irc ( $_[0] ) || return 0;

  if ( not $self->nick_exists($nickname) ) {
	return 0;
  }
  if ( defined ( $self->{State}->{by_nickname}->{ $nickname }->{UMode} ) and $self->{State}->{by_nickname}->{ $nickname }->{UMode} =~ /w/ ) {
	return 1;
  }
  return 0;
}

sub is_nick_on_channel {
  my ($self) = shift;
  my ($nickname) = u_irc ( $_[0] ) || return 0;
  my ($channel) = u_irc ( $_[1] ) || return 0;
  
  if ( ( not $self->channel_exists($channel) ) or ( not $self->nick_exists($nickname) ) ) {
	return 0;
  }
  if ( defined ( $self->{State}->{Channels}->{ $channel }->{Members}->{ $nickname } ) ) {
	return 1;
  }
  return 0;
}

sub nick_long_form {
  my ($self) = shift;
  my ($nickname) = u_irc ( $_[0] ) || return undef;

  if ( not $self->nick_exists($nickname) ) {
	return 0;
  }
  return $self->{State}->{by_nickname}->{ $nickname }->{NickName} . '!' . $self->{State}->{by_nickname}->{ $nickname }->{UserName} . '@' . $self->{State}->{by_nickname}->{ $nickname }->{HostName};
}

sub user_invited_to_channel {
  my ($self) = shift;
  my ($channel) = u_irc ( $_[0] ) || return 0;
  my ($nickname) = u_irc ( $_[1] ) || return 0;

  if ( ( not $self->nick_exists($nickname) ) ) {
	return 0;
  }
  if ( defined ( $self->{State}->{by_nickname}->{ $nickname }->{Invites}->{ $channel } ) ) {
	return 1;
  }
  return 0;
}

sub server_exists {
  my ($self) = shift;
  my ($server) = u_irc ( $_[0] ) || return 0;

  if ( defined ( $self->{State}->{Servers}->{ $server } ) ) {
	return 1;
  }
  $server =~ s/\*/[\x01-\xFF]{0,}/g;
  $server =~ s/\?/[\x01-\xFF]{1,1}/g;
  foreach my $servername ( keys %{ $self->{State}->{Servers} } ) {
	if ( $servername =~ /^$server$/ ) {
		return 1;
	}
  }
  return 0;
}

sub is_server_me {
  my ($self) = shift;
  my ($server) = u_irc ( $_[0] ) || return 0;
  my ($client) = $_[1] || return 0;

  if ( not $self->client_exists( $client ) ) {
	return 0;
  }
  if ( $server eq u_irc ( $self->{Config}->{ServerName} ) or $server eq $self->{Clients}->{ $client }->{SockAddr} ) {
	return 1;
  }
  return 0;
}

sub server_created {
  my ($self) = shift;

  return time2str("%a %h %d %Y at %H:%M:%S %Z",$self->{StartTime});
}

sub current_time {
  my ($self) = shift;

  return time2str("%A %B %e %Y -- %H:%M %z",time);
}

sub lowest_ping_frequency {
  my ($self) = shift;
  my ($return) = 60;
  
  foreach my $client ( keys %{ $self->{Clients} } ) {
	if ( defined ( $self->{Clients}->{ $client }->{PingFreq} ) and $self->{Clients}->{ $client }->{PingFreq} < $return ) {
		$return = $self->{Clients}->{ $client }->{PingFreq};
	}
  }
  foreach my $server ( keys %{ $self->{Servers} } ) {
	if ( defined ( $self->{Servers}->{ $server }->{PingFreq} ) and $self->{Servers}->{ $server }->{PingFreq} < $return ) {
		$return = $self->{Servers}->{ $server }->{PingFreq};
	}
  }
  return $return;
}

sub contains_wildcard {
  my ($self) = shift;
  my ($input) = $_[0] || return 0;

  if ( $input =~ /(\x2A|\x3F)/ ) {
	return 1;
  }
  return 0;
}

sub nicks_match_wildcard {
  my ($self) = shift;
  my ($input) = u_irc ( $_[0] ) || return undef;
  my (@returns);
  
  if ( $input ne "" ) {
    $input =~ s/\*/[\x01-\xFF]{0,}/g;
    $input =~ s/\?/[\x01-\xFF]{1,1}/g;
    $input =~ s/\@/\x40/g;
    $input =~ s/\^/\x5E/g;
    foreach my $nick ( keys %{ $self->{State}->{by_nickname} } ) {
	if ( $nick =~ /^$input$/ ) {
	  push ( @returns, $nick );
	}
    }
  }
  return @returns;
}

sub is_my_client {
  my ($self) = shift;
  my ($nickname) = u_irc ( $_[0] ) || return undef;

  if ( not $self->nick_exists($nickname) ) {
	return 0;
  }
  if ( defined ( $self->{State}->{by_nickname}->{ $nickname }->{Wheel} ) and defined ( $self->{Clients}->{ $self->{State}->{by_nickname}->{ $nickname }->{Wheel} } ) ) {
  	return $self->{State}->{by_nickname}->{ $nickname }->{Wheel};
  }
  return undef;
}

sub server_name {
  my ($self) = shift;

  return $self->{Config}->{ServerName};
}

sub server_token {
  my ($self) = shift;

  if ( defined ( $self->{Config}->{Token} ) ) {
	return $self->{Config}->{Token};
  } else {
	return 'AA';
  }
}

sub server_version {
  my ($self) = shift;

  return $self->{Config}->{Version};
}

sub server_description {
  my ($self) = shift;

  return $self->{Config}->{ServerDesc};
}

sub irc_network {
  my ($self) = shift;

  return $self->{Config}->{Network};
}

sub connection_exists {
  my ($self) = shift;
  my ($wheel_id) = shift || return 0;

  if ( defined ( $self->{Connections}->{ $wheel_id } ) ) {
	return 1;
  }
  return 0;
}

sub client_exists {
  my ($self) = shift;
  my ($wheel_id) = shift || return 0;

  if ( defined ( $self->{Clients}->{ $wheel_id } ) ) {
	return 1;
  }
  return 0;
}

sub client_nickname {
  my ($self) = shift;
  my ($wheel_id) = $_[0] || return undef;

  if ( $self->connection_exists($wheel_id) ) {
	return $self->{Connections}->{ $wheel_id }->{ProperNick};
  }
  if ( $self->client_exists($wheel_id) ) {
	return $self->{State}->{by_nickname}->{ $self->{Clients}->{ $wheel_id }->{NickName} }->{NickName};
  }
  return undef;
}

sub proper_nickname {
  my ($self) = shift;
  my ($nickname) = u_irc ( $_[0] ) || return undef;

  if ( not $self->nick_exists($nickname) ) {
	return undef;
  }
  if ( defined ( $self->{State}->{by_nickname}->{ $nickname } ) ) {
	return $self->{State}->{by_nickname}->{ $nickname }->{NickName};
  }
  return undef;
}

sub client_matches_i_line {
  my ($self) = shift;
  my ($wheel_id) = $_[0] || return 0;

  return 0 if ( not defined ( $self->{Connections}->{ $wheel_id } ) );
  my ($peeraddress) = $self->{Connections}->{ $wheel_id }->{PeerAddr};
  my ($sockport) = $self->{Connections}->{ $wheel_id }->{SockPort};
  my ($password) = $self->{Connections}->{ $wheel_id }->{GotPwd};

  # Process I-Lines and find a match
  foreach my $iline ( @{ $self->{I_Lines} } ) {
    my ($ipmask) = $iline->{TargetAddr};
    my ($hostmask) = $iline->{HostAddr};
    my ($passw) = $iline->{Password};
    my ($port) = $iline->{Port};
    $ipmask =~ s/\*/[\x01-\xFF]{0,}/g;
    $ipmask =~ s/\?/[\x01-\xFF]{1,1}/g;
    $hostmask =~ s/\*/[\x01-\xFF]{0,}/g;
    $hostmask =~ s/\?/[\x01-\xFF]{1,1}/g;
    $port =~ s/\*/[\x01-\xFF]{0,}/g;
    $port =~ s/\?/[\x01-\xFF]{1,1}/g;
    if ( $peeraddress =~ /^$ipmask$/ and $sockport =~ /^$port$/ ) {
	  if ( defined ( $passw ) and ( not defined ( $password ) ) ) {
		return -1;
	  }
	  if ( defined ( $passw ) and defined ( $password ) and $passw ne $password ) {
		return -1;
	  }
	  return 1;
    }
  }
  return 0;
}

sub client_matches_o_line {
  my ($self) = shift;
  my ($wheel_id) = $_[0] || return 0;
  my ($username) = $_[1] || return 0;

  my ($peeraddress) = $self->{Clients}->{ $wheel_id }->{PeerAddr};
  my ($ipmask) = $self->{Operators}->{ $username }->{IPMask};

  if ( ( not defined ( $ipmask ) ) and $peeraddress =~ /^127\./ ) {
	return 1;
  }
  if ( not defined ( $ipmask ) ) {
	return 0;
  }
  $ipmask =~ s/\*/[\x01-\xFF]{0,}/g;
  $ipmask =~ s/\?/[\x01-\xFF]{1,1}/g;
  if ( $peeraddress =~ /^$ipmask$/ ) {
	return 1;
  }
  return 0;
}

sub is_reserved_channel {
  my ($self) = shift;
  my ($channelname) = u_irc ( $_[0] ) || return undef;

  foreach my $chan ( @reserved_channels ) {
	if ( $channelname eq $chan ) {
		return $chan;
	}
  }
  return undef;
}

sub generate_client_numeric {
  my ($self) = shift;

  1;
}

sub list_ports_used {
  my ($self) = shift;

  return keys %{ $self->{Listeners} };
}

1;
__END__

=head1 NAME

POE::Component::Server::IRC - a fully event-driven standalone IRC server daemon module.

=head1 SYNOPSIS

  use POE;
  use POE::Component::Server::IRC;

  my ($pocosi) = POE::Component::Server::IRC->spawn( Alias => 'ircd' );

  POE::Session->create (
        inline_states => { _start => \&test_start,
                           _stop  => \&test_stop, },

        heap => { Obj  => $pocosi },
  );

  $poe_kernel->run();
  exit 0;

  sub test_start {
    my ($kernel,$heap) = @_[KERNEL,HEAP];

    $kernel->post ( 'ircd' => 'register' );
    $kernel->post ( 'ircd' => 'configure' => { Auth => 1, AntiFlood => 1 } );
    $kernel->post ( 'ircd' => 'add_i_line' => { IPMask => '*', Port => 6667 } );
    $kernel->post ( 'ircd' => 'add_operator' => { UserName => 'Flibble', Password => 'letmein' } );
    $kernel->post ( 'ircd' => 'add_listener' => { Port => 6667 } );
    $kernel->post ( 'ircd' => 'set_motd' => [ 'This is an experimental server', 'Testing POE::Component::Server::IRC', 'Enjoy!' ] );
  }

  sub test_stop {
	print "Server stopped\n";
  }

=head1 DESCRIPTION

POE::Component::Server::IRC is a POE component which implements an RFC compliant standalone Internet Relay Chat
server ( IRCd ).

Features include an auth subsystem, that performs hostname and ident lookups on each connecting client and antiflood code that disconnects clients that attempt to flood the server.

The SYNOPSIS demonstrates how to create a simple ircd, which listens for connections on port 6667.

=head1 METHODS

Object methods that we will accept.

=item spawn

Creates a new POE::Component::Server::IRC component. Returns an object. Takes the following arguments: 'Alias': mandatory argument, the POE::Kernel alias that you want to bless the component with; 'Debug': optional, set 1 to enable trace information, default 0.

Spawn will also accept any of the arguments accepted by 'configure', see below.

=head1 INPUT

Events that the component will accept.

=over

=item configure

Accepts either a hashref as the first argument or a list of key/values. 'Auth': setting this to 0 or 1, disables or enables, respectively, the ircd auth subsystem; 'AntiFlood': setting this to 0 or 1, disables or enables the antiflood code for *all* connecting clients ( IRC operators are exempt from flood protection anyways ); 'ServerName': the name for your server; 'ServerDesc': the description for your server; 'Network': the name of your network.

  $kernel->post ( 'ircd' => configure =>
	{ Auth => 1,
	  AntiFlood => 1,
	  ServerName => 'poco.server.irc',
	  ServerDesc => 'Poco? POCO? POCO!',
	  Network => 'poconet',
	}
  ); # Defaults shown

=item add_i_line

An 'I' line defines who can connect to your IRCd. Accepts either a hashref as the first argument or a list of key/values. 'TargetAddr': is a mask to match connecting clients against; 'Port': the listening port this I line will apply to;
'Password': the password that clients will have to use to gain entry to this server.

The default for any parameter not supplied is to use a mask of '*' for that entry, so:

  $kernel->post( 'ircd' => 'add_i_line' );

would allow anyone to connect to any listening port without a password being required.

The * and ? chars can be used in any of the fields, except Password ( that would be silly ).

=item add_listener

Creates a listening port, so that clients can connect to your IRCd. Accepts either a hashref as the first argument
or a list of key/values. 'Port': mandatory argument, the socket port one wishes to listen on.

=item add_operator

Adds an 'O' line to the IRCd. Accepts either a hashref as the first argument or a list of key/values. Mandatory values :
'UserName': the operator username; 'Password': the password for that username; Optionally, 'IPMask': a mask to
match the user's IP address against.

UserName and Password are required in all cases. Without an IPMask, the default behaviour is to only all connections from the loopback interface, ie. local operators.

Once a user becomes an operator they are not subject to the antiflood mechanism. This is a feature.

=item set_motd

Sets the server Message of the Day, which is sent to all clients when they successfully connect to the server.
Accepts an arrayref as first argument. Each entry in that arrayref becomes a separate line of MOTD output.

=back

=head1 OUTPUT

There is currently no output from the component.

=head1 CAVEATS

The component creates a standalone server. This means that it is not currently possible to link servers together
to form IRC networks.

This is alpha grade code. Development is ongoing to implement the server-to-server protocols to enable IRC
networks to be created and to make the component more modular in design.

=head1 DEVELOPMENT ROADMAP

Watch CPAN for further releases.

=item modular design
=item port existing code to new framework
=item server to server protocols

=head1 AUTHOR

Chris Williams, E<lt>chris@bingosnet.co.ukE<gt>

=head1 SEE ALSO

RFC 2810 L<http://www.faqs.org/rfcs/rfc2810.html>
RFC 2811 L<http://www.faqs.org/rfcs/rfc2811.html>
RFC 2812 L<http://www.faqs.org/rfcs/rfc2812.html>
RFC 2813 L<http://www.faqs.org/rfcs/rfc2813.html>

=cut

