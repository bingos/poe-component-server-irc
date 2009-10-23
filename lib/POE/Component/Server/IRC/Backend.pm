package POE::Component::Server::IRC::Backend;

use strict;
use warnings;
use POE qw(Wheel::SocketFactory Wheel::ReadWrite Filter::Stackable Filter::Line Filter::IRCD);
use POE::Component::Server::IRC::Plugin qw( :ALL );
use Socket;
use Carp;
use Net::Netmask;
use base qw(POE::Component::Pluggable);
use vars qw($VERSION);

$VERSION = '1.40';

sub create {
  my $package = shift;
  croak "$package requires an even number of parameters" if @_ & 1;
  my %parms = @_;

  $parms{ lc $_ } = delete $parms{$_} for keys %parms;

  my $self = bless \%parms, $package;

  $self->{prefix} = 'ircd_backend_' unless $self->{prefix};
  $self->{antiflood} = 1 unless defined $self->{antiflood} and $self->{antiflood} eq '0';
  my $options = delete $self->{options};
  my $sslify_options = delete $self->{sslify_options};
  my $plugin_debug   = delete $self->{plugin_debug};

  $self->_pluggable_init(
        prefix     => $self->{prefix},
        reg_prefix => 'PCSI_',
        types      => { SERVER => 'IRCD' },
        ($plugin_debug ? (debug => 1) : () ),
  );


  $self->{session_id} = POE::Session->create(
	object_states => [
		$self => { _start	 => '_start',
			   add_connector => '_add_connector',
			   add_filter    => '_add_filter',
			   add_listener  => '_add_listener', 
			   del_filter    => '_del_filter',
			   del_listener  => '_del_listener', 
			   send_output   => '_send_output',
			   shutdown 	 => '_shutdown', },
		$self => [ qw(  __send_event
				__send_output
				_accept_connection 
				_accept_failed 
				_auth_client
				_auth_done
				_conn_alarm
				_conn_input 
				_conn_error 
				_conn_flushed
				_event_dispatcher
				_got_hostname_response
				_got_ip_response
				_sock_failed
				_sock_up
				_start 
				ident_agent_error
				ident_agent_reply
				register 
				unregister) ],
	],
	heap => $self,
	( ref($options) eq 'HASH' ? ( options => $options ) : () ),
  )->ID();
  $self->{got_zlib} = 0;
  eval { 
	require POE::Filter::Zlib::Stream; 
	$self->{got_zlib} = 1;
  };

  if ( $sslify_options and ref $sslify_options eq 'ARRAY' ) {
    $self->{got_ssl} = $self->{got_server_ssl} = 0;
    eval {
	require POE::Component::SSLify; 
	import POE::Component::SSLify qw(SSLify_Options Server_SSLify Client_SSLify);
	$self->{got_ssl} = 1;
    };
    warn "$@\n" if $@;
    if ( $self->{got_ssl} ) {
	eval { SSLify_Options( @{ $sslify_options } ); };
        $self->{got_server_ssl} = 1 unless $@;
	warn "$@\n" if $@;
    }
  }

  return $self;
}

sub session_id {
  my $self = shift;
  return $self->{session_id};
}

sub yield {
  my $self = shift;
  $poe_kernel->post( $self->session_id() => @_ );
}

sub call {
  my $self = shift;
  $poe_kernel->call( $self->session_id() => @_ );
}

sub _start {
  my ($kernel,$self,$sender) = @_[KERNEL,OBJECT,SENDER];

  $self->{session_id} = $_[SESSION]->ID();

  if ( $self->{alias} ) {
	$kernel->alias_set( $self->{alias} );
  } else {
	$kernel->refcount_increment( $self->{session_id} => __PACKAGE__ );
  }

  $self->{ircd_filter} = POE::Filter::IRCD->new( DEBUG => $self->{debug}, colonify => 1 );
  $self->{line_filter} = POE::Filter::Line->new( InputRegexp => '\015?\012', OutputLiteral => "\015\012" );
  $self->{filter} = POE::Filter::Stackable->new( Filters => [ $self->{line_filter}, $self->{ircd_filter} ] );
  $self->{can_do_auth} = 0;
  eval {
	require POE::Component::Client::Ident::Agent;
	require POE::Component::Client::DNS;
  };
  unless ( $@ ) {
	$self->{resolver} = POE::Component::Client::DNS->spawn( Alias => 'poco_dns_' . $self->{session_id}, Timeout => 10 );
	$self->{can_do_auth} = 1;
  }
  $self->{will_do_auth} = 0;
  if ( $self->{auth} and $self->{can_do_auth} ) {
	$self->{will_do_auth} = 1;
  }
  $self->_load_our_plugins();
  if ( $kernel != $sender ) {
    $self->{sessions}->{ $sender->ID }++;
    $kernel->post( $sender => $self->{prefix} . 'registered' => $self );
  }
  undef;
}

sub _load_our_plugins {
  return 1;
}

###################
# Control methods #
###################

sub register {
  my ($kernel,$self,$session,$sender) = @_[KERNEL,OBJECT,SESSION,SENDER];
  $session = $session->ID(); $sender = $sender->ID();

  $self->{sessions}->{ $sender }++;
  $kernel->refcount_increment( $sender => __PACKAGE__ ) if $self->{sessions}->{ $sender } == 1 and $sender ne $session;
  $kernel->post( $sender => $self->{prefix} . 'registered' => $self );
  undef;
}

sub unregister {
  my ($kernel,$self,$session,$sender) = @_[KERNEL,OBJECT,SESSION,SENDER];
  $session = $session->ID(); $sender = $sender->ID();

  delete $self->{sessions}->{ $sender };
  $kernel->refcount_decrement( $sender => __PACKAGE__ ) if $sender ne $session;
  $kernel->post( $sender => $self->{prefix} . 'unregistered' );
  undef;
}

sub shutdown {
  my ($self) = shift;
  $self->yield( 'shutdown' => @_ );
}

sub _shutdown {
  my ($kernel,$self) = @_[KERNEL,OBJECT];

  $kernel->alias_remove( $_ ) for $kernel->alias_list();
  $kernel->refcount_decrement( $self->{session_id} => __PACKAGE__ ) unless $self->{alias};

  $self->{terminating} = 1;
  delete $self->{listeners};
  delete $self->{connectors};
  delete $self->{wheels}; # :)
  $kernel->alarm_remove_all();
  $kernel->refcount_decrement( $_ => __PACKAGE__ ) for keys %{ $self->{sessions} };
  $self->_pluggable_destroy();
  $self->_unload_our_plugins();
  undef;
}

sub _unload_our_plugins {
  return 1;
}

sub send_event {
  my $self = shift;
  my $event = shift;

  return 0 unless $event;
  my $prefix = $self->{prefix};
  $event = $prefix . $event unless $event =~ /^(_|\Q$prefix\E)/;
  $self->yield( '__send_event' => $event => @_ );
  return 1;
}

sub __send_event {
  my( $self, $event, @args ) = @_[ OBJECT, ARG0, ARG1 .. $#_ ];
  $self->_send_event( $event, @args );
  return 1;
}

sub _send_event {
  my ($self,$event,@args) = @_;
  return 1 if $self->_pluggable_process( 'SERVER', $event, \( @args ) ) == PCSI_EAT_ALL;
  $poe_kernel->post( $_ => $event, @args ) for  keys % { $self->{sessions} };
  return 1;
}

sub _pluggable_event {
    my ($self, @args) = @_;
    $self->yield(__send_event => @args);
    return;
}

############################
# Listener related methods #
############################

sub _accept_failed {
  my ($kernel,$self,$operation,$errnum,$errstr,$listener_id) = @_[KERNEL,OBJECT,ARG0..ARG3];
  delete $self->{listeners}->{ $listener_id };
  $self->_send_event( $self->{prefix} . 'listener_failure', $listener_id, $operation, $errnum, $errstr );
  undef;
}

sub _accept_connection {
  my ($kernel,$self,$socket,$peeraddr,$peerport,$listener_id) = @_[KERNEL,OBJECT,ARG0..ARG3];
  my $sockaddr = inet_ntoa( ( unpack_sockaddr_in ( getsockname $socket ) )[1] );
  my $sockport = ( unpack_sockaddr_in ( getsockname $socket ) )[0];
  $peeraddr = inet_ntoa( $peeraddr );
  my $listener = $self->{listeners}->{ $listener_id };

  if ( $self->{got_server_ssl} and $listener->{usessl} ) {
	eval { $socket = POE::Component::SSLify::Server_SSLify( $socket ); };
	warn "$@\n" if $@;
  }

  return if $self->denied( $peeraddr );

  my $wheel = POE::Wheel::ReadWrite->new(
	Handle => $socket,
	Filter => $self->{filter},
	InputEvent => '_conn_input',
	ErrorEvent => '_conn_error',
	FlushedEvent => '_conn_flushed',
  );

  if ( $wheel ) {
	my $wheel_id = $wheel->ID();
        my $ref = { wheel => $wheel, peeraddr => $peeraddr, peerport => $peerport, flooded => 0,
		      sockaddr => $sockaddr, sockport => $sockport, idle => time(), antiflood => $listener->{antiflood}, compress => 0 };
	$self->_send_event( $self->{prefix} . 'connection' => $wheel_id => $peeraddr => $peerport => $sockaddr => $sockport );
	if ( $listener->{do_auth} and $self->{will_do_auth} ) {
		$kernel->yield( '_auth_client' => $wheel_id );
	} else {
		$self->_send_event( $self->{prefix} . 'auth_done' => $wheel_id => { ident    => '',
										    hostname => '' } )
	}
	$ref->{freq} = $listener->{freq};
        $ref->{alarm} = $kernel->delay_set( _conn_alarm => $listener->{freq} => $wheel_id );
	$self->{wheels}->{ $wheel_id } = $ref;
  }
  undef;
}

sub add_listener {
  my ($self) = shift;
  croak "add_listener requires an even number of parameters" if @_ & 1;
  $self->yield( 'add_listener' => @_ );
}

sub _add_listener {
  my ($kernel,$self) = @_[KERNEL,OBJECT];
  my %parms = @_[ARG0..$#_];

  $parms{ lc($_) } = delete $parms{$_} for keys %parms;

  my $bindport = $parms{port} || 0;
  my $freq = $parms{freq} || 180;
  my $auth = 1;
  my $antiflood = 1;
  my $usessl = 0;
  $usessl = 1 if $parms{usessl};
  $auth = 0 if defined $parms{auth} and $parms{auth} eq '0';
  $antiflood = 0 if defined $parms{antiflood} and $parms{antiflood} eq '0';

  my $listener = POE::Wheel::SocketFactory->new(
	BindPort => $bindport,
	( $parms{bindaddr} ? ( BindAddress => $parms{bindaddr} ) : () ),
	Reuse => 'on',
	( $parms{listenqueue} ? ( ListenQueue => $parms{listenqueue} ) : () ),
	SuccessEvent => '_accept_connection',
	FailureEvent => '_accept_failed',
  );

  if ( $listener ) {
	my $port = ( unpack_sockaddr_in( $listener->getsockname ) )[0];
	my $listener_id = $listener->ID();
	$self->_send_event( $self->{prefix} . 'listener_add' => $port => $listener_id );
	$self->{listening_ports}->{ $port } = $listener_id;
	$self->{listeners}->{ $listener_id }->{wheel} = $listener;
	$self->{listeners}->{ $listener_id }->{port} = $port;
	$self->{listeners}->{ $listener_id }->{freq} = $freq;
	$self->{listeners}->{ $listener_id }->{do_auth} = $auth;
	$self->{listeners}->{ $listener_id }->{antiflood} = $antiflood;
	$self->{listeners}->{ $listener_id }->{usessl} = $usessl;
  }
  undef;
}

sub del_listener {
  my ($self) = shift;
  croak "add_listener requires an even number of parameters" if @_ & 1;
  $self->yield( 'del_listener' => @_ );
}

sub _del_listener {
  my ($kernel,$self) = @_[KERNEL,OBJECT];
  my %parms = @_[ARG0..$#_];

  $parms{ lc($_) } = delete $parms{$_} for keys %parms;

  my $listener_id = delete $parms{listener};
  my $port = delete $parms{port};

  if ( $self->_listener_exists( $listener_id ) ) {
	$port = delete $self->{listeners}->{ $listener_id }->{port};
	delete $self->{listening_ports}->{ $port };
	delete $self->{listeners}->{ $listener_id };
	$self->_send_event( $self->{prefix} . 'listener_del' => $port => $listener_id );
  }

  if ( $self->_port_exists( $port ) ) {
	$listener_id = delete $self->{listening_ports}->{ $port };
	delete $self->{listeners}->{ $listener_id };
	$self->_send_event( $self->{prefix} . 'listener_del' => $port => $listener_id );
  }

  undef;
}

sub _listener_exists {
  my $self = shift;
  my $listener_id = shift || return 0;
  return 1 if defined $self->{listeners}->{ $listener_id };
  return 0;
}

sub _port_exists {
  my $self = shift;
  my $port = shift || return 0;
  return 1 if defined $self->{listening_ports}->{ $port };
  return 0;
}

#############################
# Connector related methods #
#############################

sub add_connector {
  my $self = shift;
  croak "add_connector requires an even number of parameters" if @_ & 1;
  $self->yield( 'add_connector' => @_ );
}

sub _add_connector {
  my ($kernel,$self,$sender) = @_[KERNEL,OBJECT,SENDER];
  #croak "add_connector requires an even number of parameters" if @_[ARG0..$#_] & 1;
  my %parms = @_[ARG0..$#_];

  $parms{ lc($_) } = delete $parms{$_} for keys %parms;
  
  my $remoteaddress = $parms{remoteaddress};
  my $remoteport = $parms{remoteport};
  
  return unless $remoteaddress and $remoteport;

  my $wheel = POE::Wheel::SocketFactory->new(
	SocketDomain   => AF_INET,
	SocketType     => SOCK_STREAM,
	SocketProtocol => 'tcp',
	RemoteAddress => $remoteaddress,
	RemotePort    => $remoteport,
	SuccessEvent  => '_sock_up',
	FailureEvent  => '_sock_failed',
	( $parms{bindaddress} ? ( BindAddress => $parms{bindaddress} ) : () ),
  );

  if ( $wheel ) {
	$parms{wheel} = $wheel;
	$self->{connectors}->{ $wheel->ID() } = \%parms;
  }
  undef;
}

sub _sock_failed {
  my ($kernel,$self,$op,$errno,$errstr,$connector_id) = @_[KERNEL,OBJECT,ARG0..ARG3];
  my $ref = delete $self->{connectors}->{ $connector_id };
  delete $ref->{wheel};
  $self->_send_event( $self->{prefix} . 'socketerr' => $ref );
  undef;
}

sub _sock_up {
  my ($kernel,$self,$socket,$peeraddr,$peerport,$connector_id) = @_[KERNEL,OBJECT,ARG0..ARG3];
  $peeraddr = inet_ntoa( $peeraddr );

  my $cntr = delete $self->{connectors}->{ $connector_id };
  if ( $self->{got_ssl} and $cntr->{usessl} ) {
    eval {
      $socket = POE::Component::SSLify::Client_SSLify( $socket );
    };
    warn "Couldn't use an SSL socket: $@ \n" if $@;
  }

  my $wheel = POE::Wheel::ReadWrite->new(
	Handle => $socket,
	#Filter => $self->{filter},
	Filter => POE::Filter::Stackable->new( Filters => [ $self->{filter} ] ),
	InputEvent => '_conn_input',
	ErrorEvent => '_conn_error',
	FlushedEvent => '_conn_flushed',
  );

  if ( $wheel ) {
	my $wheel_id = $wheel->ID();
	my $sockaddr = inet_ntoa( ( unpack_sockaddr_in ( getsockname $socket ) )[1] );
	my $sockport = ( unpack_sockaddr_in ( getsockname $socket ) )[0];
        my $ref = { wheel => $wheel, peeraddr => $peeraddr, peerport => $peerport, 
		      sockaddr => $sockaddr, sockport => $sockport, idle => time(), antiflood => 0, compress => 0 };
	$self->{wheels}->{ $wheel_id } = $ref;
	$self->_send_event( $self->{prefix} . 'connected' => $wheel_id => $peeraddr => $peerport => $sockaddr => $sockport => $cntr->{name} );
  }
  undef;
}

##############################
# Generic Connection Handler #
##############################

#sub add_filter {
#  my $self = shift;
#  croak "add_filter requires an even number of parameters" if @_ & 1;
#  $self->call( 'add_filter' => @_ );
#}

sub _add_filter {
  my ($kernel,$self,$sender) = @_[KERNEL,OBJECT,SENDER];
  my $wheel_id = $_[ARG0] || croak "You must supply a connection id\n";
  my $filter = $_[ARG1] || croak "You must supply a filter object\n";
  return unless $self->_wheel_exists( $wheel_id );
  my $stackable = POE::Filter::Stackable->new( Filters => [ $self->{line_filter}, $self->{ircd_filter}, $filter ] );
  if ( $self->compressed_link( $wheel_id ) ) {
	$stackable->unshift( POE::Filter::Zlib::Stream->new() );
  }
  $self->{wheels}->{ $wheel_id }->{wheel}->set_filter( $stackable );
  $self->_send_event( $self->{prefix} . 'filter_add' => $wheel_id => $filter );
  undef;
}

sub _anti_flood {
  my ($self,$wheel_id,$input) = splice @_, 0, 3;
  my $current_time = time();

  return unless $wheel_id and $self->_wheel_exists( $wheel_id ) and $input; 
  SWITCH: { 
     if ( $self->{wheels}->{ $wheel_id }->{flooded} ) {
	last SWITCH;
     }
     if ( ( not $self->{wheels}->{ $wheel_id }->{timer} ) or $self->{wheels}->{ $wheel_id }->{timer} < $current_time ) {
	$self->{wheels}->{ $wheel_id }->{timer} = $current_time;
    	my $event = $self->{prefix} . 'cmd_' . lc ( $input->{command} );
    	$self->_send_event( $event => $wheel_id => $input );
	last SWITCH;
     }
     if ( $self->{wheels}->{ $wheel_id }->{timer} <= ( $current_time + 10 ) ) {
	$self->{wheels}->{ $wheel_id }->{timer} += 1;
	push @{ $self->{wheels}->{ $wheel_id }->{msq} }, $input;
	push @{ $self->{wheels}->{ $wheel_id }->{alarm_ids} }, $poe_kernel->alarm_set( '_event_dispatcher' => $self->{wheels}->{ $wheel_id }->{timer} => $wheel_id );
	last SWITCH;
     }
     $self->{wheels}->{ $wheel_id }->{flooded} = 1;
     $self->_send_event( $self->{prefix} . 'connection_flood' => $wheel_id );
  }
  return 1;
}

sub _conn_error {
  my ($self,$errstr,$wheel_id) = @_[OBJECT,ARG2,ARG3];
  return unless $self->_wheel_exists( $wheel_id );
  $self->_disconnected( $wheel_id, $errstr || $self->{wheels}->{ $wheel_id }->{disconnecting} );
  undef;
}

sub _conn_alarm {
  my ($kernel,$self,$wheel_id) = @_[KERNEL,OBJECT,ARG0];
  return unless $self->_wheel_exists( $wheel_id );
  my $conn = $self->{wheels}->{ $wheel_id };
  $self->_send_event( $self->{prefix} . 'connection_idle' => $wheel_id => $conn->{freq} );
  $conn->{alarm} = $kernel->delay_set( _conn_alarm => $conn->{freq} => $wheel_id );
  undef;
}

sub _conn_flushed {
  my ($kernel,$self,$wheel_id) = @_[KERNEL,OBJECT,ARG0];
  return unless $self->_wheel_exists( $wheel_id );
  if ( $self->{wheels}->{ $wheel_id }->{disconnecting} ) {
	$self->_disconnected( $wheel_id, $self->{wheels}->{ $wheel_id }->{disconnecting} );
	return;
  }
  if ( $self->{wheels}->{ $wheel_id }->{compress_pending} ) {
	delete $self->{wheels}->{ $wheel_id }->{compress_pending};
	$self->{wheels}->{ $wheel_id }->{wheel}->get_input_filter()->unshift( POE::Filter::Zlib::Stream->new() );
	$self->_send_event( $self->{prefix} . 'compressed_conn' => $wheel_id );
	return;
  }
  undef;
}

sub _conn_input {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];
  my $conn = $self->{wheels}->{ $wheel_id };

  $self->_send_event( $self->{prefix} . 'raw_input' => $wheel_id => $input->{raw_line} ) if $self->{raw_events};
  $conn->{seen} = time();
  $kernel->delay_adjust( $conn->{alarm} => $conn->{freq} );
  #ToDo: Antiflood code
  if ( $self->antiflood( $wheel_id ) ) {
	$self->_anti_flood( $wheel_id => $input );
  } else {
    my $event = $self->{prefix} . 'cmd_' . lc $input->{command};
    $self->_send_event( $event => $wheel_id => $input );
  }
  undef;
}

#sub del_filter {
#  my $self = shift;
#  $self->call( 'del_filter' => @_ );
#}

sub _del_filter {
  my ($kernel,$self,$sender) = @_[KERNEL,OBJECT,SENDER];
  my $wheel_id = $_[ARG0] || croak "You must supply a connection id\n";
  return unless $self->_wheel_exists( $wheel_id );
  $self->{wheels}->{ $wheel_id }->{wheel}->set_filter( $self->{filter} );
  $self->_send_event( $self->{prefix} . 'filter_del' => $wheel_id );
  undef;
}

sub _event_dispatcher {
  my ($kernel,$self,$wheel_id) = @_[KERNEL,OBJECT,ARG0];

  return unless $self->_wheel_exists( $wheel_id ) and !$self->{wheels}->{ $wheel_id }->{flooded};
  shift @{ $self->{wheels}->{ $wheel_id }->{alarm_ids} };
  my $input = shift @{ $self->{wheels}->{ $wheel_id }->{msq} };
  if ( $input ) {
    my $event = $self->{prefix} . 'cmd_' . lc ( $input->{command} );
    $self->_send_event( $event => $wheel_id => $input );
  }
  undef;
}

sub send_output {
  my ($self,$output) = splice @_, 0, 2;
  if ( $output and ref( $output ) eq 'HASH' ) {
    if ( scalar @_ == 1 or ( $output->{command} and $output->{command} eq 'ERROR' ) ) {
  	$self->{wheels}->{ $_ }->{wheel}->put( $output ) for grep { $self->_wheel_exists( $_ ) } @_;
    	return 1;
    }
    $self->yield( __send_output => $output => $_ ) for grep { $self->_wheel_exists($_) } @_;
    return 1;
  }
  return 0;
}

sub __send_output {
  my ($self,$output,$route_id) = @_[OBJECT,ARG0,ARG1];
  $self->{wheels}->{ $route_id }->{wheel}->put( $output ) if $self->_wheel_exists( $route_id );
  undef;
}

sub _send_output {
  $_[OBJECT]->send_output( @_[ARG0..$#_] );
  undef;
}

##########################
# Auth subsystem methods #
##########################

sub _auth_client {
  my ($kernel,$self,$wheel_id) = @_[KERNEL,OBJECT,ARG0];
  return unless $self->_wheel_exists( $wheel_id );

  my ($peeraddr,$peerport,$sockaddr,$sockport) = $self->connection_info( $wheel_id );

  $self->send_output( { command => 'NOTICE', params => [ 'AUTH', '*** Checking Ident' ] }, $wheel_id );
  $self->send_output( { command => 'NOTICE', params => [ 'AUTH', '*** Checking Hostname' ] }, $wheel_id );

  if ( $peeraddr !~ /^127\./ ) {
	my $response = $self->{resolver}->resolve( 
		event => '_got_hostname_response', 
		host => $peeraddr,
		context => { wheel => $wheel_id, peeraddress => $peeraddr },
		type => 'PTR' 
	);
	if ( $response ) {
		$kernel->yield( '_got_hostname_response' => $response );
	}
  } else {
  	$self->send_output( { command => 'NOTICE', params => [ 'AUTH', '*** Found your hostname' ] }, $wheel_id );
	$self->{wheels}->{ $wheel_id }->{auth}->{hostname} = 'localhost';
	$self->yield( '_auth_done' => $wheel_id );
  }
  POE::Component::Client::Ident::Agent->spawn( 
		PeerAddr => $peeraddr, 
		PeerPort => $peerport, 
		SockAddr => $sockaddr,
	        SockPort => $sockport, 
		BuggyIdentd => 1, 
		TimeOut => 10,
		Reference => $wheel_id 
  );
  undef;
}

sub _auth_done {
  my ($kernel,$self,$wheel_id) = @_[KERNEL,OBJECT,ARG0];

  return unless $self->_wheel_exists( $wheel_id );
  if ( defined ( $self->{wheels}->{ $wheel_id }->{auth}->{ident} ) and defined ( $self->{wheels}->{ $wheel_id }->{auth}->{hostname} ) ) {
	$self->_send_event( $self->{prefix} . 'auth_done' => $wheel_id => { 
		ident    => $self->{wheels}->{ $wheel_id }->{auth}->{ident},
   	        hostname => $self->{wheels}->{ $wheel_id }->{auth}->{hostname} } )
		unless ( $self->{wheels}->{ $wheel_id }->{auth}->{done} );
	$self->{wheels}->{ $wheel_id }->{auth}->{done}++;
  }
  undef;
}

sub _got_hostname_response {
    my ($kernel,$self) = @_[KERNEL,OBJECT];
    my $response = $_[ARG0];
    my $wheel_id = $response->{context}->{wheel};

    return unless $self->_wheel_exists( $wheel_id );
    if ( defined $response->{response} ) {
      my @answers = $response->{response}->answer();

      if ( scalar @answers == 0 ) {
	# Send NOTICE to client of failure.
	$self->send_output( { command => 'NOTICE', params => [ 'AUTH', "*** Couldn\'t look up your hostname" ] }, $wheel_id ) unless defined $self->{wheels}->{ $wheel_id }->{auth}->{hostname};
	$self->{wheels}->{ $wheel_id }->{auth}->{hostname} = '';
	$self->yield( '_auth_done' => $wheel_id );
      }

      foreach my $answer (@answers) {
	my $context = $response->{context};
	$context->{hostname} = $answer->rdatastr();
	if ( $context->{hostname} =~ /\.$/ ) {
	   chop $context->{hostname};
	}
	my $query = $self->{resolver}->resolve( 
		event => '_got_ip_response', 
		host => $answer->rdatastr(), 
		context => $context, 
		type => 'A' 
	);
	if ( defined $query ) {
	   $self->yield( '_got_ip_response' => $query );
	}
      }
    } else {
	# Send NOTICE to client of failure.
	$self->send_output( { command => 'NOTICE', params => [ 'AUTH', "*** Couldn\'t look up your hostname" ] }, $wheel_id ) unless defined $self->{wheels}->{ $wheel_id }->{auth}->{hostname};
	$self->{wheels}->{ $wheel_id }->{auth}->{hostname} = '';
	$self->yield( '_auth_done' => $wheel_id );
    }
    undef;
}

sub _got_ip_response {
    my ($kernel,$self) = @_[KERNEL,OBJECT];
    my $response = $_[ARG0];
    my $wheel_id = $response->{context}->{wheel};

    return unless $self->_wheel_exists( $wheel_id );
    if ( defined $response->{response} ) {
      my @answers = $response->{response}->answer();
      my $peeraddress = $response->{context}->{peeraddress};
      my $hostname = $response->{context}->{hostname};

      if ( scalar @answers == 0 ) {
	# Send NOTICE to client of failure.
	$self->send_output( { command => 'NOTICE', params => [ 'AUTH', "*** Couldn\'t look up your hostname" ] }, $wheel_id ) unless defined $self->{wheels}->{ $wheel_id }->{auth}->{hostname};
	$self->{wheels}->{ $wheel_id }->{auth}->{hostname} = '';
	$self->yield( '_auth_done' => $wheel_id );
      }

      foreach my $answer (@answers) {
	if ( $answer->rdatastr() eq $peeraddress and !defined $self->{wheels}->{ $wheel_id }->{auth}->{hostname} ) {
	   $self->send_output( { command => 'NOTICE', params => [ 'AUTH', '*** Found your hostname' ] }, $wheel_id ) unless $self->{wheels}->{ $wheel_id }->{auth}->{hostname};
	   $self->{wheels}->{ $wheel_id }->{auth}->{hostname} = $hostname;
	   $self->yield( '_auth_done' => $wheel_id );
	   return;
	} else {
	   $self->send_output( { command => 'NOTICE', params => [ 'AUTH', '*** Your forward and reverse DNS do not match' ] }, $wheel_id ) unless $self->{wheels}->{ $wheel_id }->{auth}->{hostname};
	   $self->{wheels}->{ $wheel_id }->{auth}->{hostname} = '';
	   $self->yield( '_auth_done' => $wheel_id );
	}
      }
    } else {
	# Send NOTICE to client of failure.
	$self->send_output( { command => 'NOTICE', params => [ 'AUTH', "*** Couldn\'t look up your hostname" ] }, $wheel_id ) unless $self->{wheels}->{ $wheel_id }->{auth}->{hostname};
	$self->{wheels}->{ $wheel_id }->{auth}->{hostname} = '';
	$self->yield( '_auth_done' => $wheel_id );
    }
    undef;
}

sub ident_agent_reply {
  my ($kernel,$self,$ref,$opsys,$other) = @_[KERNEL,OBJECT,ARG0,ARG1,ARG2];
  my $wheel_id = $ref->{Reference};

  if ( $self->_wheel_exists( $wheel_id ) ) {
      my $ident = '';
      if ( uc ( $opsys ) ne 'OTHER' ) {
	$ident = $other;
      }
      $self->send_output( { command => 'NOTICE', params => [ 'AUTH', "*** Got Ident response" ] }, $wheel_id );
      $self->{wheels}->{ $wheel_id }->{auth}->{ident} = $ident;
      $self->yield( '_auth_done' => $wheel_id );
  }
  undef;
}

sub ident_agent_error {
  my ($kernel,$self,$ref,$error) = @_[KERNEL,OBJECT,ARG0,ARG1];
  my $wheel_id = $ref->{Reference};

  if ( $self->_wheel_exists( $wheel_id ) ) {
      $self->send_output( { command => 'NOTICE', params => [ 'AUTH', "*** No Ident response" ] }, $wheel_id );
      $self->{wheels}->{ $wheel_id }->{auth}->{ident} = '';
      $self->yield( '_auth_done' => $wheel_id );
  }
  undef;
}

######################
# Connection methods #
######################

sub antiflood {
  my ($self,$wheel_id,$value) = splice @_, 0, 3;
  return unless $self->_wheel_exists( $wheel_id );
  return 0 unless $self->{antiflood};
  return $self->{wheels}->{ $wheel_id }->{antiflood} unless defined $value;
  unless ( $value ) {
    # Flush pending messages from that wheel
    while ( my $alarm_id = shift @{ $self->{wheels}->{ $wheel_id }->{alarm_ids} } ) {
      $poe_kernel->alarm_remove( $alarm_id );
      my $input = shift @{ $self->{wheels}->{ $wheel_id }->{msq} };
      if ( $input ) {
        my $event = $self->{prefix} . 'cmd_' . lc ( $input->{command} );
        $self->_send_event( $event => $wheel_id => $input );
      }
    }
  }
  $self->{wheels}->{ $wheel_id }->{antiflood} = $value;
}

sub compressed_link {
  my ($self,$wheel_id,$value,$cntr) = splice @_, 0, 4;
  return unless $self->{got_zlib};
  return unless $self->_wheel_exists( $wheel_id );
  return $self->{wheels}->{ $wheel_id }->{compress} unless defined $value;
  if ( $value ) {
	if ( $cntr ) {
	  $self->{wheels}->{ $wheel_id }->{wheel}->get_input_filter()->unshift( POE::Filter::Zlib::Stream->new() );
	$self->_send_event( $self->{prefix} . 'compressed_conn' => $wheel_id );
	} else {
	  $self->{wheels}->{ $wheel_id }->{compress_pending} = 1;
	}
  } else {
	$self->{wheels}->{ $wheel_id }->{wheel}->get_input_filter()->shift();
  }
  $self->{wheels}->{ $wheel_id }->{compress} = $value;
}

sub disconnect {
  my ($self,$wheel_id,$string) = splice @_, 0, 3;
  return unless $wheel_id and $self->_wheel_exists( $wheel_id );
  $self->{wheels}->{ $wheel_id }->{disconnecting} = $string || 'Client Quit';
}

sub _disconnected {
  my ($self,$wheel_id,$errstr) = splice @_, 0, 3;
  return unless $wheel_id and $self->_wheel_exists( $wheel_id );
  my $conn = delete $self->{wheels}->{ $wheel_id };
  $poe_kernel->alarm_remove( $_ ) for ( $conn->{alarm}, @{ $conn->{alarm_ids} } );
  $self->_send_event( $self->{prefix} . 'disconnected' => $wheel_id => $errstr || 'Client Quit' );
  return 1;
}

sub connection_info {
  my ($self,$wheel_id) = splice @_, 0, 2;
  return unless $self->_wheel_exists( $wheel_id );
  return map { $self->{wheels}->{ $wheel_id }->{$_} } qw(peeraddr peerport sockaddr sockport);
}

sub _wheel_exists {
  my ($self,$wheel_id) = @_;
  return 0 unless $wheel_id and defined $self->{wheels}->{ $wheel_id };
  return 1;
}

sub _conn_flooded {
  my $self = shift;
  my $conn_id = shift || return;
  return unless $self->_wheel_exists( $conn_id );
  return $self->{wheels}->{ $conn_id }->{flooded};
}

######################
# Spoofed Client API #
######################



##################
# Access Control #
##################

sub add_denial {
  my $self = shift;
  my $netmask = shift || return;
  my $reason = shift || 'Denied';
  return unless $netmask->isa('Net::Netmask');
  $self->{denials}->{ $netmask } = { blk => $netmask, reason => $reason };
  return 1;
}
 
sub del_denial {
  my $self = shift;
  my $netmask = shift || return;
  return unless $netmask->isa('Net::Netmask');
  return unless $self->{denials}->{ $netmask };
  delete $self->{denials}->{ $netmask };
  return 1;
}

sub add_exemption {
  my $self = shift;
  my $netmask = shift || return;
  return unless $netmask->isa('Net::Netmask');
  $self->{exemptions}->{ $netmask } = $netmask unless $self->{exemptions}->{ $netmask };
  return 1;
}

sub del_exemption {
  my $self = shift;
  my $netmask = shift || return;
  return unless $netmask->isa('Net::Netmask');
  return unless $self->{exemptions}->{ $netmask };
  delete $self->{exemptions}->{ $netmask };
  return 1;
}

sub denied {
  my $self = shift;
  my $ipaddr = shift || return;
  return 0 if $self->exempted( $ipaddr );
  foreach my $mask ( keys %{ $self->{denials} } ) {
    return $self->{denials}->{ $mask }->{reason} if $self->{denials}->{ $mask }->{blk}->match($ipaddr);
  }
  return 0;
}

sub exempted {
  my $self = shift;
  my $ipaddr = shift || return;
  foreach my $mask ( keys %{ $self->{exemptions} } ) {
    return 1 if $self->{exemptions}->{ $mask }->match($ipaddr);
  }
  return 0;
}

##################
# Plugin methods #
##################

1;
__END__

=head1 NAME

POE::Component::Server::IRC::Backend - A POE component class that provides network connection abstraction for
POE::Component::Server::IRC.

=head1 SYNOPSIS

  use POE qw(Component::Server::IRC::Backend);

  my $object = POE::Component::Server::IRC::Backend->create();

  POE::Session->create(
	package_states => [
		'main' => [ qw(_start) ],
	],
	heap => { ircd => $object },
  );

  $poe_kernel->run();
  exit 0;

  sub _start {
  }

=head1 DESCRIPTION

POE::Component::Server::IRC::Backend - A POE component class that provides network connection abstraction for
L<POE::Component::Server::IRC>.

=head1 CONSTRUCTOR

=over

=item C<create>

Returns an object. Accepts the following parameters, all are optional: 

  'alias', a POE::Kernel alias to set;
  'auth', set to 0 to globally disable IRC authentication, default is auth is enabled;
  'antiflood', set to 0 to globally disable flood protection;
  'prefix', this is the prefix that is used to generate event names that the component produces, 
	    the default is 'ircd_backend_'.

  my $object = POE::Component::Server::IRC::Backend->create( 
	alias => 'ircd', # Set an alias, default, no alias set.
	auth  => 0, # Disable auth globally, default enabled.
	antiflood => 0, # Disable flood protection globally, default enabled.
  );

If the component is created from within another session, that session will be automagcially registered
with the component to receive events and get an 'ircd_backend_registered' event.

=back

=head1 METHODS

These are the methods that may be invoked on our object.

=over

=item C<shutdown>

Takes no arguments. Terminates the component. Removes all listeners and connectors. Disconnects all current client and server connections.

=item C<session_id>

Takes no arguments. Returns the ID of the component's session. Ideal for posting events to the component.

=item C<send_event>

Seen an event through the component's event handling system. First argument is the event name, subsequent arguments are the event's parameters.

=item C<antiflood>

Takes two arguments, a connection id and true/false value. If value is specified antiflood protection is enabled or disabled accordingly for the specified connection. If a value is not specified the current status of antiflood protection is returned. Returns undef on error.

=item C<compressed_link>

Takes two arguments, a connection id and true/false value. If value is specified compression is enabled or disabled accordingly for the specified connection. If a value is not specified the current status of compression is returned. Returns undef on error.

=item C<disconnect>

Requires on argument, the connection id you wish to disconnect. The component will terminate the connection the next time that the wheel input is flushed, so you may send some sort of error message to the client on that connection. Returns true on success, undef on error.

=item C<connection_info>

Takes one argument, a connection_id. Returns a list consisting of: the IP address of the peer; the port on the peer; 
our socket address; our socket port. Returns undef on error.

   my($peeraddr,$peerport,$sockaddr,$sockport) = $object->connection_info( $conn_id );

=item C<add_denial>

Takes one mandatory argument and one optional. The first mandatory argument is a L<Net::Netmask> object that will be used to check connecting IP addresses against. The second optional argument is a reason string for the denial.

=item C<del_denial>

Takes one mandatory argument, a L<Net::Netmask> object to remove from the current denial list.

=item C<denied>

Takes one argument, an IP address. Returns true or false depending on whether that IP is denied or not.

=item C<add_exemption>

Takes one mandatory argument, a L<Net::Netmask> object that will be checked against connecting IP addresses for exemption from denials.

=item C<del_exemption>

Takes one mandatory argument, a L<Net::Netmask> object to remove from the current exemption list.

=item C<exempted>

Takes one argument, an IP address. Returns true or false depending on whether that IP is exempt from denial or not.

=item C<yield>

This method provides an alternative object based means of posting events to the component. First argument is the event to post, following arguments are sent as arguments to the resultant post.

=item C<call>

This method provides an alternative object based means of calling events to the component. First argument is the event to call, following arguments are sent as arguments to the resultant call.

=back

=head1 INPUT EVENTS

These are POE events that the component will accept:

=over

=item C<register>

Takes no arguments. Registers a session to receive events from the component.

=item C<unregister>

Takes no arguments. Unregisters a previously registered session.

=item C<add_listener>

Takes a number of arguments. Adds a new listener.

	'port', the TCP port to listen on. Default is a random port;
	'auth', enable or disable auth sub-system for this listener. Default enabled;
	'bindaddr', specify a local address to bind the listener to;
	'listenqueue', change the SocketFactory's ListenQueue;

=item C<del_listener>

Takes either 'port' or 'listener': 

	'listener' is a previously returned listener ID;
	'port', listening TCP port; 

The listener will be deleted. Note: any connected clients on that port will not be disconnected.

=item C<add_connector>

Takes two mandatory arguments, 'remoteaddress' and 'remoteport'. Opens a TCP connection to specified address and port.

	'remoteaddress', hostname or IP address to connect to;
	'remoteport', the TCP port on the remote host;
	'bindaddress', a local address to bind from ( optional );

=item C<send_output>

Takes a hashref and one or more connection IDs.

  $poe_kernel->post( $object->session_id() => send_output => 
	{ prefix => 'blah!~blah@blah.blah.blah',
	  command => 'PRIVMSG',
	  params  => [ '#moo', 'cows go moo, not fish :D' ] },
	@list_of_connection_ids );

=back

=head1 OUTPUT EVENTS

Once registered your session will receive these states, which will have the applicable prefix as specified to create() or the default which is 'ircd_backend_':

=over

=item C<registered>

  Emitted: when a session registers with the component;
  Target:	the registering session;
  Args: 
	ARG0, the component's object;

=item C<unregistered>

  Emitted: when a session unregisters with the component;
  Target: the unregistering session;
  Args: none

=item C<connection>

  Emitted: when a client connects to one of the component's listeners;
  Target: all plugins and registered sessions;
  Args:
	ARG0, the conn id;
	ARG1, their ip address;
	ARG2, their tcp port;
	ARG3, our ip address;
	ARG4, our socket port;

=item C<auth_done>

  Emitted: after a client has connected and the component has validated hostname and ident;
  Target: all plugins and registered sessions;
  Args:
	ARG0, the conn id;
	ARG1, a HASHREF with the following keys: 'ident' and 'hostname';

=item C<listener_add>

  Emitted: on a successful add_listener() call;
  Target: all plugins and registered sessions;
  Args:
	ARG0, the listening port;
	ARG1, the listener id;

=item C<listener_del>

  Emitted: on a successful del_listener() call;
  Target: all plugins and registered sessions;
  Args:
	ARG0, the listening port;
	ARG1, the listener id;

=item C<listener_failure>

  Emitted: when a listener wheel fails;
  Target: all plugins and registered sessions;
  Args:
	ARG0, the listener id;
	ARG1, the name of the operation that failed;
	ARG2, numeric value for $!;
	ARG3, string value for $!;

=item C<socketerr>

  Emitted: on the failure of an add_connector()
  Target: all plugins and registered sessions;
  Args:
	ARG0, a HASHREF containing the params that add_connector() was called with;

=item C<connected>

  Emitted: when the component establishes a connection with a peer;
  Target: all plugins and registered sessions;
  Args:
	ARG0, the conn id;
	ARG1, their ip address;
	ARG2, their tcp port;
	ARG3, our ip address;
	ARG4, our socket port;

=item C<connection_flood>

  Emitted: when a client connection is flooded;
  Target: all plugins and registered sessions;
  Args:
	ARG0, the conn id;

=item C<connection_idle>

  Emitted: when a client connection has not sent any data for a set period;
  Target: all plugins and registered sessions;
  Args:
	ARG0, the conn id;
	ARG1, the number of seconds period we consider as idle;

=item C<disconnected>

  Emitted: when a client disconnects;
  Target: all plugins and registered sessions;
  Args:
	ARG0, the conn id;
	ARG1, the error or reason for disconnection;

=item C<cmd_*>

  Emitted: when a client or peer sends a valid IRC line to us;
  Target: all plugins and registered sessions;
  Args:
	ARG0, the conn id;
	ARG1, a HASHREF containing the output record from POE::Filter::IRCD:
	{ prefix => 'blah!~blah@blah.blah.blah',
	  command => 'PRIVMSG',
	  params  => [ '#moo', 'cows go moo, not fish :D' ],
	  raw_line => ':blah!~blah@blah.blah.blah.blah PRIVMSG #moo :cows go moo, not fish :D' };

=back

=head1 PLUGIN SYSTEM

POE::Component::Server::IRC sports a plugin system remarkably similar to L<POE::Component::IRC>'s.

These are plugin related methods:

=over

=item C<pipeline>

Returns the L<POE::Component::Server::IRC::Pipeline> object used internally by the component.

=item C<plugin_add>

Accepts two arguments:

  The alias for the plugin
  The actual plugin object

The alias is there for the user to refer to it, as it is possible to have multiple
plugins of the same kind active in one PoCo-Server-IRC-Backend object.

Returns 1 if plugin was initialized, undef if not.

=item C<plugin_del>

Accepts one argument:

  The alias for the plugin or the plugin object itself

Returns the plugin object if the plugin was removed, undef if not.

=item C<plugin_get>

Accepts one argument:

  The alias for the plugin

Returns the plugin object if it was found, undef if not.

=item C<plugin_list>
=item C<plugin_order>

Has no arguments.

Returns a hashref of plugin objects, keyed on alias, or an empty list if there are no
plugins loaded.

=item C<plugin_register>
=item C<plugin_unregister>

See L<POE::Component::Server::IRC::Plugin> for details on these methods.

=back

And plugin related states, prefixed with the appropriate prefix or the default, 'ircd_backend_':

=over

=item C<plugin_add>

  Emitted: when the component successfully adds a new plugin;
  Target: all plugins and registered sessions;
  Args:
	ARG0, plugin alias;
	ARG1, plugin object;

=item C<plugin_del>

  Emitted: when the component successfully removes a plugin;
  Target: all plugins and registered sessions;
  Args:
	ARG0, plugin alias;
	ARG1, plugin object;

=back

=head1 AUTHOR

Chris 'BinGOs' Williams

=head1 LICENSE

Copyright E<copy> Chris Williams

This module may be used, modified, and distributed under the same terms as Perl itself. Please see the license that came with your Perl distribution for details.

=head1 SEE ALSO

L<POE::Filter::IRCD>

L<POE::Component::IRC>

L<POE>
