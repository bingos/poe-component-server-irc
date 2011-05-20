package POE::Component::Server::IRC::Backend;

use strict;
use warnings;
use Carp qw(croak);
use POE qw(Wheel::SocketFactory Wheel::ReadWrite Filter::Stackable
           Filter::Line Filter::IRCD);
use POE::Component::Server::IRC::Plugin qw(:ALL);
use Net::Netmask;
use Socket;
use base qw(POE::Component::Syndicator);

sub create {
    my $package = shift;
    croak("$package requires an even number of parameters") if @_ & 1;
    my %parms = @_;
    $parms{ lc $_ } = delete $parms{$_} for keys %parms;
    my $self = bless \%parms, $package;

    $self->{prefix}    = 'ircd_backend_' if !defined $self->{prefix};
    $self->{antiflood} = 1 if !defined $self->{antiflood};
    my $options        = delete $self->{options};
    my $sslify_options = delete $self->{sslify_options};
    my $plugin_debug   = delete $self->{plugin_debug};

    eval {
        require POE::Filter::Zlib::Stream;
        $self->{got_zlib} = 1;
    };

    if ($self->{auth}) {
        eval {
            require POE::Component::Client::Ident::Agent;
            $self->{got_ident} = 1;
        };
        if (!$self->{got_ident}) {
            croak('POE::Component::Client::Ident::Agent needed for authentication');
        }
        eval {
            require POE::Component::Client::DNS;
            $self->{got_dns} = 1;
        };
        if (!$self->{got_dns}) {
            croak('POE::Component::Client::DNS needed for authentication');
        }
    }

    if ($sslify_options && ref $sslify_options eq 'ARRAY') {
        eval {
            require POE::Component::SSLify;
            POE::Component::SSLify->import(
                qw(SSLify_Options Server_SSLify Client_SSLify)
            );
        };
        chomp $@;
        croak("Can't use ssl: $@") if $@;

        eval { SSLify_Options(@$sslify_options); };
        chomp $@;
        croak("Can't use ssl: $@") if $@;
        $self->{got_ssl} = 1;
    }


    $self->_syndicator_init(
        prefix     => $self->{prefix},
        reg_prefix => 'PCSI_',
        types      => [ SERVER => 'IRCD', USER => 'U' ],
        ($plugin_debug ? (debug => 1) : () ),
        object_states => [
            $self => {
                syndicator_started => '_start',
                add_connector      => '_add_connector',
                add_filter         => '_add_filter',
                add_listener       => '_add_listener',
                del_filter         => '_del_filter',
                del_listener       => '_del_listener',
                send_output        => '_send_output',
                shutdown           => '_shutdown',
            },
            $self => [qw(
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
                ident_agent_error
                ident_agent_reply
            )],
        ],
        (ref $options eq 'HASH' ? (options => $options) : ()),
    );

    return $self;
}

sub _start {
    my ($kernel, $self, $sender) = @_[KERNEL, OBJECT, SENDER];

    $self->{ircd_filter} = POE::Filter::IRCD->new(
        DEBUG    => $self->{debug},
        colonify => 1,
    );
    $self->{line_filter} = POE::Filter::Line->new(
        InputRegexp => '\015?\012',
        OutputLiteral => "\015\012",
    );
    $self->{filter} = POE::Filter::Stackable->new(
        Filters => [$self->{line_filter}, $self->{ircd_filter}],
    );

    if ($self->{auth}) {
        $self->{resolver} = POE::Component::Client::DNS->spawn(
            Alias   => 'poco_dns_' . $self->session_id(),
            Timeout => 10,
        );
    }

    $self->_load_our_plugins();

    return;
}

sub _load_our_plugins {
    return 1;
}

sub shutdown {
    my ($self) = shift;
    $self->yield('shutdown', @_);
    return;
}

sub _shutdown {
    my ($kernel, $self) = @_[KERNEL, OBJECT];

    $self->{terminating} = 1;
    delete $self->{listeners};
    delete $self->{connectors};
    delete $self->{wheels};
    $self->_syndicator_destroy();
    $self->_unload_our_plugins();
    return;
}

sub _unload_our_plugins {
    return 1;
}

sub _accept_failed {
    my ($kernel, $self, $operation, $errnum, $errstr, $listener_id)
        = @_[KERNEL, OBJECT, ARG0..ARG3];

    delete $self->{listeners}{$listener_id};
    $self->send_event(
        "$self->{prefix}listener_failure",
        $listener_id,
        $operation,
        $errnum,
        $errstr,
    );
    return;
}

sub _accept_connection {
    my ($kernel, $self, $socket, $peeraddr, $peerport, $listener_id)
        = @_[KERNEL, OBJECT, ARG0..ARG3];

    my $sockaddr = inet_ntoa((unpack_sockaddr_in(getsockname $socket))[1]);
    my $sockport = (unpack_sockaddr_in(getsockname $socket))[0];
    $peeraddr    = inet_ntoa($peeraddr);
    my $listener = $self->{listeners}{$listener_id};

    if ($self->{got_ssl} && $listener->{usessl}) {
        eval {
            $socket = POE::Component::SSLify::Server_SSLify($socket);
        };
        chomp $@;
        die "Failed to SSLify server socket: $@" if $@;
    }

    return if $self->denied($peeraddr);

    my $wheel = POE::Wheel::ReadWrite->new(
        Handle       => $socket,
        Filter       => $self->{filter},
        InputEvent   => '_conn_input',
        ErrorEvent   => '_conn_error',
        FlushedEvent => '_conn_flushed',
    );

    if ($wheel) {
        my $wheel_id = $wheel->ID();
        my $ref = {
            wheel     => $wheel,
            peeraddr  => $peeraddr,
            peerport  => $peerport,
            flooded   => 0,
            sockaddr  => $sockaddr,
            sockport  => $sockport,
            idle      => time(),
            antiflood => $listener->{antiflood},
            compress  => 0
        };

        $self->send_event(
            "$self->{prefix}connection",
            $wheel_id,
            $peeraddr,
            $peerport,
            $sockaddr,
            $sockport
        );

        if ($listener->{do_auth} && $self->{auth}) {
            $kernel->yield('_auth_client', $wheel_id);
        }
        else {
            $self->send_event(
                "$self->{prefix}auth_done",
                $wheel_id => {
                    ident    => '',
                    hostname => '',
                },
            );
        }

        $ref->{freq} = $listener->{freq};
        $ref->{alarm} = $kernel->delay_set(
            '_conn_alarm',
            $listener->{freq},
            $wheel_id,
        );
        $self->{wheels}{$wheel_id} = $ref;
    }
    return;
}

sub add_listener {
    my ($self) = shift;
    croak('add_listener requires an even number of parameters') if @_ & 1;
    $self->yield('add_listener', @_);
    return;
}

sub _add_listener {
    my ($kernel, $self) = @_[KERNEL, OBJECT];
    my %args = @_[ARG0..$#_];

    $args{ lc($_) } = delete $args{$_} for keys %args;

    my $bindport  = $args{port} || 0;
    my $freq      = $args{freq} || 180;
    my $auth      = 1;
    my $antiflood = 1;
    my $usessl    = 0;
    $usessl    = 1 if $args{usessl};
    $auth      = 0 if defined $args{auth} && $args{auth} eq '0';
    $antiflood = 0 if defined $args{antiflood} && $args{antiflood} eq '0';

    my $listener = POE::Wheel::SocketFactory->new(
        BindPort     => $bindport,
        SuccessEvent => '_accept_connection',
        FailureEvent => '_accept_failed',
        Reuse        => 'on',
        ($args{bindaddr} ? (BindAddress => $args{bindaddr}) : ()),
        ($args{listenqueue} ? (ListenQueue => $args{listenqueue}) : ()),
    );

    if ($listener) {
        my $port = (unpack_sockaddr_in($listener->getsockname))[0];
        my $listener_id = $listener->ID();
        $self->send_event(
            $self->{prefix} . 'listener_add',
            $port,
            $listener_id,
        );
        $self->{listening_ports}{$port} = $listener_id;
        $self->{listeners}{$listener_id}{wheel}     = $listener;
        $self->{listeners}{$listener_id}{port}      = $port;
        $self->{listeners}{$listener_id}{freq}      = $freq;
        $self->{listeners}{$listener_id}{do_auth}   = $auth;
        $self->{listeners}{$listener_id}{antiflood} = $antiflood;
        $self->{listeners}{$listener_id}{usessl}    = $usessl;
    }
    return;
}

sub del_listener {
    my ($self) = shift;
    croak("add_listener requires an even number of parameters") if @_ & 1;
    $self->yield('del_listener', @_);
    return;
}

sub _del_listener {
    my ($kernel, $self) = @_[KERNEL, OBJECT];
    my %args = @_[ARG0..$#_];

    $args{lc $_} = delete $args{$_} for keys %args;

    my $listener_id = delete $args{listener};
    my $port = delete $args{port};

    if ($self->_listener_exists($listener_id)) {
        $port = delete $self->{listeners}{$listener_id}{port};
        delete $self->{listening_ports}{$port};
        delete $self->{listeners}{$listener_id};
        $self->send_event(
            $self->{prefix} . 'listener_del',
            $port,
            $listener_id,
        );
    }

    if ($self->_port_exists($port)) {
        $listener_id = delete $self->{listening_ports}{$port};
        delete $self->{listeners}{$listener_id};
        $self->send_event(
            $self->{prefix} . 'listener_del',
            $port,
            $listener_id,
        );
    }

    return;
}

sub _listener_exists {
    my $self = shift;
    my $listener_id = shift || return;
    return 1 if defined $self->{listeners}{$listener_id};
    return;
}

sub _port_exists {
    my $self = shift;
    my $port = shift || return;
    return 1 if defined $self->{listening_ports}->{$port};
    return;
}

sub add_connector {
    my $self = shift;
    croak("add_connector requires an even number of parameters") if @_ & 1;
    $self->yield('add_connector', @_);
    return;
}

sub _add_connector {
    my ($kernel, $self, $sender) = @_[KERNEL, OBJECT, SENDER];
    my %args = @_[ARG0..$#_];

    $args{lc $_} = delete $args{$_} for keys %args;

    my $remoteaddress = $args{remoteaddress};
    my $remoteport = $args{remoteport};

    return if !$remoteaddress || !$remoteport;

    my $wheel = POE::Wheel::SocketFactory->new(
        SocketDomain   => AF_INET,
        SocketType     => SOCK_STREAM,
        SocketProtocol => 'tcp',
        RemoteAddress  => $remoteaddress,
        RemotePort     => $remoteport,
        SuccessEvent   => '_sock_up',
        FailureEvent   => '_sock_failed',
        ($args{bindaddress} ? (BindAddress => $args{bindaddress}) : ()),
    );

    if ($wheel) {
        $args{wheel} = $wheel;
        $self->{connectors}{$wheel->ID()} = \%args;
    }
    return;
}

sub _sock_failed {
    my ($kernel, $self, $op, $errno, $errstr, $connector_id)
        = @_[KERNEL, OBJECT, ARG0..ARG3];

    my $ref = delete $self->{connectors}{$connector_id};
    delete $ref->{wheel};
    $self->send_event("$self->{prefix}socketerr",$ref);
    return;
}

sub _sock_up {
    my ($kernel, $self, $socket, $peeraddr, $peerport, $connector_id)
        = @_[KERNEL, OBJECT, ARG0..ARG3];
    $peeraddr = inet_ntoa($peeraddr);

    my $cntr = delete $self->{connectors}{$connector_id};
    if ($self->{got_ssl} && $cntr->{usessl}) {
        eval {
            $socket = POE::Component::SSLify::Client_SSLify($socket);
        };
        chomp $@;
        die "Failed to SSLify client socket: $@" if $@;
    }

    my $wheel = POE::Wheel::ReadWrite->new(
        Handle       => $socket,
        InputEvent   => '_conn_input',
        ErrorEvent   => '_conn_error',
        FlushedEvent => '_conn_flushed',
        Filter       => POE::Filter::Stackable->new(
            Filters => [$self->{filter}],
        ),
    );

    return if !$wheel;
    my $wheel_id = $wheel->ID();
    my $sockaddr = inet_ntoa((unpack_sockaddr_in(getsockname $socket))[1]);
    my $sockport = (unpack_sockaddr_in(getsockname $socket))[0];
    my $ref = {
        wheel     => $wheel,
        peeraddr  => $peeraddr,
        peerport  => $peerport,
        sockaddr  => $sockaddr,
        sockport  => $sockport,
        idle      => time(),
        antiflood => 0,
        compress  => 0,
    };

    $self->{wheels}{$wheel_id} = $ref;
    $self->send_event(
        "$self->{prefix}connected",
        $wheel_id,
        $peeraddr,
        $peerport,
        $sockaddr,
        $sockport,
        $cntr->{name}
    );
    return;
}

sub _add_filter {
    my ($kernel, $self, $sender) = @_[KERNEL, OBJECT, SENDER];
    my $wheel_id = $_[ARG0] || croak("You must supply a connection id\n");
    my $filter = $_[ARG1] || croak("You must supply a filter object\n");
    return if !$self->_wheel_exists($wheel_id);

    my $stackable = POE::Filter::Stackable->new(
        Filters => [
            $self->{line_filter},
            $self->{ircd_filter},
            $filter,
        ],
    );

    if ($self->compressed_link($wheel_id)) {
        $stackable->unshift(POE::Filter::Zlib::Stream->new());
    }
    $self->{wheels}{$wheel_id}{wheel}->set_filter($stackable);
    $self->send_event("$self->{prefix}filter_add", $wheel_id, $filter);
    return;
}

sub _anti_flood {
    my ($self, $wheel_id, $input) = splice @_, 0, 3;
    my $current_time = time();

    return if !$wheel_id || !$self->_wheel_exists($wheel_id) || !$input;

    SWITCH: {
        if ($self->{wheels}->{ $wheel_id }->{flooded}) {
            last SWITCH;
        }
        if (!$self->{wheels}{$wheel_id}{timer}
            || $self->{wheels}{$wheel_id}{timer} < $current_time) {

            $self->{wheels}{$wheel_id}{timer} = $current_time;
            my $event = "$self->{prefix}cmd_" . lc $input->{command};
            $self->send_event($event, $wheel_id, $input);
            last SWITCH;
        }
        if ($self->{wheels}{$wheel_id}{timer} <= $current_time + 10) {
            $self->{wheels}{$wheel_id}{timer} += 1;
            push @{ $self->{wheels}{$wheel_id}{msq} }, $input;
            push @{ $self->{wheels}{$wheel_id}{alarm_ids} },
                $poe_kernel->alarm_set(
                    '_event_dispatcher',
                    $self->{wheels}{$wheel_id}{timer},
                    $wheel_id
                );
            last SWITCH;
        }

        $self->{wheels}{$wheel_id}{flooded} = 1;
        $self->send_event("$self->{prefix}connection_flood", $wheel_id);
    }

    return 1;
}

sub _conn_error {
    my ($self, $errstr, $wheel_id) = @_[OBJECT, ARG2, ARG3];
    return if !$self->_wheel_exists($wheel_id);
    $self->_disconnected(
        $wheel_id,
        $errstr || $self->{wheels}{$wheel_id}{disconnecting}
    );
    return;
}

sub _conn_alarm {
    my ($kernel, $self, $wheel_id) = @_[KERNEL, OBJECT, ARG0];
    return if !$self->_wheel_exists($wheel_id);
    my $conn = $self->{wheels}{$wheel_id};

    $self->send_event(
        "$self->{prefix}connection_idle",
        $wheel_id,
        $conn->{freq},
    );
    $conn->{alarm} = $kernel->delay_set(
        '_conn_alar',
        $conn->{freq},
        $wheel_id,
    );

    return;
}

sub _conn_flushed {
    my ($kernel, $self, $wheel_id) = @_[KERNEL, OBJECT, ARG0];
    return if !$self->_wheel_exists($wheel_id);

    if ($self->{wheels}{$wheel_id}{disconnecting}) {
        $self->_disconnected(
            $wheel_id,
            $self->{wheels}{$wheel_id}{disconnecting},
        );
        return;
    }

    if ($self->{wheels}{$wheel_id}{compress_pending}) {
        delete $self->{wheels}{$wheel_id}{compress_pending};
        $self->{wheels}{$wheel_id}{wheel}->get_input_filter()->unshift(
            POE::Filter::Zlib::Stream->new(),
        );
        $self->send_event("$self->{prefix}compressed_conn", $wheel_id);
        return;
    }
    return;
}

sub _conn_input {
    my ($kernel, $self, $input, $wheel_id) = @_[KERNEL, OBJECT, ARG0, ARG1];
    my $conn = $self->{wheels}{$wheel_id};

    if ($self->{raw_events}) {
        $self->send_event(
            "$self->{prefix}raw_input",
            $wheel_id,
            $input->{raw_line},
        );
    }
    $conn->{seen} = time();
    $kernel->delay_adjust($conn->{alarm}, $conn->{freq});

    # TODO: Antiflood code
    if ($self->antiflood($wheel_id)) {
        $self->_anti_flood($wheel_id, $input);
    }
    else {
        my $event = "$self->{prefix}cmd_" . lc $input->{command};
        $self->send_event($event, $wheel_id, $input);
    }
    return;
}

sub _del_filter {
    my ($kernel, $self, $sender) = @_[KERNEL, OBJECT, SENDER];
    my $wheel_id = $_[ARG0] || croak("You must supply a connection id\n");
    return if !$self->_wheel_exists($wheel_id);

    $self->{wheels}{$wheel_id}{wheel}->set_filter($self->{filter});
    $self->send_event("$self->{prefix}filter_del", $wheel_id);
    return;
}

sub _event_dispatcher {
    my ($kernel, $self, $wheel_id) = @_[KERNEL, OBJECT, ARG0];

    if (!$self->_wheel_exists($wheel_id)
        || $self->{wheels}{$wheel_id}{flooded}) {
        return;
    }

    shift @{ $self->{wheels}{$wheel_id}{alarm_ids} };
    my $input = shift @{ $self->{wheels}{$wheel_id}{msq} };

    if ($input) {
        my $event = "$self->{prefix}cmd_" . lc $input->{command};
        $self->send_event($event, $wheel_id, $input);
    }
    return;
}

sub send_output {
    my ($self, $output) = splice @_, 0, 2;

    if ($output && ref $output eq 'HASH') {
        if (@_ == 1 || $output->{command}
            && $output->{command} eq 'ERROR') {

            for my $id (grep { $self->_wheel_exists($_) } @_) {
                $self->{wheels}{ $id}{wheel}->put($output);
            }
            return 1;
        }

        for my $id (grep { $self->_wheel_exists($_) } @_) {
            $self->yield('__send_output', $output, $id);
        }
        return 1;
    }

    return;
}

sub __send_output {
    my ($self, $output, $route_id) = @_[OBJECT, ARG0, ARG1];
    if ($self->_wheel_exists($route_id)) {
        $self->{wheels}{$route_id}{wheel}->put($output);
    }
    return;
}

sub _send_output {
    $_[OBJECT]->send_output(@_[ARG0..$#_]);
    return;
}

sub _auth_client {
    my ($kernel, $self, $wheel_id) = @_[KERNEL, OBJECT, ARG0];
    return if !$self->_wheel_exists($wheel_id);

    my ($peeraddr, $peerport, $sockaddr, $sockport)
        = $self->connection_info($wheel_id);

    $self->send_output(
        {
            command => 'NOTICE',
            params  => ['AUTH', '*** Checking Ident'],
        },
        $wheel_id,
    );

    $self->send_output(
        {
            command => 'NOTICE',
            params  => ['AUTH', '*** Checking Hostname'],
        },
        $wheel_id,
    );

    if ($peeraddr !~ /^127\./) {
        my $response = $self->{resolver}->resolve(
            event   => '_got_hostname_response',
            host    => $peeraddr,
            type    => 'PTR',
            context => {
                wheel       => $wheel_id,
                peeraddress => $peeraddr,
            },
        );

        if ($response) {
            $kernel->yield('_got_hostname_response', $response);
        }
    }
    else {
        $self->send_output(
            {
                command => 'NOTICE',
                params  => ['AUTH', '*** Found your hostname']
            },
            $wheel_id,
        );
        $self->{wheels}{$wheel_id}{auth}{hostname} = 'localhost';
        $self->yield('_auth_done', $wheel_id);
    }

    POE::Component::Client::Ident::Agent->spawn(
        PeerAddr    => $peeraddr,
        PeerPort    => $peerport,
        SockAddr    => $sockaddr,
        SockPort    => $sockport,
        BuggyIdentd => 1,
        TimeOut     => 10,
        Reference   => $wheel_id,
    );
    return;
}

sub _auth_done {
    my ($kernel, $self, $wheel_id) = @_[KERNEL, OBJECT, ARG0];

    return if !$self->_wheel_exists($wheel_id);
    if (defined $self->{wheels}{$wheel_id}{auth}{ident}
        && defined $self->{wheels}{$wheel_id}{auth}{hostname}) {

        if (!$self->{wheels}{$wheel_id}{auth}{done}) {
            $self->send_event(
                "$self->{prefix}auth_done",
                $wheel_id => {
                    ident    => $self->{wheels}{$wheel_id}{auth}{ident},
                    hostname => $self->{wheels}{$wheel_id}{auth}{hostname},
                },
            );
        }
        $self->{wheels}->{ $wheel_id }->{auth}->{done}++;
    }
    return;
}

sub _got_hostname_response {
    my ($kernel, $self) = @_[KERNEL, OBJECT];
    my $response = $_[ARG0];
    my $wheel_id = $response->{context}{wheel};

    return if !$self->_wheel_exists($wheel_id);

    if (!defined $response->{response}) {
        if (!defined $self->{wheels}{$wheel_id}{auth}{hostname}) {
            # Send NOTICE to client of failure.
            $self->send_output(
                {
                    command => 'NOTICE',
                    params  => [
                        'AUTH',
                        "*** Couldn\'t look up your hostname",
                    ],
                },
                $wheel_id,
            );
        }
        $self->{wheels}{$wheel_id}{auth}{hostname} = '';
        $self->yield('_auth_done', $wheel_id);
        return;
    }

    my @answers = $response->{response}->answer();

    if (@answers == 0) {
        if (!defined $self->{wheels}{$wheel_id}{auth}{hostname}) {
            # Send NOTICE to client of failure.
            $self->send_output(
                {
                    command => 'NOTICE',
                    params  => [
                        'AUTH',
                        "*** Couldn\'t look up your hostname",
                    ]
                },
                $wheel_id,
            );
        }
        $self->{wheels}->{ $wheel_id }->{auth}->{hostname} = '';
        $self->yield( '_auth_done' => $wheel_id );
    }

    for my $answer (@answers) {
        my $context = $response->{context};
        $context->{hostname} = $answer->rdatastr();

        chop $context->{hostname} if $context->{hostname} =~ /\.$/;
        my $query = $self->{resolver}->resolve(
            event   => '_got_ip_response',
            host    => $answer->rdatastr(),
            context => $context,
            type    => 'A'
        );
        if (defined $query) {
            $self->yield('_got_ip_response', $query);
        }
    }

    return;
}

sub _got_ip_response {
    my ($kernel, $self) = @_[KERNEL, OBJECT];
    my $response = $_[ARG0];
    my $wheel_id = $response->{context}{wheel};

    return if !$self->_wheel_exists($wheel_id);

    if (!defined $response->{response}) {
        # Send NOTICE to client of failure.
        if (!$self->{wheels}{$wheel_id}{auth}{hostname}) {
            $self->send_output(
                {
                    command => 'NOTICE',
                    params  => [
                        'AUTH',
                        "*** Couldn't look up your hostname",
                    ],
                },
                $wheel_id,
            );
        }
        $self->{wheels}{$wheel_id}{auth}{hostname} = '';
        $self->yield('_auth_done', $wheel_id);
    }

    my @answers     = $response->{response}->answer();
    my $peeraddress = $response->{context}{peeraddress};
    my $hostname    = $response->{context}{hostname};

    if (@answers == 0) {
        if (!defined $self->{wheels}{$wheel_id}{auth}{hostname}) {
            # Send NOTICE to client of failure.
            $self->send_output(
                {
                    command => 'NOTICE',
                    params  => [
                        'AUTH',
                        "*** Couldn\'t look up your hostname",
                    ],
                },
                $wheel_id,
            );
        }
        $self->{wheels}{$wheel_id}{auth}{hostname} = '';
        $self->yield('_auth_done', $wheel_id);
    }

    for my $answer (@answers) {
        if ($answer->rdatastr() eq $peeraddress
            && !defined $self->{wheels}{$wheel_id}{auth}{hostname}) {

            if (!$self->{wheels}{$wheel_id}{auth}{hostname}) {
                $self->send_output(
                    {
                        command => 'NOTICE',
                        params  => ['AUTH', '*** Found your hostname'],
                    },
                    $wheel_id,
                );
            }
            $self->{wheels}{$wheel_id}{auth}{hostname} = $hostname;
            $self->yield('_auth_done', $wheel_id);
            return;
        }
        else {
            if (!$self->{wheels}->{ $wheel_id }->{auth}->{hostname}) {
                $self->send_output(
                    {
                        command => 'NOTICE',
                        params  => [
                            'AUTH',
                            '*** Your forward and reverse DNS do not match',
                        ],
                    },
                    $wheel_id,
                );
            }
            $self->{wheels}->{ $wheel_id }->{auth}->{hostname} = '';
            $self->yield( '_auth_done' => $wheel_id );
        }
    }
    return;
}

sub ident_agent_reply {
    my ($kernel, $self, $ref, $opsys, $other)
        = @_[KERNEL, OBJECT, ARG0, ARG1, ARG2];
    my $wheel_id = $ref->{Reference};

    if ($self->_wheel_exists($wheel_id)) {
        my $ident = '';
        $ident = $other if uc $opsys ne 'OTHER';
        $self->send_output(
            {
                command => 'NOTICE',
                params  => ['AUTH', "*** Got Ident response"],
            },
            $wheel_id
        );
        $self->{wheels}{$wheel_id}{auth}{ident} = $ident;
        $self->yield('_auth_done', $wheel_id);
    }
    return;
}

sub ident_agent_error {
    my ($kernel, $self, $ref, $error) = @_[KERNEL, OBJECT, ARG0, ARG1];
    my $wheel_id = $ref->{Reference};

    if ($self->_wheel_exists($wheel_id)) {
        $self->send_output(
            {
                command => 'NOTICE',
                params  => ['AUTH', "*** No Ident response"],
            },
            $wheel_id
        );
        $self->{wheels}{$wheel_id}{auth}{ident} = '';
        $self->yield('_auth_done', $wheel_id);
    }
    return;
}

sub antiflood {
    my ($self, $wheel_id, $value) = splice @_, 0, 3;
    return if !$self->_wheel_exists($wheel_id);
    return 0 if !$self->{antiflood};
    return $self->{wheels}{$wheel_id}{antiflood} if !defined $value;

    if (!$value) {
        # Flush pending messages from that wheel
        while (my $alarm_id = shift @{ $self->{wheels}{$wheel_id}{alarm_ids} }) {
            $poe_kernel->alarm_remove($alarm_id);
            my $input = shift @{ $self->{wheels}{$wheel_id}{msq} };

            if ($input) {
                my $event = "$self->{prefix}cmd_" . lc $input->{command};
                $self->send_event($event, $wheel_id, $input);
            }
        }
    }

    $self->{wheels}{$wheel_id}{antiflood} = $value;
    return;
}

sub compressed_link {
    my ($self, $wheel_id, $value, $cntr) = splice @_, 0, 4;
    return if !$self->_wheel_exists($wheel_id);
    return 0 if !$self->{got_zlib};
    return $self->{wheels}{$wheel_id}{compress} if !defined $value;

    if ($value) {
        if ($cntr) {
            $self->{wheels}{$wheel_id}{wheel}->get_input_filter()->unshift(
                POE::Filter::Zlib::Stream->new()
            );
            $self->send_event(
                "$self->{prefix}compressed_conn",
                $wheel_id,
            );
        }
        else {
            $self->{wheels}{$wheel_id}{compress_pending} = 1;
        }
    }
    else {
        $self->{wheels}{$wheel_id}{wheel}->get_input_filter()->shift();
    }

    $self->{wheels}{$wheel_id}{compress} = $value;
    return;
}

sub disconnect {
    my ($self, $wheel_id, $string) = splice @_, 0, 3;
    return if !$wheel_id || !$self->_wheel_exists($wheel_id);
    $self->{wheels}{$wheel_id}{disconnecting} = $string || 'Client Quit';
    return;
}

sub _disconnected {
    my ($self, $wheel_id, $errstr) = splice @_, 0, 3;
    return if !$wheel_id || !$self->_wheel_exists($wheel_id);

    my $conn = delete $self->{wheels}{$wheel_id};
    for my $alarm_id ($conn->{alarm}, @{ $conn->{alarm_ids} }) {
        $poe_kernel->alarm_remove($_);
    }
    $self->send_event(
        "$self->{prefix}disconnected",
        $wheel_id,
        $errstr || 'Client Quit',
    );

    return 1;
}

sub connection_info {
    my ($self, $wheel_id) = splice @_, 0, 2;
    return if !$self->_wheel_exists($wheel_id);
    return map {
        $self->{wheels}{$wheel_id}{$_}
    } qw(peeraddr peerport sockaddr sockport);
}

sub _wheel_exists {
    my ($self, $wheel_id) = @_;
    return if !$wheel_id || !defined $self->{wheels}{$wheel_id};
    return 1;
}

sub _conn_flooded {
    my $self = shift;
    my $conn_id = shift || return;
    return if !$self->_wheel_exists($conn_id);
    return $self->{wheels}{$conn_id}{flooded};
}

sub add_denial {
    my $self = shift;
    my $netmask = shift || return;
    my $reason = shift || 'Denied';
    return if !$netmask->isa('Net::Netmask');

    $self->{denials}{$netmask} = {
        blk    => $netmask,
        reason => $reason,
    };
    return 1;
}

sub del_denial {
    my $self = shift;
    my $netmask = shift || return;
    return if !$netmask->isa('Net::Netmask');
    return if !$self->{denials}{$netmask};
    delete $self->{denials}{$netmask};
    return 1;
}

sub add_exemption {
    my $self = shift;
    my $netmask = shift || return;
    return if !$netmask->isa('Net::Netmask');

    if (!$self->{exemptions}{$netmask}) {
        $self->{exemptions}{$netmask} = $netmask;
    }
    return 1;
}

sub del_exemption {
    my $self = shift;
    my $netmask = shift || return;
    return if !$netmask->isa('Net::Netmask');
    return if !$self->{exemptions}{$netmask};
    delete $self->{exemptions}{$netmask};
    return 1;
}

sub denied {
    my $self = shift;
    my $ipaddr = shift || return;
    return if $self->exempted($ipaddr);

    for my $mask (keys %{ $self->{denials} }) {
        if ($self->{denials}{$mask}{blk}->match($ipaddr)) {
            return $self->{denials}{$mask}{reason};
        }
    }

    return;
}

sub exempted {
    my $self = shift;
    my $ipaddr = shift || return;
    for my $mask (keys %{ $self->{exemptions} }) {
        return 1 if $self->{exemptions}{$mask}->match($ipaddr);
    }
    return;
}

1;

=head1 NAME

POE::Component::Server::IRC::Backend - A POE component class that provides network connection abstraction for POE::Component::Server::IRC

=head1 SYNOPSIS

 use POE qw(Component::Server::IRC::Backend);

 my $object = POE::Component::Server::IRC::Backend->create();

 POE::Session->create(
     package_states => [
         main => [qw(_start)],
     ],
     heap => { ircd => $object },
 );

 $poe_kernel->run();

  sub _start {
  }

=head1 DESCRIPTION

POE::Component::Server::IRC::Backend - A POE component class that provides
network connection abstraction for
L<POE::Component::Server::IRC|POE::Component::Server::IRC>. It uses a
plugin system. See
L<POE::Component::Server::IRC::Plugin|POE::Component::Server::IRC::Plugin>
for details.

=head1 CONSTRUCTOR

=head2 C<create>

Returns an object. Accepts the following parameters, all are optional: 

=over

=item B<'alias'>, a POE::Kernel alias to set;

=item B<'auth'>, set to 0 to globally disable IRC authentication, default
is auth is enabled;

=item B<'antiflood'>, set to 0 to globally disable flood protection;

=item B<'prefix'>, this is the prefix that is used to generate event names
that the component produces. The default is 'ircd_backend_'.

=back

 my $object = POE::Component::Server::IRC::Backend->create( 
     alias => 'ircd', # Set an alias, default, no alias set.
     auth  => 0, # Disable auth globally, default enabled.
     antiflood => 0, # Disable flood protection globally, default enabled.
 );

If the component is created from within another session, that session will
be automagcially registered with the component to receive events and get
an 'ircd_backend_registered' event.

=head1 METHODS

These are the methods that may be invoked on our object.

=head2 C<shutdown>

Takes no arguments. Terminates the component. Removes all listeners and
connectors. Disconnects all current client and server connections.

=head2 C<antiflood>

Takes two arguments, a connection id and true/false value. If value is
specified antiflood protection is enabled or disabled accordingly for the
specified connection. If a value is not specified the current status of
antiflood protection is returned. Returns undef on error.

=head2 C<compressed_link>

Takes two arguments, a connection id and true/false value. If value is
specified compression is enabled or disabled accordingly for the specified
connection. If a value is not specified the current status of compression
is returned. Returns undef on error.

=head2 C<disconnect>

Requires on argument, the connection id you wish to disconnect. The
component will terminate the connection the next time that the wheel input
is flushed, so you may send some sort of error message to the client on
that connection. Returns true on success, undef on error.

=head2 C<connection_info>

Takes one argument, a connection_id. Returns a list consisting of: the IP
address of the peer; the port on the peer; our socket address; our socket
port. Returns undef on error.

 my ($peeraddr, $peerport, $sockaddr, $sockport) = $object->connection_info($conn_id);

=head2 C<add_denial>

Takes one mandatory argument and one optional. The first mandatory
argument is a L<Net::Netmask> object that will be used to check
connecting IP addresses against. The second optional argument is a reason
string for the denial.

=head2 C<del_denial>

Takes one mandatory argument, a L<Net::Netmask> object to remove from the
current denial list.

=head2 C<denied>

Takes one argument, an IP address. Returns true or false depending on
whether that IP is denied or not.

=head2 C<add_exemption>

Takes one mandatory argument, a L<Net::Netmask> object that will be
checked against connecting IP addresses for exemption from denials.

=head2 C<del_exemption>

Takes one mandatory argument, a L<Net::Netmask> object to remove from the
current exemption list.

=head2 C<exempted>

Takes one argument, an IP address. Returns true or false depending on
whether that IP is exempt from denial or not.

=head2 C<session_id>

I<Inherited from L<POE::Component::Syndicator|POE::Component::Syndicator/session_id>>

Takes no arguments. Returns the ID of the component's session. Ideal for posting
events to the component.

 $kernel->post($irc->session_id() => 'mode' => $channel => '+o' => $dude);

=head2 C<session_alias>

I<Inherited from L<POE::Component::Syndicator|POE::Component::Syndicator/session_alias>>

Takes no arguments. Returns the session alias that has been set through
L<C<spawn>|/spawn>'s alias argument.

=head2 C<yield>

I<Inherited from L<POE::Component::Syndicator|POE::Component::Syndicator/yield>>

This method provides an alternative object based means of posting events to the
component. First argument is the event to post, following arguments are sent as
arguments to the resultant post.

 $irc->yield(mode => $channel => '+o' => $dude);

=head2 C<call>

I<Inherited from L<POE::Component::Syndicator|POE::Component::Syndicator/call>>

This method provides an alternative object based means of calling events to the
component. First argument is the event to call, following arguments are sent as
arguments to the resultant
call.

=head2 C<delay>

I<Inherited from L<POE::Component::Syndicator|POE::Component::Syndicator/delay>>

This method provides a way of posting delayed events to the component. The
first argument is an arrayref consisting of the delayed command to post and
any command arguments. The second argument is the time in seconds that one
wishes to delay the command being posted.

 my $alarm_id = $ircd->delay( [ mode => $channel => '+o' => $dude ], 60 );

Returns an alarm ID that can be used with L<C<delay_remove>|/delay_remove>
to cancel the delayed event. This will be undefined if something went wrong.

=head2 C<delay_remove>

I<Inherited from L<POE::Component::Syndicator|POE::Component::Syndicator/delay_remove>>

This method removes a previously scheduled delayed event from the component.
Takes one argument, the C<alarm_id> that was returned by a
L<C<delay>|/delay> method call.

 my $arrayref = $ircd->delay_remove( $alarm_id );

Returns an arrayref that was originally requested to be delayed.

=head2 C<send_event>

I<Inherited from L<POE::Component::Syndicator|POE::Component::Syndicator/send_event>>

Sends an event through the component's event handling system. These will get
processed by plugins then by registered sessions. First argument is the event
name, followed by any parameters for that event.

=head2 C<send_event_next>

I<Inherited from L<POE::Component::Syndicator|POE::Component::Syndicator/send_event_next>>

This sends an event right after the one that's currently being processed.
Useful if you want to generate some event which is directly related to
another event so you want them to appear together. This method can only be
called when POE::Component::IRC is processing an event, e.g. from one of your
event handlers. Takes the same arguments as L<C<send_event>/send_event>.

=head2 C<send_event_now>

I<Inherited from L<POE::Component::Syndicator|POE::Component::Syndicator/send_event_now>>

This will send an event to be processed immediately. This means that if an
event is currently being processed and there are plugins or sessions which
will receive it after you do, then an event sent with C<send_event_now> will
be received by those plugins/sessions I<before> the current event. Takes the
same arguments as L<C<send_event>/send_event>.

=head2 C<pipeline>

I<Inherited from L<Object::Pluggable|Object::Pluggable/pipeline>>

Returns the L<Object::Pluggable::Pipeline|Object::Pluggable::Pipeline>
object.

=head2 C<plugin_add>

I<Inherited from L<Object::Pluggable|Object::Pluggable/plugin_add>>

Accepts two arguments:

 The alias for the plugin
 The actual plugin object
 Any number of extra arguments

The alias is there for the user to refer to it, as it is possible to have
multiple plugins of the same kind active in one Object::Pluggable object.

This method goes through the pipeline's C<push()> method, which will call
C<< $plugin->plugin_register($pluggable, @args) >>.

Returns the number of plugins now in the pipeline if plugin was initialized,
C<undef>/an empty list if not.

=head2 C<plugin_del>

I<Inherited from L<Object::Pluggable|Object::Pluggable/plugin_del>>

Accepts the following arguments:

 The alias for the plugin or the plugin object itself
 Any number of extra arguments

This method goes through the pipeline's C<remove()> method, which will call
C<< $plugin->plugin_unregister($pluggable, @args) >>.

Returns the plugin object if the plugin was removed, C<undef>/an empty list
if not.

=head2 C<plugin_get>

I<Inherited from L<Object::Pluggable|Object::Pluggable/plugin_get>>

Accepts the following arguments:

 The alias for the plugin

This method goes through the pipeline's C<get()> method.

Returns the plugin object if it was found, C<undef>/an empty list if not.

=head2 C<plugin_list>

I<Inherited from L<Object::Pluggable|Object::Pluggable/plugin_list>>

Takes no arguments.

Returns a hashref of plugin objects, keyed on alias, or an empty list if
there are no plugins loaded.

=head2 C<plugin_order>

I<Inherited from L<Object::Pluggable|Object::Pluggable/plugin_order>>

Takes no arguments.

Returns an arrayref of plugin objects, in the order which they are
encountered in the pipeline.

=head2 C<plugin_register>

I<Inherited from L<Object::Pluggable|Object::Pluggable/plugin_register>>

Accepts the following arguments:

 The plugin object
 The type of the hook (the hook types are specified with _pluggable_init()'s 'types')
 The event name[s] to watch

The event names can be as many as possible, or an arrayref. They correspond
to the prefixed events and naturally, arbitrary events too.

You do not need to supply events with the prefix in front of them, just the
names.

It is possible to register for all events by specifying 'all' as an event.

Returns 1 if everything checked out fine, C<undef>/an empty list if something
is seriously wrong.

=head2 C<plugin_unregister>

I<Inherited from L<Object::Pluggable|Object::Pluggable/plugin_unregister>>

Accepts the following arguments:

 The plugin object
 The type of the hook (the hook types are specified with _pluggable_init()'s 'types')
 The event name[s] to unwatch

The event names can be as many as possible, or an arrayref. They correspond
to the prefixed events and naturally, arbitrary events too.

You do not need to supply events with the prefix in front of them, just the
names.

It is possible to register for all events by specifying 'all' as an event.

Returns 1 if all the event name[s] was unregistered, undef if some was not
found.

=head1 INPUT EVENTS

These are POE events that the component will accept:

=head2 C<register>

Takes no arguments. Registers a session to receive events from the component.

=head2 C<unregister>

Takes no arguments. Unregisters a previously registered session.

=head2 C<add_listener>

Takes a number of arguments. Adds a new listener.

=over

=item B<'port'>, the TCP port to listen on. Default is a random port;

=item B<'auth'>, enable or disable auth sub-system for this listener. Default
enabled;

=item B<'bindaddr'>, specify a local address to bind the listener to;

=item B<'listenqueue'>, change the SocketFactory's ListenQueue;

=back

=head2 C<del_listener>

Takes either 'port' or 'listener': 

B<'listener'> is a previously returned listener ID;
B<'port'>, listening TCP port; 

The listener will be deleted. Note: any connected clients on that port
will not be disconnected.

=head2 C<add_connector>

Takes two mandatory arguments, B<'remoteaddress'> and B<'remoteport'>.
Opens a TCP connection to specified address and port.

=over

=item B<'remoteaddress'>, hostname or IP address to connect to;

=item B<'remoteport'>, the TCP port on the remote host;

=item B<'bindaddress'>, a local address to bind from (optional);

=back

=head2 C<send_output>

Takes a hashref and one or more connection IDs.

 $poe_kernel->post(
     $object->session_id(),
     'send_output',
     {
         prefix  => 'blah!~blah@blah.blah.blah',
         command => 'PRIVMSG',
         params  => ['#moo', 'cows go moo, not fish :D']
     },
     @list_of_connection_ids,
 );

=head1 OUTPUT EVENTS

Once registered your session will receive these states, which will have the
applicable prefix as specified to L<C<create>|/create> or the default which
is 'ircd_backend_':

=head2 C<registered>

=over

=item Emitted: when a session registers with the component;

=item Target: the registering session;

=item Args:

=over

=item C<ARG0>: the component's object;

=back

=back

=head2 C<unregistered>

=over

=item Emitted: when a session unregisters with the component;

=item Target: the unregistering session;

=item Args: none

=back

=head2 C<connection>

=over

=item Emitted: when a client connects to one of the component's listeners;

=item Target: all plugins and registered sessions

=item Args:

=over

=item C<ARG0>: the conn id;

=item C<ARG1>: their ip address;

=item C<ARG2>: their tcp port;

=item C<ARG3>: our ip address;

=item C<ARG4>: our socket port;

=back

=back

=head2 C<auth_done>

=over

=item Emitted: after a client has connected and the component has validated
hostname and ident;

=item Target: Target: all plugins and registered sessions;

=item Args:

=over

=item C<ARG0>, the connection id;

=item C<ARG1>, a HASHREF with the following keys: 'ident' and 'hostname';

=back

=back

=head2 C<listener_add>

=over

=item Emitted: on a successful add_listener() call;

=item Target: all plugins and registered sessions;

=item Args:

=over

=item C<ARG0>, the listening port;

=item C<ARG1>, the listener id;

=back

=back

=head2 C<listener_del>

=head2 C<registered>

=over

=item Emitted: on a successful del_listener() call;

=item Target: all plugins and registered sessions;

=item Args:

=over

=item C<ARG0>, the listening port;

=item C<ARG1>, the listener id;

=back

=back

=head2 C<listener_failure>

=over

=item Emitted: when a listener wheel fails;

=item Target: all plugins and registered sessions;

=item Args:

=over

=item C<ARG0>, the listener id;

=item C<ARG1>, the name of the operation that failed;

=item C<ARG2>, numeric value for $!;

=item C<ARG3>, string value for $!;

=back

=back

=head2 C<socketerr>

=over

=item Emitted: on the failure of an add_connector()

=item Target: all plugins and registered sessions;

=item Args:

=over

=item C<ARG0>, a HASHREF containing the params that add_connector() was
called with;

=back

=back

=head2 C<connected>

=over

=item Emitted: when the component establishes a connection with a peer;

=item Target: all plugins and registered sessions;

=item Args:

=over

=item C<ARG0>, the connection id;

=item C<ARG1>, their ip address;

=item C<ARG2>, their tcp port;

=item C<ARG3>, our ip address;

=item C<ARG4>, our socket port;

=back

=back

=head2 C<connection_flood>

=over

=item Emitted: when a client connection is flooded;

=item Target: all plugins and registered sessions;

=item Args:

=over

=item C<ARG0>, the connection id;

=back

=back

=head2 C<connection_idle>

=over

=item Emitted: when a client connection has not sent any data for a set
period;

=item Target: all plugins and registered sessions;

=item Args:

=over

=item C<ARG0>, the connection id;

=item C<ARG1>, the number of seconds period we consider as idle;

=back

=back

=head2 C<disconnected>

=over

=item Emitted: when a client disconnects;

=item Target: all plugins and registered sessions;

=item Args:

=over

=item C<ARG0>, the connection id;

=item C<ARG1>, the error or reason for disconnection;

=back

=back

=head2 C<cmd_*>

=over

=item Emitted: when a client or peer sends a valid IRC line to us;

=item Target: all plugins and registered sessions;

=item Args:

=over

=item C<ARG0>, the connection id;

=item C<ARG1>, a HASHREF containing the output record from
POE::Filter::IRCD:

 {
     prefix => 'blah!~blah@blah.blah.blah',
     command => 'PRIVMSG',
     params  => [ '#moo', 'cows go moo, not fish :D' ],
     raw_line => ':blah!~blah@blah.blah.blah.blah PRIVMSG #moo :cows go moo, not fish :D'
 }

=back

=back

=head1 AUTHOR

Chris 'BinGOs' Williams

=head1 LICENSE

Copyright E<copy> Chris Williams

This module may be used, modified, and distributed under the same terms as
Perl itself. Please see the license that came with your Perl distribution
for details.

=head1 SEE ALSO

L<POE|POE>

L<POE::Filter::IRCD|POE::Filter::IRCD>

L<POE::Component::Server::IRC|POE::Component::Server::IRC>

=cut
