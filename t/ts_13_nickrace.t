use strict;
use warnings;
use POE qw(Wheel::SocketFactory);
use Socket;
use POE::Component::IRC;
use POE::Component::Server::IRC;
use Test::More tests => 4;

my $bot1 = POE::Component::IRC->spawn(
    plugin_debug => 1,
    alias        => 'bot1',
);
my $bot2 = POE::Component::IRC->spawn(
    plugin_debug => 1,
    alias        => 'bot2',
);
my $ircd = POE::Component::Server::IRC->spawn(
    Auth      => 0,
    AntiFlood => 0,
);

POE::Session->create(
    package_states => [
        main => [qw(
            _start
            _config_ircd 
            _shutdown 
            irc_001
            irc_433
            irc_disconnected
        )],
    ],
);

$poe_kernel->run();

sub _start {
    my ($kernel, $heap) = @_[KERNEL, HEAP];

    my $wheel = POE::Wheel::SocketFactory->new(
        BindAddress  => '127.0.0.1',
        BindPort     => 0,
        SuccessEvent => '_fake_success',
        FailureEvent => '_fake_failure',
    );

    if ($wheel) {
        my $port = ( unpack_sockaddr_in( $wheel->getsockname ) )[0];
        $kernel->yield(_config_ircd => $port);
        $heap->{count} = 0;
        $wheel = undef;
        $kernel->delay(_shutdown => 60 );
        return;
    }

    $kernel->yield('_shutdown');
}

sub _config_ircd {
    my ($kernel, $port) = @_[KERNEL, ARG0];

    $ircd->yield('add_i_line');
    $ircd->yield(add_listener => Port => $port);
    
    $bot1->yield(register => 'all');
    $bot1->yield(connect => {
        nick    => 'TestBot1',
        server  => '127.0.0.1',
        port    => $port,
        ircname => 'Test test bot',
    });
    
    $bot2->yield(register => 'all');
    $bot2->yield(connect => {
        nick    => 'TestBot1',
        server  => '127.0.0.1',
        port    => $port,
        ircname => 'Test test bot',
    });
}

sub irc_001 {
    my $irc = $_[SENDER]->get_heap();
    pass($irc->session_alias() . ' logged in');
}

sub irc_433 {
    my $irc = $_[SENDER]->get_heap();
    my $other = $irc == $bot1 ? $bot2 : $bot1;

    pass($irc->session_alias . ' nick collision');
    $other->yield('quit');
    $irc->yield('quit');
}

sub irc_disconnected {
    my ($kernel, $sender, $heap) = @_[KERNEL, SENDER, HEAP];
    my $irc = $sender->get_heap();
    
    pass($irc->session_alias() . ' disconnected');
    $heap->{count}++;
    $kernel->yield('_shutdown') if $heap->{count} == 2;
}

sub _shutdown {
    my ($kernel) = $_[KERNEL];
    
    $kernel->alarm_remove_all();
    $ircd->yield('shutdown');
    $bot1->yield('shutdown');
    $bot2->yield('shutdown');
}

