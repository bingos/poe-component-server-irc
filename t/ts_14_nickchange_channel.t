use strict;
use warnings;
use POE qw(Wheel::SocketFactory);
use Socket qw(unpack_sockaddr_in);
use POE::Component::IRC;
use POE::Component::Server::IRC;
use Test::More tests => 3;

my $ircd = POE::Component::Server::IRC->spawn(
    Auth      => 0,
    AntiFlood => 0,
);

my $irc = POE::Component::IRC->spawn(
    Flood => 1,
);

POE::Session->create(
    package_states => [
        (__PACKAGE__) => [qw(
            _start
            irc_001
            irc_join
            irc_nick
            irc_disconnected
            _shutdown
        )],
    ],
);

POE::Kernel->run();

sub _start {
    $_[KERNEL]->delay(_shutdown => 60);

    my $wheel = POE::Wheel::SocketFactory->new(
        BindAddress  => '127.0.0.1',
        BindPort     => 0,
        SuccessEvent => '_fake_success',
        FailureEvent => '_fake_failure',
    );

    my $port = (unpack_sockaddr_in($wheel->getsockname))[0];
    $ircd->yield(add_listener => Port => $port);
    $irc->yield(register => 'all');
    $irc->yield(connect => {
        nick   => 'foo',
        server => '127.0.0.1',
        port   => $port,
    });
}

sub irc_001 {
    my $irc = $_[SENDER]->get_heap();
    pass('Logged in');
    $irc->yield(join => '#foobar');
}

sub irc_join {
    my $irc = $_[SENDER]->get_heap();
    pass('Joined channel');
    $irc->yield(nick => 'newnick');
    $irc->yield('quit');
}

sub irc_nick {
    is($_[HEAP]{got_nick}, undef, 'Got irc_nick only once');
    $_[HEAP]->{irc_nick}++;
}

sub irc_disconnected {
    $_[KERNEL]->yield('_shutdown');
}

sub _shutdown {
    $_[KERNEL]->alarm_remove_all();
    $ircd->yield('shutdown');
    $irc->yield('shutdown');
}
