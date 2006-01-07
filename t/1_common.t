use Test::More tests => 15;
BEGIN { use_ok('POE::Component::Server::IRC::Common', qw(:ALL)) }
ok( 'SIMPLE' eq u_irc( 'simple' ), "Upper simple test" );
ok( 'simple' eq l_irc( 'SIMPLE' ), "Lower simple test" );
ok( 'C0MPL~[X]' eq u_irc ( 'c0mpl^{x}' ), "Upper complex test" );
ok( 'c0mpl^{x}' eq l_irc ( 'C0MPL~[X]' ), "Lower complex test" );
my $hashref = parse_mode_line( qw(ov rita bob) );
ok( $hashref->{modes}->[0] eq '+o', "Parse mode test 1" );
ok( $hashref->{args}->[0] eq 'rita', "Parse mode test 2" );
ok( unparse_mode_line( '+o-v-o-o+v-o+o+o' ) eq '+o-voo+v-o+oo', "Unparse mode test 1" );
my $banmask = parse_ban_mask( 'stalin*' );
ok( $banmask eq 'stalin*!*@*', "Parse ban mask test 1" );
ok( validate_nick_name( 'm00[^]' ), "Nickname is valid test" );
ok( !validate_nick_name( 'm00[=]' ), "Nickname is invalid test" );
ok( validate_chan_name( '#chan.nel' ), "Channel is valid test" );
ok( !validate_chan_name( '#chan,nel' ), "Channel is invalid test" );
ok( matches_mask( '**', '127.0.0.1' ), "Mask matches Test" );
ok( !matches_mask( '127.0.0.2', '127.0.0.1' ), "Mask not matches Test" );
