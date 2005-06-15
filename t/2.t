# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 1.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 2;
BEGIN { use_ok('POE::Component::Server::IRC') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

SKIP: {
  eval { require POE::Component::IRC };

  skip "No POE::Component::IRC skipping tests", 1 if $@;

  my ($obj) = POE::Component::Server::IRC->create();
  isa_ok( $obj, 'POE::Component::Server::IRC' );

}
