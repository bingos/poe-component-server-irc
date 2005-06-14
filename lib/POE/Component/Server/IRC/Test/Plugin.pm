package POE::Component::Server::IRC::Test::Plugin;

use POE::Component::Server::IRC::Plugin qw( :ALL );

sub new {
  return bless { @_[1..$#_] }, $_[0];
}

sub PCSI_register {
  $_[1]->plugin_register( $_[0], 'SERVER', qw(all) );
  return 1;
}

sub PCSI_unregister {
  return 1;
}

sub _default {
  return PCSI_EAT_NONE;
}

1;
