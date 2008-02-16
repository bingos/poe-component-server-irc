package POE::Component::Server::IRC::Test::Plugin;

use strict;
use POE::Component::Server::IRC::Plugin qw( :ALL );

our $VERSION = '1.20';

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
__END__

=head1 NAME

POE::Component::Server::IRC::Test::Plugin - Part of the L<POE::Component::Server::IRC> test-suite.

=head1 DESCRIPTION

POE::Component::Server::IRC::Test::Plugin is a very simple L<POE::Component::Server::IRC> plugin used to test that the plugin system is working correctly.

=head1 CONSTRUCTOR

=over

=item new

No arguments required, returns an POE::Component::Server::IRC::Test::Plugin object.

=back

=head1 AUTHOR

Chris "BinGOs" Williams

=head1 SEE ALSO

L<POE::Component::Server::IRC::Plugin>
