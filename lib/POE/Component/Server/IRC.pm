# Author: Chris "BinGOs" Williams
#
# This module may be used, modified, and distributed under the same
# terms as Perl itself. Please see the license that came with your Perl
# distribution for details.
#
package POE::Component::Server::IRC;

use base qw(POE::Component::Server::IRC::Backend);
use POE::Component::Server::IRC::Daemon;
use vars qw($VERSION);

$VERSION = '0.31';

sub _load_our_plugins {
  my ($self) = shift;

  $self->plugin_add( 'Daemon', POE::Component::Server::IRC::Daemon->new() );
  return 1;
}

1;
