# Author: Chris "BinGOs" Williams
#
# This module may be used, modified, and distributed under the same
# terms as Perl itself. Please see the license that came with your Perl
# distribution for details.
#
package POE::Component::Server::IRC;

use base qw(POE::Component::Server::IRC::Backend);
use POE::Component::Server::IRC::Daemon;
use vars qw($VERSION $REVISION);

$VERSION = '0.99';
$REVISION = $LastChangedRevision$;

sub _load_our_plugins {
  my ($self) = shift;

  $self->{daemon} = POE::Component::Server::IRC::Daemon->new();

  $self->plugin_add( 'Daemon', $self->{daemon} );
  return 1;
}

sub _unload_our_plugins {
  my ($self) = shift;

  my ($daemon) = delete ( $self->{daemon} );
  $self->plugin_del( $daemon );
  return 1;
}

sub daemon {
  return $_[0]->{daemon};
}

1;
