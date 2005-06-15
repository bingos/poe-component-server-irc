# Author: Chris "BinGOs" Williams
#
# This module may be used, modified, and distributed under the same
# terms as Perl itself. Please see the license that came with your Perl
# distribution for details.
#
package POE::Component::Server::IRC::Daemon;

use POE::Component::Server::IRC::Plugin qw ( :ALL );
use Carp;
use vars qw($VERSION);

$VERSION = '0.31';

sub new {
  my ($package) = shift;
  croak "$package requires an even numbers of parameters\n" if @_ & 1;
  my %parms = @_;

  foreach my $key ( keys %parms ) {
	$parms{ lc $key } = delete $parms{ $key };
  }

  return bless \%parms, $package;
}

sub PCSI_register {
  my ($self,$ircd) = splice @_, 0, 2;

  $ircd->plugin_register( $self, 'SERVER', qw(all) );
  return 1;
}

sub PCSI_unregister {
  return 1;
}

1;
