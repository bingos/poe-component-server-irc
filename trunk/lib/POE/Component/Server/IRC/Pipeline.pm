package POE::Component::Server::IRC::Pipeline;

use strict;
use warnings;

our $VERSION = '1.20';


sub new {
  my ($class, $irc) = @_;

  return bless {
    PLUGS => {},
    PIPELINE => [],
    HANDLES => {},
    IRC => $irc,
  }, $class;
}


sub push {
  my ($self, $alias, $plug) = @_;
  $@ = "Plugin named '$alias' already exists ($self->{PLUGS}{$alias})", return
    if $self->{PLUGS}{$alias};

  my $return;

  eval { $return = $plug->PCSI_register($self->{IRC}) };

  if ($return) {
    push @{ $self->{PIPELINE} }, $plug;
    $self->{PLUGS}{$alias} = $plug;
    $self->{PLUGS}{$plug} = $alias;
    $self->{IRC}->yield(__send_event => $self->{IRC}->{prefix} . 'plugin_add' => $alias => $plug);
    return scalar @{ $self->{PIPELINE} };
  }
  else { return }
}


sub pop {
  my ($self) = @_;

  return unless @{ $self->{PIPELINE} };

  my $plug = pop @{ $self->{PIPELINE} };
  my $alias = delete $self->{PLUGS}{$plug};
  delete $self->{PLUGS}{$alias};
  delete $self->{HANDLES}{$plug};

  eval { $plug->PCSI_unregister($self->{IRC}) };
  $self->{IRC}->yield(__send_event => $self->{IRC}->{prefix} . 'plugin_del' => $alias, $plug);

  return wantarray() ? ($plug, $alias) : $plug;
}


sub unshift {
  my ($self, $alias, $plug) = @_;
  $@ = "Plugin named '$alias' already exists ($self->{PLUGS}{$alias}", return
    if $self->{PLUGS}{$alias};

  my $return;

  eval { $return = $plug->PCSI_register($self->{IRC}) };

  if ($return) {
    unshift @{ $self->{PIPELINE} }, $plug;
    $self->{PLUGS}{$alias} = $plug;
    $self->{PLUGS}{$plug} = $alias;
    $self->{IRC}->yield(__send_event => $self->{IRC}->{prefix} . 'plugin_add' => $alias => $plug);
    return scalar @{ $self->{PIPELINE} };
  }
  else { return }

  return scalar @{ $self->{PIPELINE} };
}


sub shift {
  my ($self) = @_;

  return unless @{ $self->{PIPELINE} };

  my $plug = shift @{ $self->{PIPELINE} };
  my $alias = delete $self->{PLUGS}{$plug};
  delete $self->{PLUGS}{$alias};
  delete $self->{HANDLES}{$plug};

  eval { $plug->PCSI_unregister($self->{IRC}) };
  $self->{IRC}->yield(__send_event => $self->{IRC}->{prefix} . 'plugin_del' => $alias, $plug);

  return wantarray() ? ($plug, $alias) : $plug;
}


sub replace {
  my ($self, $old, $new_a, $new_p) = @_;
  my ($old_a, $old_p) = ref($old) ?
    ($self->{PLUGS}{$old}, $old) :
    ($old, $self->{PLUGS}{$old});

  $@ = "Plugin '$old_a' does not exist", return
    unless $old_p;

  delete $self->{PLUGS}{$old_p};
  delete $self->{PLUGS}{$old_a};
  delete $self->{HANDLES}{$old_p};
  eval { $old_p->PCSI_unregister($self->{IRC}) };
  $self->{IRC}->yield(__send_event => $self->{IRC}->{prefix} . 'plugin_del' => $old_a, $old_p);

  $@ = "Plugin named '$new_a' already exists ($self->{PLUGS}{$new_a}", return
    if $self->{PLUGS}{$new_a};

  my $return;

  eval { $return = $new_p->PCSI_register($self->{IRC}) };

  if ($return) {
    $self->{PLUGS}{$new_p} = $new_a;
    $self->{PLUGS}{$new_a} = $new_p;

    for (@{ $self->{PIPELINE} }) {
      $_ = $new_p, last if $_ == $old_p;
    }

    $self->{IRC}->yield(__send_event => $self->{IRC}->{prefix} . 'plugin_add' => $new_a => $new_p);
    return 1;
  }
  else { return }
}


sub remove {
  my ($self, $old) = @_;
  my ($old_a, $old_p) = ref($old) ?
    ($self->{PLUGS}{$old}, $old) :
    ($old, $self->{PLUGS}{$old});

  $@ = "Plugin '$old_a' does not exist", return
    unless $old_p;

  delete $self->{PLUGS}{$old_p};
  delete $self->{PLUGS}{$old_a};
  delete $self->{HANDLES}{$old_p};

  my $i = 0;
  for (@{ $self->{PIPELINE} }) {
    splice(@{ $self->{PIPELINE} }, $i, 1), last
      if $_ == $old_p;
    ++$i;
  }

  eval { $old_p->PCSI_unregister($self->{IRC}) };
  $self->{IRC}->yield(__send_event => $self->{IRC}->{prefix} . 'plugin_del' => $old_a, $old_p);

  return wantarray ? ($old_p, $old_a) : $old_p;
}


sub get {
  my ($self, $old) = @_;
  my ($old_a, $old_p) = ref($old) ?
    ($self->{PLUGS}{$old}, $old) :
    ($old, $self->{PLUGS}{$old});

  $@ = "Plugin '$old_a' does not exist", return
    unless $old_p;

  return wantarray ? ($old_p, $old_a) : $old_p;
}


sub get_index {
  my ($self, $old) = @_;
  my ($old_a, $old_p) = ref($old) ?
    ($self->{PLUGS}{$old}, $old) :
    ($old, $self->{PLUGS}{$old});

  $@ = "Plugin '$old_a' does not exist", return -1
    unless $old_p;

  my $i = 0;
  for (@{ $self->{PIPELINE} }) {
    return $i if $_ == $old_p;
    ++$i;
  }
}


sub insert_before {
  my ($self, $old, $new_a, $new_p) = @_;
  my ($old_a, $old_p) = ref($old) ?
    ($self->{PLUGS}{$old}, $old) :
    ($old, $self->{PLUGS}{$old});

  $@ = "Plugin '$old_a' does not exist", return
    unless $old_p;

  $@ = "Plugin named '$new_a' already exists ($self->{PLUGS}{$new_a}", return
    if $self->{PLUGS}{$new_a};

  my $return;

  eval { $return = $new_p->PCSI_register($self->{IRC}) };

  if ($return) {
    $self->{PLUGS}{$new_p} = $new_a;
    $self->{PLUGS}{$new_a} = $new_p;

    my $i = 0;
    for (@{ $self->{PIPELINE} }) {
      splice(@{ $self->{PIPELINE} }, $i, 0, $new_p), last
        if $_ == $old_p;
      ++$i;
    }

    $self->{IRC}->yield(__send_event => $self->{IRC}->{prefix} . 'plugin_add' => $new_a => $new_p);
    return 1;
  }
  else { return }
}


sub insert_after {
  my ($self, $old, $new_a, $new_p) = @_;
  my ($old_a, $old_p) = ref($old) ?
    ($self->{PLUGS}{$old}, $old) :
    ($old, $self->{PLUGS}{$old});

  $@ = "Plugin '$old_a' does not exist", return
    unless $old_p;

  $@ = "Plugin named '$new_a' already exists ($self->{PLUGS}{$new_a}", return
    if $self->{PLUGS}{$new_a};

  my $return;

  eval { $return = $new_p->PCSI_register($self->{IRC}) };

  if ($return) {
    $self->{PLUGS}{$new_p} = $new_a;
    $self->{PLUGS}{$new_a} = $new_p;

    my $i = 0;
    for (@{ $self->{PIPELINE} }) {
      splice(@{ $self->{PIPELINE} }, $i+1, 0, $new_p), last
        if $_ == $old_p;
      ++$i;
    }

    $self->{IRC}->yield(__send_event => $self->{IRC}->{prefix} . 'plugin_add' => $new_a => $new_p);
    return 1;
  }
  else { return }
}


sub bump_up {
  my ($self, $old, $diff) = @_;
  my $idx = $self->get_index($old);

  return -1 if $idx < 0;

  my $pipeline = $self->{PIPELINE};
  $diff ||= 1;

  my $pos = $idx - $diff;

  warn "$idx - $diff is negative, moving to head of the pipeline"
    if $pos < 0;

  splice(@$pipeline, $pos, 0, splice(@$pipeline, $idx, 1));

  return $pos;
}


sub bump_down {
  my ($self, $old, $diff) = @_;
  my $idx = $self->get_index($old);

  return -1 if $idx < 0;

  my $pipeline = $self->{PIPELINE};
  $diff ||= 1;

  my $pos = $idx + $diff;

  warn "$idx + $diff is too high, moving to back of the pipeline"
    if $pos >= @$pipeline;

  splice(@$pipeline, $pos, 0, splice(@$pipeline, $idx, 1));

  return $pos;
}


1;

__END__

=head1 NAME

POE::Component::Server::IRC::Pipeline - the plugin pipeline for POE::Component::Server::IRC::Backend.

=head1 SYNOPSIS

  use POE qw( Component::Server::IRC::Backend );
  use POE::Component::Server::IRC::Pipeline;
  use My::Plugin;

  my $irc = POE::Component::Server::IRC::Backend->create;

  # the following operations are presented in pairs
  # the first is the general procedure, the second is
  # the specific way using the pipeline directly

  # to install a plugin
  $irc->plugin_add(mine => My::Plugin->new);
  $irc->pipeline->push(mine => My::Plugin->new);  

  # to remove a plugin
  $irc->plugin_del('mine');        # or the object
  $irc->pipeline->remove('mine');  # or the object

  # to get a plugin
  my $plug = $irc->plugin_get('mine');
  my $plug = $irc->pipeline->get('mine');

  # there are other very specific operations that
  # the pipeline offers, demonstrated here:

  # to get the pipeline object itself
  my $pipe = $irc->pipeline;

  # to install a plugin Cat the front of the pipeline
  $pipe->unshift(mine => My::Plugin->new);

  # to remove the plugin at the end of the pipeline
  my $plug = $pipe->pop;

  # to remove the plugin at the front of the pipeline
  my $plug = $pipe->shift;

  # to replace a plugin with another
  $pipe->replace(mine => newmine => My::Plugin->new);

  # to insert a plugin before another
  $pipe->insert_before(mine => newmine => My::Plugin->new);

  # to insert a plugin after another
  $pipe->insert_after(mine => newmine => My::Plugin->new);

  # to get the location in the pipeline of a plugin
  my $index = $pipe->get_index('mine');

  # to move a plugin closer to the front of the pipeline
  $pipe->bump_up('mine');

  # to move a plugin closer to the end of the pipeline
  $pipe->bump_down('mine');

=head1 DESCRIPTION

POE::Component::Server::IRC::Pipeline defines the Plugin pipeline system for POE::Component::Server::IRC::Backend
instances.  

=head1 METHODS

=over

=item new

Takes one argument, the POE::Component::Server::IRC::Backend object to attach to.

=item push

Take two arguments, an alias for a plugin and the plugin object itself.  If a plugin with
that alias already exists, $@ will be set and undef will be returned.  Otherwise, it adds
the plugin to the end of the pipeline and registers it.  This will yield an 'plugin_add'
event.  If successful, it returns the size of the pipeline.

  my $new_size = $pipe->push($name, $plug);

=item unshift

Take two arguments, an alias for a plugin and the plugin object itself.  If a plugin with
that alias already exists, $@ will be set and undef will be returned.  Otherwise, it adds
the plugin to the beginning of the pipeline and registers it.  This will yield an 'plugin_add'
event.  If successful, it returns the size of the pipeline.

  my $new_size = $pipe->push($name, $plug);

=item replace

Take three arguments, the old plugin or its alias, an alias for the new plugin and the new
plugin object itself.  If the old plugin doesn't exist, or if there is already a plugin with
the new alias (besides the old plugin), $@ will be set and undef will be returned.  Otherwise,
it removes the old plugin (yielding an 'plugin_del' event) and replaces it with the new
plugin.  This will yield an 'plugin_add' event.  If successful, it returns 1.

  my $success = $pipe->replace($name, $new_name, $new_plug);
  my $success = $pipe->replace($plug, $new_name, $new_plug);

=item insert_before

Takes three arguments, the plugin that is relative to the operation, an alias for the new
plugin and the new plugin object itself.  If the first plugin doesn't exist, or if there is
already a plugin with the new alias, $@ will be set and undef will be returned.  Otherwise,
the new plugin is placed just prior to the other plugin in the pipeline.  If successful, it
returns 1.

  my $success = $pipe->insert_before($name, $new_name, $new_plug);
  my $success = $pipe->insert_before($plug, $new_name, $new_plug);

=item insert_after

Takes three arguments, the plugin that is relative to the operation, an alias for the new
plugin and the new plugin object itself.  If the first plugin doesn't exist, or if there is
already a plugin with the new alias, $@ will be set and undef will be returned.  Otherwise,
the new plugin is placed just after to the other plugin in the pipeline.  If successful, it
returns 1.

  my $success = $pipe->insert_after($name, $new_name, $new_plug);
  my $success = $pipe->insert_after($plug, $new_name, $new_plug);

=item bump_up

Takes one or two arguments, the plugin or its alias, and the distance to bump the plugin.
The distance defaults to 1.  If the plugin doesn't exist, $@ will be set and B<-1 will be
returned, not undef>.  Otherwise, the plugin will be moved the given distance closer to the
front of the pipeline.  A warning is issued alerting you if it would have been moved past the
beginning of the pipeline, and the plugin is placed at the beginning.  If successful, the new
index of the plugin in the pipeline is returned.

  my $pos = $pipe->bump_up($name);
  my $pos = $pipe->bump_up($plug);
  my $pos = $pipe->bump_up($name, $delta);
  my $pos = $pipe->bump_up($plug, $delta);

=item bump_down

Takes one or two arguments, the plugin or its alias, and the distance to bump the plugin.
The distance defaults to 1.  If the plugin doesn't exist, $@ will be set and B<-1 will be
returned, not undef>.  Otherwise, the plugin will be moved the given distance closer to the
end of the pipeline.  A warning is issued alerting you if it would have been moved past the
end of the pipeline, and the plugin is placed at the end.  If successful, the new index of
the plugin in the pipeline is returned.

  my $pos = $pipe->bump_down($name);
  my $pos = $pipe->bump_down($plug);
  my $pos = $pipe->bump_down($name, $delta);
  my $pos = $pipe->bump_down($plug, $delta);

=item remove

Takes one argument, a plugin or its alias.  If the plugin doesn't exist, $@ will be set and
undef will be returned.  Otherwise, the plugin is removed from the pipeline.  This will yield
an 'plugin_del' event.  In list context, it returns the plugin and its alias; in scalar
context, it returns only the plugin.

  my ($plug, $name) = $pipe->remove($the_name);
  my ($plug, $name) = $pipe->remove($the_plug);
  my $plug = $pipe->remove($the_name);
  my $plug = $pipe->remove($the_plug);

=item shift

Takes no arguments.  The first plugin in the pipeline is removed.  This will yield
an 'plugin_del' event.  In list context, it returns the plugin and its alias; in scalar
context, it returns only the plugin.  If there were no elements, undef will be returned.

  my ($plug, $name) = $pipe->shift;
  my $plug = $pipe->shift;

=item pop

Takes no arguments.  The last plugin in the pipeline is removed.  This will yield
an 'plugin_del' event.  In list context, it returns the plugin and its alias; in scalar
context, it returns only the plugin.  If there were no elements, undef will be returned.

  my ($plug, $name) = $pipe->pop;
  my $plug = $pipe->pop;

=item get

Takes one argument, a plugin or its alias.  If no such plugin exists, $@ will be set and
undef will be returned.  In list context, it returns the plugin and its alias; in scalar
context, it returns only the plugin.

  my ($plug, $name) = $pipe->get($the_name);
  my ($plug, $name) = $pipe->get($the_plug);
  my $plug = $pipe->get($the_name);
  my $plug = $pipe->get($the_plug);

=item get_index

Takes one argument, a plugin or its alias.  If no such plugin exists, $@ will be set and
B<-1 will be returned, not undef>.  Otherwise, the index in the pipeline is returned.

  my $pos = $pipe->get_index($name);
  my $pos = $pipe->get_index($plug);

=back

=head1 BUGS

None known so far.

=head1 SEE ALSO

L<POE::Component::IRC>, L<POE::Component::IRC::Plugin>.  Also look at
L<POE::Session::MultiDispatch> which does something similar for session events.

=head1 AUTHOR

Jeff C<japhy> Pinyan, F<japhy@perlmonk.org>.

=head1 LICENSE

Copyright C<(c)> Jeff Pinyan

This module may be used, modified, and distributed under the same terms as Perl itself. Please see the license that came with your Perl distribution for details.

=cut
