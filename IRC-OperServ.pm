package POE::Component::Server::IRC::OperServ;

use strict;
use POE;
use Carp;
use base qw(POE::Component::Server::IRC);
use Data::Dumper;

our (@valid_commands) = qw(PASS NICK USER SERVER OPER QUIT SQUIT JOIN PART MODE TOPIC NAMES LIST INVITE KICK VERSION STATS LINKS TIME CONNECT TRACE ADMIN INFO WHO WHOIS WHOWAS KILL PING PONG ERROR AWAY REHASH RESTART SUMMON USERS WALLOPS USERHOST ISON MOTD LUSERS DIE);

our (@client_commands) = qw(PASS NICK USER QUIT JOIN NAMES PART MODE TOPIC KICK OPER SUMMON USERS WHO AWAY MOTD LUSERS VERSION INVITE USERHOST PING PONG WHOIS LIST ISON ADMIN INFO WHOWAS TIME WALLOPS STATS KILL);

our (@server_commands) = qw(WALLOPS);

our (@connection_commands) = qw(PASS NICK USER SERVER QUIT);

our (@reserved_channels) = qw(&CONNECTIONS &STATE);


sub spawn {
  my ($package) = shift;
  croak "$package requires an even number of parameters" if @_ % 2;
  my (%args) = @_;

  unless ( $args{'Alias'} ) {
	croak "You must specify an Alias to $package->spawn";
  }

  my ($self) = $package->new(@_);

  my (@object_client_handlers) = map { 'ircd_client_' . lc } @client_commands;
  my (@object_server_handlers) = map { 'ircd_server_' . lc } @server_commands;
  my (@object_connection_handlers) = map { 'ircd_connection_' . lc } @connection_commands;

  POE::Session->create(
	object_states => [
		$self => { _start              => 'ircd_start',
			   _stop               => 'ircd_stop',
			   ircd_client_privmsg => 'ircd_client_message',
			   ircd_client_rehash  => 'ircd_client_o_cmds',
			   ircd_client_restart => 'ircd_client_o_cmds',
			   ircd_client_die     => 'ircd_client_o_cmds',
			   ircd_client_notice  => 'ircd_client_message',
			   shutdown            => 'ircd_shutdown' },
		$self => [ qw(got_hostname_response got_ip_response poll_connections client_registered auth_client register unregister configure add_operator add_listener accept_new_connection accept_failed connection_input connection_error connection_flushed set_motd ident_client_reply ident_client_error auth_done add_i_line sig_hup_rehash client_dispatcher client_ping ircd_operserv) ],
		$self => \@object_client_handlers,
		$self => \@object_server_handlers,
		$self => \@object_connection_handlers,
	],
	options => { trace => $self->{Debug} },
  );

  $self->{State}->{by_nickname}->{ 'OPERSERV' } = { NickName => 'OperServ',
						    UserName => 'operserv',
						    HostName => 'oper.server.irc',
						    RealName => 'OperServ 0.2',
						    UMode    => 'o',
						    TimeStamp => time(),
						    Server   => 'oper.server.irc' };
  $self->{State}->{Servers}->{ 'oper.server.irc' }->{Description} = 'Oper? Oper!';
  return $self;
}

sub ircd_operserv {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];
  my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};

  SWITCH: {
    if ( ( not defined ( $input ) ) or $input eq '' ) {
	$self->{Clients}->{ $wheel_id }->{Wheel}->put ( { command => 'NOTICE', prefix => $self->nick_long_form('OPERSERV'), params => [ $self->client_nickname($wheel_id), 'No command given' ] } );
	last SWITCH;
    }
    my (@cmd_line) = split(/\x20+/,$input);
    my ($reply) = 'Unknown command or invalid syntax.';
    SWITCH2: {
	if ( uc ( $cmd_line[0] ) eq 'OP' and $self->channel_exists($cmd_line[1]) and $self->is_channel_member($cmd_line[1],$nickname) and ( not $self->is_channel_operator($cmd_line[1],$nickname) ) ) {
	   $self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }->{Members}->{ $nickname } .= 'o';
	   $self->{State}->{by_nickname}->{ $nickname }->{Channels}->{ u_irc ( $cmd_line[1] ) } .= 'o';
	   $self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }->{Members}->{ $nickname } = join( '', sort( split(//,$self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }->{Members}->{ $nickname } ) ) );
	   $self->{State}->{by_nickname}->{ $nickname }->{Channels}->{ u_irc ( $cmd_line[1] ) } = join( '', sort( split(//,$self->{State}->{by_nickname}->{ $nickname }->{Channels}->{ u_irc ( $cmd_line[1] ) } ) ) );
	   foreach my $member ( keys %{ $self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }->{Members} } ) {
	      if ( my $member_wheel = $self->is_my_client($member) ) {
		 $self->send_output_to_client( $member_wheel, { command => 'MODE', prefix => $self->server_name(), params => [ $self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }->{ChannelName}, '+o', $self->client_nickname($wheel_id) ] } );
	      } else {
		# TODO: Send to other servers.
	      }
	   }
	   $reply = 'Done.';
	   last SWITCH2;
	}
	if ( uc ( $cmd_line[0] ) eq 'CLEARCHAN' and $self->channel_exists($cmd_line[1]) ) {
	   # Clear modes
	   foreach my $member ( keys %{ $self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }->{Members} } ) {
	      if ( my $member_wheel = $self->is_my_client($member) ) {
		 $self->send_output_to_client( $member_wheel, { command => 'MODE', prefix => $self->server_name(), params => [ $self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }->{ChannelName}, '-' . $self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }->{Mode} ] } );
	      } else {
		# TODO: Send to other servers.
	      }
	   }
	   delete ( $self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }->{Mode} );
	   delete ( $self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }->{ChanKey} );
	   delete ( $self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }->{ChanLimit} );
	   # Clear bans
	   foreach my $ban ( keys %{ $self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }->{Bans} } ) {
	     foreach my $member ( keys %{ $self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }->{Members} } ) {
	      if ( my $member_wheel = $self->is_my_client($member) ) {
		 $self->send_output_to_client( $member_wheel, { command => 'MODE', prefix => $self->server_name(), params => [ $self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }->{ChannelName}, '-b', $ban ] } );
	      } else {
		# TODO: Send to other servers.
	      }
	     }
	   }
	   delete ( $self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }->{Bans} );
	   $reply = 'Done.';
	   last SWITCH2;
	}
	if ( uc ( $cmd_line[0] ) eq 'KICK' and $self->channel_exists($cmd_line[1]) and $self->is_nick_on_channel($cmd_line[2],$cmd_line[1]) ) {
	   $self->send_output_to_channel( $cmd_line[1], { command => 'KICK', prefix => $self->server_name(), params => [ $self->channel_name($cmd_line[1]), $self->proper_nickname($cmd_line[2]), 'OperServ Channel KICK by ' . $self->client_nickname($wheel_id) ] } );
	   $self->state_channel_part($cmd_line[1],$cmd_line[2]);
	   $reply = 'Done.';
	   last SWITCH2;
	}
	if ( uc ( $cmd_line[0] ) eq 'DUMP' ) {
	   $Data::Dumper::Indent = 1;
	   foreach my $line (  split(/\n/,Data::Dumper->Dump([$self])) ) {
		$self->send_output_to_channel( '&STATE', { command => 'NOTICE', prefix => $self->server_name(), params => [ '&STATE', $line ] } );
	   }
	   $reply = 'Done.';
	   last SWITCH2;
	}
	if ( uc ( $cmd_line[0] ) eq 'DUMPCHAN' and $self->channel_exists($cmd_line[1]) ) {
	   $Data::Dumper::Indent = 1;
	   foreach my $line (  split(/\n/,Data::Dumper->Dump([$self->{State}->{Channels}->{ u_irc ( $cmd_line[1] ) }])) ) {
		$self->send_output_to_channel( '&STATE', { command => 'NOTICE', prefix => $self->server_name(), params => [ '&STATE', $line ] } );
	   }
	   $reply = 'Done.';
	   last SWITCH2;
	}
    }
    $self->{Clients}->{ $wheel_id }->{Wheel}->put ( { command => 'NOTICE', prefix => $self->nick_long_form('OperServ'), params => [ $self->client_nickname($wheel_id), $reply ] } );
  }
}

sub u_irc {
  my ($value) = shift || return undef;

  $value =~ tr/a-z{}|/A-Z[]\\/;
  return $value;
}

sub ircd_client_message {
  my ($kernel,$self,$input,$wheel_id) = @_[KERNEL,OBJECT,ARG0,ARG1];

  SWITCH: {
    if ( not defined ( $self->{Clients}->{ $wheel_id } ) ) {
	last SWITCH;
    }
    my ($nickname) = $self->{Clients}->{ $wheel_id }->{NickName};
    if ( not defined ( $input->{params}->[0] ) or $input->{params}->[0] eq "" ) {
	#ERR_NORECIPIENT
	$self->send_output_to_client($wheel_id,'411',$input->{command});
	last SWITCH;
    }
    if ( not defined ( $input->{params}->[1] ) or $input->{params}->[1] eq "" ) {
	#ERR_NOTEXTTOSEND
	$self->send_output_to_client($wheel_id,'412');
	last SWITCH;
    }
    foreach my $recipient ( split (/,/,$input->{params}->[0]) ) {
      SWITCH2: {
	if ( ( not $self->channel_exists($recipient) ) and ( not $self->nick_exists($recipient) ) ) {
	  #ERR_NOSUCHNICK
	  $self->send_output_to_client($wheel_id,'401',$recipient);
	  last SWITCH2;
	}
	if ( $self->channel_exists($recipient) and ( ( $self->is_channel_mode_set($recipient,'n') and not $self->is_channel_member($recipient,$nickname) ) or ( $self->is_channel_mode_set($recipient,'m') and not ( $self->is_channel_operator($recipient,$nickname) or $self->has_channel_voice($recipient,$nickname) ) ) ) or ( $self->is_user_banned_from_channel($nickname,$recipient) ) ) {
	  #ERR_CANNOTSENDTOCHAN
	  $self->send_output_to_client($wheel_id,'404',$recipient);
	  last SWITCH2;
	}
	if ( $self->nick_exists($recipient) ) {
	  if ( my $recipient_wheel = $self->is_my_client($recipient) ) {
	    $self->send_output_to_client( $recipient_wheel, { command => $input->{command}, prefix => $self->nick_long_form($nickname), params => [ $recipient, $input->{params}->[1] ] } );
	    if ( $self->is_user_away($recipient) and $input->{command} ne 'NOTICE' ) {
		#RPL_AWAY
		$self->send_output_to_client( $wheel_id, { command => '301', prefix => $self->server_name(), params => [ $self->client_nickname($wheel_id), $self->proper_nick( $recipient ), $self->{State}->{by_nickname}->{ u_irc ( $recipient ) }->{Away} ] } );
	    }
	  } else {
	    # TODO: Send in the right direction.
	    # Put OperServ code here.
	    if ( uc ( $recipient ) eq 'OPERSERV' and $self->is_operator($nickname) ) {
		$kernel->post ( $self->{Alias} => 'ircd_operserv' => $input->{params}->[1] => $wheel_id );
	    }
	  }
	  last SWITCH2;
	}
        foreach my $member ( keys %{ $self->{State}->{Channels}->{ u_irc ( $recipient ) }->{Members} } ) {
	  if ( my $member_wheel = $self->is_my_client($member) and $member ne $nickname ) {
	    $self->send_output_to_client( $member_wheel, { command => $input->{command}, prefix => $self->nick_long_form($nickname), params => [ $self->channel_name( $recipient ), ( $input->{params}->[1] =~ /^:/ ? ':' . $input->{params}->[1] : $input->{params}->[1] ) ] } );
	  } else {
	    #TODO: Work out direction to send it.
	  }
        }
        # Send to appropriate servers.
      }
    }
  }
}

1;

__END__

=head1 NAME

POE::Component::Server::IRC::OperServ - a fully event-driven standalone IRC server daemon module with simple operator services.

=head1 SYNOPSIS

  use POE;
  use POE::Component::Server::IRC;

  my ($pocosi) = POE::Component::Server::IRC::OperServ->spawn( Alias => 'ircd' );

  POE::Session->create (
        inline_states => { _start => \&test_start,
                           _stop  => \&test_stop, },

        heap => { Obj  => $pocosi },
  );

  $poe_kernel->run();
  exit 0;

  sub test_start {
    my ($kernel,$heap) = @_[KERNEL,HEAP];

    $kernel->post ( 'ircd' => 'register' );
    $kernel->post ( 'ircd' => 'configure' => { Auth => 1, AntiFlood => 1 } );
    $kernel->post ( 'ircd' => 'add_i_line' => { IPMask => '*', Port => 6667 } );
    $kernel->post ( 'ircd' => 'add_operator' => { UserName => 'Flibble', Password => 'letmein' } );
    $kernel->post ( 'ircd' => 'add_listener' => { Port => 6667 } );
    $kernel->post ( 'ircd' => 'set_motd' => [ 'This is an experimental server', 'Testing POE::Component::Server::IRC', 'Enjoy!' ] );
  }

  sub test_stop {
	print "Server stopped\n";
  }

=head1 DESCRIPTION

POE::Component::Server::IRC::OperServ is subclass of L<POE::Component::Server::IRC|POE::Component::Server::IRC> 
which provides simple operator services.

The documentation is the same as for L<POE::Component::Server::IRC|POE::Component::Server::IRC>, consult that for
usage.

=head1 OperServ

This subclass provides a server user called OperServ. OperServ accepts PRIVMSG commands from operators.

  /msg OperServ <command> <parameters>

The following commands are accepted:

=over

=item OP <#channelname>

The OperServ will give you channel operator status on the indicated channel. You must already be on the indicated channel.

=item CLEARCHAN <#channelname>

The OperServ will remove all channel modes on the indicated channel, including all users' +ov flags.

=item KICK <#channelname> <nickname>

The OperServ will kick the indicated user from the indicated channel.

=back

=head1 OUTPUT

The OperServ responds with NOTICES.

=head1 AUTHOR

Chris Williams, E<lt>chris@bingosnet.co.ukE<gt>

=head1 SEE ALSO

L<POE::Component::Server::IRC|POE::Component::Server::IRC>

=cut
