package POE::Component::Server::IRC::Common;

use strict;
use warnings FATAL => 'all';
use Algorithm::Diff qw(diff);
use Crypt::PasswdMD5;

require Exporter;
use base qw(Exporter);
our @EXPORT_OK = qw(
    u_irc l_irc gen_mode_change parse_mode_line unparse_mode_line
    parse_ban_mask validate_nick_name validate_chan_name matches_mask_array
    matches_mask parse_user mkpasswd chkpasswd
);
our %EXPORT_TAGS = ( ALL => [@EXPORT_OK] );


sub u_irc {
    my ($value, $type) = @_;
    return if !defined $value;
    $type = 'rfc1459' if !defined $type;
    $type = lc $type;

    if ( $type eq 'ascii' ) {
        $value =~ tr/a-z/A-Z/;
    }
    elsif ( $type eq 'strict-rfc1459' ) {
        $value =~ tr/a-z{}|/A-Z[]\\/;
    }
    else {
        $value =~ tr/a-z{}|^/A-Z[]\\~/;
    }

    return $value;
}

sub l_irc {
    my ($value, $type) = @_;
    return if !defined $value;
    $type = 'rfc1459' if !defined $type;
    $type = lc $type;

    if ( $type eq 'ascii' ) {
        $value =~ tr/A-Z/a-z/;
    }
    elsif ( $type eq 'strict-rfc1459' ) {
        $value =~ tr/A-Z[]\\/a-z{}|/;
    }
    else {
        $value =~ tr/A-Z[]\\~/a-z{}|^/;
    }

    return $value;
}

sub parse_mode_line {
    my @args = @_;

    my $chanmodes = [qw(beI k l imnpst)];
    my $statmodes = 'ohv';
    my $hashref = { };
    my $count = 0;

    while (my $arg = shift @args) {
        if (ref $arg eq 'ARRAY') {
            $chanmodes = $arg;
            next;
        }
        if (ref $arg eq 'HASH') {
            $statmodes = join '', keys %{ $arg };
            next;
        }
        if ($arg =~ /^(\+|-)/ or $count == 0) {
            my $action = '+';
            for my $char ( split (//,$arg) ) {
                if ($char eq '+' or $char eq '-') {
                    $action = $char;
                }
                else {
                    push @{ $hashref->{modes} }, $action . $char;
                }
                push @{ $hashref->{args} }, shift @args if $char =~ /[$statmodes$chanmodes->[0]$chanmodes->[1]]/;
                push @{ $hashref->{args} }, shift @args if $action eq '+' && $char =~ /[$chanmodes->[2]]/;
            }
         }
         else {
            push @{ $hashref->{args} }, $arg;
         }
         $count++;
    }

    return $hashref;
}

sub parse_ban_mask {
    my ($arg) = @_;
    return if !defined $arg;

    $arg =~ s/\x2a{2,}/\x2a/g;
    my @ban;
    my $remainder;
    if ($arg !~ /\x21/ and $arg =~ /\x40/) {
        $remainder = $arg;
    }
    else {
        ($ban[0], $remainder) = split /\x21/, $arg, 2;
    }

    $remainder =~ s/\x21//g if defined $remainder;
    @ban[1..2] = split(/\x40/, $remainder, 2) if defined $remainder;
    $ban[2] =~ s/\x40//g if defined $ban[2];

    for my $i (1..2) {
        $ban[$i] = '*' if !$ban[$i];
    }

    return $ban[0] . '!' . $ban[1] . '@' . $ban[2];
}

sub unparse_mode_line {
    my ($line) = @_;
    return if !defined $line || !length $line;

    my $action; my $return;
    for my $mode ( split(//,$line) ) {
       if ( $mode =~ /^(\+|-)$/ and ( !$action or $mode ne $action ) ) {
         $return .= $mode;
         $action = $mode;
         next;
       }
       $return .= $mode if ( $mode ne '+' and $mode ne '-' );
    }
    $return =~ s/[+-]$//;
    return $return;
}

sub validate_nick_name {
    my ($nickname) = @_;
    return if !defined $nickname || !length $nickname;
    return 1 if $nickname =~ /^[A-Za-z_0-9`\-^\|\\\{}\[\]]+$/;
    return;
}

sub validate_chan_name {
    my ($channel) = @_;
    return if !defined $channel || !length $channel;
    return 1 if $channel =~ /^(\x23|\x26|\x2B)/ and $channel !~ /(\x20|\x07|\x00|\x0D|\x0A|\x2C)+/;
    return;
}

sub matches_mask_array {
    my ($masks, $matches) = @_;
    return if ref $masks ne 'ARRAY';
    return if ref $matches ne 'ARRAY';

    my $ref = { };
    for my $mask ( @{ $masks } ) {
        for my $match ( @{ $matches } ) {
            push @{ $ref->{ $mask } }, $match if matches_mask( $mask, $match );
        }
    }
    return $ref;
}

sub matches_mask {
    my ($mask, $match) = @_;
    return if !defined $mask || !length $mask;
    return if !defined $match || !length $match;

    $match = u_irc $match;
    $mask =~ s/\x2A+/\x2A/g;
    my $umask = quotemeta u_irc $mask;
    $umask =~ s/\\\*/[\x01-\xFF]{0,}/g;
    $umask =~ s/\\\?/[\x01-\xFF]{1,1}/g;
    return 1 if $match =~ /^$umask$/;
    return;
}

sub gen_mode_change {
    my ($before, $after) = @_;
    $before = '' if !defined $before;
    $after = '' if !defined $after;

    my @before = split //, $before;
    my @after  = split //, $after;
    my $string = '';
    my @hunks = diff(\@before, \@after);
    for my $h ( @hunks ) {
        $string .= $_->[0] . $_->[2] for @$h;
    }

    return unparse_mode_line($string);
}

sub parse_user {
    my ($user) = @_;
    return if !defined $user || !length $user;

    my ($n, $u, $h) = split /[!@]/, $user;
    return ($n, $u, $h) if wantarray();
    return $n;
}

sub mkpasswd {
    my ($plain, %opts) = @_;
    return if !defined $plain || !length $plain;
    $opts{lc $_} = delete $opts{$_} for keys %opts;

    return unix_md5_crypt($plain) if $opts{md5};
    return apache_md5_crypt($plain) if $opts{apache};
    my $salt = join '', ('.','/', 0..9, 'A'..'Z', 'a'..'z')[rand 64, rand 64];
    return crypt($plain, $salt);
}

sub chkpasswd {
    my ($pass, $chk) = @_;
    return if !defined $pass || !length $pass;
    return if !defined $chk || !length $chk;

    my $md5 = '$1$'; my $apr = '$apr1$';
    if (index($chk,$apr) == 0) {
        my $salt = $chk;
        $salt =~ s/^\Q$apr//;
        $salt =~ s/^(.*)\$/$1/;
        $salt = substr( $salt, 0, 8 );
        return 1 if apache_md5_crypt( $pass, $salt ) eq $chk;
    }
    elsif ( index($chk,$md5) == 0 ) {
        my $salt = $chk;
        $salt =~ s/^\Q$md5//;
        $salt =~ s/^(.*)\$/$1/;
        $salt = substr( $salt, 0, 8 );
        return 1 if unix_md5_crypt( $pass, $salt ) eq $chk;
    }

    return 1 if crypt( $pass, $chk ) eq $chk;
    return 1 if $pass eq $chk;
    return;
}

1;

=encoding utf8

=head1 NAME

POE::Component::Server::IRC::Common - provides a set of common functions for the POE::Component::Server::IRC suite.

=head1 SYNOPSIS

  use strict;
  use warnings;

  use POE::Component::Server::IRC::Common qw( :ALL );

  my $nickname = '^Lame|BOT[moo]';

  my $uppercase_nick = u_irc( $nickname );
  my $lowercase_nick = l_irc( $nickname );

  my $mode_line = 'ov+b-i Bob sue stalin*!*@*';
  my $hashref = parse_mode_line( $mode_line );

  my $banmask = 'stalin*';
  $full_banmask = parse_ban_mask( $banmask );

  if ( matches_mask( $full_banmask, 'stalin!joe@kremlin.ru' ) ) {
	print "EEK!";
  }

  my $results_hashref = matches_mask_array( \@masks, \@items_to_match_against );

  my $mode_change = gen_mode_change( 'abcde', 'befmZ' );

  my $passwd = mkpasswd( 'moocow' );


=head1 DESCRIPTION

POE::Component::IRC::Common provides a set of common functions for the L<POE::Component::Server::IRC> suite. There are included functions for uppercase and lowercase nicknames/channelnames and for parsing mode lines and ban masks.

=head1 FUNCTIONS

=over

=item C<u_irc>

Takes one mandatory parameter, a string to convert to IRC uppercase, and one optional parameter, the casemapping of the ircd ( which can be 'rfc1459', 'strict-rfc1459' or 'ascii'. Default is 'rfc1459' ). Returns the IRC uppercase equivalent of the passed string.

=item C<l_irc>

Takes one mandatory parameter, a string to convert to IRC lowercase, and one optional parameter, the casemapping of the ircd ( which can be 'rfc1459', 'strict-rfc1459' or 'ascii'. Default is 'rfc1459' ). Returns the IRC lowercase equivalent of the passed string.

=item C<parse_mode_line>

Takes a list representing an IRC mode line. Returns a hashref. If the modeline couldn't be parsed the hashref will be empty. On success the following keys will be available in the hashref:

   'modes', an arrayref of normalised modes;
   'args', an arrayref of applicable arguments to the modes;

Example:

   my $hashref = parse_mode_line( 'ov+b-i', 'Bob', 'sue', 'stalin*!*@*' );

   $hashref will be 
   {
	'modes' => [ '+o', '+v', '+b', '-i' ],
	'args'  => [ 'Bob', 'sue', 'stalin*!*@*' ],
   };

=item C<parse_ban_mask>

Takes one parameter, a string representing an IRC ban mask. Returns a normalised full banmask.

Example:

   $fullbanmask = parse_ban_mask( 'stalin*' );

   $fullbanmask will be 'stalin*!*@*';

=item C<matches_mask>

Takes two parameters, a string representing an IRC mask ( it'll be processed with parse_ban_mask() to ensure that it is normalised ) and something to match against the IRC mask, such as a nick!user@hostname string. Returns 1 if they match, 0 otherwise. Returns undef if parameters are missing. Optionally, one may pass the casemapping ( see u_irc() ), as this function ises u_irc() internally.

=item C<matches_mask_array>

Takes two array references, the first being a list of strings representing IRC mask, the second a list of somethings to test against the masks. Returns an empty hashref if there are no matches. Matches are returned are arrayrefs keyed on the mask that they matched.

=item C<gen_mode_change>

Takes two arguments, being a strings representing a set of IRC user modes before and after a change. Returns a string representing what changed.

  my $mode_change = gen_mode_change( 'abcde', 'befmZ' );
  $mode_change is now '-acd+fmZ'

=item C<unparse_mode_line>

Takes one argument a string representing a number of mode changes. Returns a condensed version of the changes.

  my $mode_line = unparse_mode_line('+o+o+o-v+v');
  $mode_line is now '+ooo-v+v'

=item C<validate_chan_name>

Takes one argument a channel name to validate. Returns true or false if the channel name is valid or not.

=item C<validate_nick_name>

Takes one argument a nickname to validate. Returns true or false if the nickname is valid or not.

=item C<parse_user>

Takes one parameter, a string representing a user in the form nick!user@hostname. In a scalar context it returns just the nickname. In a list context it returns a list consisting of the nick, user and hostname, respectively.

=item C<mkpasswd>

Takes one mandatory argument a plain string to 'encrypt'. If no further options are specified it uses C<crypt> to generate the
password. Specifying 'md5' option uses L<Crypt::PasswdMD5>'s C<unix_md5_crypt> function to generate the password. Specifying 
'apache' uses L<Crypt::PasswdMD5>'s C<apache_md5_crypt> function to generate the password.

  my $passwd = mkpasswd( 'moocow' ); # vanilla crypt()

  my $passwd = mkpasswd( 'moocow', md5 => 1 ) # unix_md5_crypt()

  my $passwd = mkpasswd( 'moocow', apache => 1 ) # apache_md5_crypt()

=item C<chkpasswd>

Takes two mandatory arguments, a password string and something to check that password against. The function first tries md5 
comparisons ( UNIX and Apache ), then C<crypt> and finally plain-text password check.

=back

=head1 AUTHOR

Chris 'BinGOs' Williams

=head1 LICENSE

Copyright E<copy> Chris Williams

This module may be used, modified, and distributed under the same terms as Perl itself. Please see the license that came with your Perl distribution for details.

=head1 SEE ALSO

L<POE::Component::Server::IRC>
