package POE::Component::Server::IRC::Common;

use strict;
use warnings;

our $VERSION = '1.00';

# We export some stuff
require Exporter;
our @ISA = qw( Exporter );
our %EXPORT_TAGS = ( 'ALL' => [ qw(u_irc l_irc parse_mode_line unparse_mode_line parse_ban_mask validate_nick_name validate_chan_name matches_mask_array matches_mask) ] );
Exporter::export_ok_tags( 'ALL' );

sub u_irc {
  my ($value) = shift || return undef;

  $value =~ tr/a-z{}|^/A-Z[]\\~/;
  return $value;
}

sub l_irc {
  my $value = shift || return;

  $value =~ tr/A-Z[]\\~/a-z{}|^/;
  return $value;
}

sub parse_mode_line {
  my $hashref = { };
  my $count = 0;
  foreach my $arg ( @_ ) {
        if ( $arg =~ /^(\+|-)/ or $count == 0 ) {
           my ($action) = '+';
           foreach my $char ( split (//,$arg) ) {
                if ( $char eq '+' or $char eq '-' ) {
                   $action = $char;
                } else {
                   push ( @{ $hashref->{modes} }, $action . $char );
                }
           }
         } else {
                push ( @{ $hashref->{args} }, $arg );
         }
         $count++;
  }
  return $hashref;
}

sub parse_ban_mask {
  my $arg = shift || return undef;

  $arg =~ s/\x2a+/\x2a/g;
  my @ban; my $remainder;
  if ( $arg !~ /\x21/ and $arg =~ /\x40/ ) {
     $remainder = $arg;
  } else {
     ($ban[0],$remainder) = split (/\x21/,$arg,2);
  }
  $remainder =~ s/\x21//g if ( defined ( $remainder ) );
  @ban[1..2] = split (/\x40/,$remainder,2) if ( defined ( $remainder ) );
  $ban[2] =~ s/\x40//g if ( defined ( $ban[2] ) );
  for ( my $i = 0; $i <= 2; $i++ ) {
    if ( ( not defined ( $ban[$i] ) ) or $ban[$i] eq '' ) {
       $ban[$i] = '*';
    }
  }
  return $ban[0] . '!' . $ban[1] . '@' . $ban[2];
}

sub unparse_mode_line {
  my $line = $_[0] || return undef;

  my $action; my $return;
  foreach my $mode ( split(//,$line) ) {
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
  my $nickname = shift || return 0;
  return 1 if $nickname =~ /^[A-Za-z_0-9`\-^\|\\\{}\[\]]+$/;
  return 0;
}

sub validate_chan_name {
  my $channel = shift || return 0;
  return 1 if $channel =~ /^(\x23|\x26|\x2B)/ and $channel !~ /(\x20|\x07|\x00|\x0D|\x0A|\x2C)+/;
  return 0;
}

sub matches_mask_array {
  my ($masks,$matches) = @_;
  return unless $masks and $matches;
  return unless ref $masks eq 'ARRAY';
  return unless ref $matches eq 'ARRAY';
  my $ref = { };
  foreach my $mask ( @{ $masks } ) {
	foreach my $match ( @{ $matches } ) {
    	   push @{ $ref->{ $mask } }, $match if matches_mask( $mask, $match );
	}
  }
  return $ref;
}

sub matches_mask {
  my ($mask,$match) = @_;
  return unless $mask and $match;
  $mask =~ s/\x2A+/\x2A/g;
  my $umask = quotemeta( u_irc( $mask ) );
  $umask =~ s/\\\*/[\x01-\xFF]{0,}/g;
  $umask =~ s/\\\?/[\x01-\xFF]{1,1}/g;
  return 1 if $match =~ /^$umask$/;
  return 0;
}

1;
__END__
