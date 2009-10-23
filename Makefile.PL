#use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
# Blah!

use 5.006;
use strict;
use inc::Module::Install;

my $GOT_IRCD;

BEGIN {
   $GOT_IRCD = 0;
   eval {
	require POE::Component::Server::IRC;
	$GOT_IRCD = 1 if $POE::Component::Server::IRC::VERSION < 0.99;
   };
}

if ( $GOT_IRCD ) {

print <<NOTICE;

\a--------------------------------------------------------------
You appear to have an older version of this module installed.

Be warned that the API has changed considerably and that your
existing scripts will need to be updated.

Please check the documentation after installation for details.
--------------------------------------------------------------

NOTICE

}

#my $dnsbl = prompt( 'Do you want optional DNSBL support ( requires POE::Component::Client::DNSBL ) [N/y]?', 'N' );

author 'Chris Williams <chris@bingosnet.co.uk>';
name 'POE-Component-Server-IRC';
version_from 'lib/POE/Component/Server/IRC.pm';
license 'perl';
abstract 'A fully event-driven networkable IRC server daemon module';
build_requires 'Test::More' => 0.47;
install_script 'bin/pmkpasswd';
perl_version '5.006';
author_tests 'xt';
no_index directory => 'xt';
makemaker_args(dist => { PREOP => "$^X ./tools/git-log.pl > ./Changes" });
requires 'Carp'   => 0;
requires 'Net::Netmask' => 1.9012;
requires 'Socket' => 0;
requires 'Date::Format' => 0;
requires 'POE'    => 0.9999;
requires 'POE::Component::Pluggable' => 1.14;
requires 'POE::Wheel::SocketFactory' => 0;
requires 'POE::Wheel::ReadWrite' => 0;
requires 'POE::Filter::Stackable' => 0;
requires 'POE::Filter::Line' => 0;
requires 'POE::Filter::IRCD' => 2.2;
requires 'POE::Component::Client::Ident' => 1.00;
requires 'POE::Component::Client::DNS' => 1.00;
requires 'POE::Component::IRC' => 5.70;
requires 'Algorithm::Diff' => 1.19;
requires 'Crypt::PasswdMD5' => 1.3;
auto_license holder => 'Chris Williams';
auto_provides;
githubmeta;
WriteAll();
