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
license 'perl';
abstract 'A fully event-driven networkable IRC server daemon module';
build_requires 'Test::More' => 0.47;
install_script 'bin/pmkpasswd';
perl_version '5.006';
author_tests 'xt';
no_index directory => 'xt';
clean_files 'META.yml';

WriteMakefile(
			  'NAME'	=> 'POE::Component::Server::IRC',
			  'PREREQ_PM' => {
					  'strict' => 0,
					  'vars' => 0,
					  'constant' => 0,
					  'Carp'   => 0,
					  'Net::Netmask' => 1.9012,
					  'Socket' => 0,
					  'Date::Format' => 0,
					  'POE'    => 0.9999,
					  'POE::Wheel::SocketFactory' => 0,
					  'POE::Wheel::ReadWrite' => 0,
					  'POE::Filter::Stackable' => 0,
					  'POE::Filter::Line' => 0,
					  'POE::Filter::IRCD' => 2.2,
					  'POE::Component::Client::Ident' => 1.00,
					  'POE::Component::Client::DNS' => 1.00,
#					  ( uc( $dnsbl ) eq 'Y' ? ( 'POE::Component::Client::DNSBL' => 0 ) : () ),
					  'POE::Component::IRC' => 5.18,
					  'Algorithm::Diff' => 1.19,
					  'Crypt::PasswdMD5' => 1.3,
					 },
			  'VERSION_FROM' => 'lib/POE/Component/Server/IRC.pm',
			  'dist' => { 
					'COMPRESS' => 'gzip --best',
					'PREOP' => ( './tools/svn-log.perl > ./Changes' ),
			  },
			 );
