use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
# Blah!

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

WriteMakefile(
			  'NAME'	=> 'POE::Component::Server::IRC',
			  'PREREQ_PM' => {
					  'warnings' => 0,
					  'POE'    => 0.3202,
					  'Carp'   => 0,
					  'Net::Netmask' => 1.9012,
					  'Socket' => 0,
					  'Date::Format' => 0,
					  'POE::Filter::IRCD' => 1.7,
					  'POE::Filter::Zlib' => 0,
					  'POE::Component::Client::Ident' => 1.00,
					  'POE::Component::Client::DNS' => 0.99,
					  'POE::Component::IRC' => 4.95
					 },
			  'VERSION_FROM' => 'lib/POE/Component/Server/IRC.pm',
			  'dist' => { 'COMPRESS' => 'gzip --best' },
			 );
