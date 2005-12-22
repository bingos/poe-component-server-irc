use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
# Blah!

WriteMakefile(
			  'NAME'	=> 'POE::Component::Server::IRC',
			  'PREREQ_PM' => {
							  'POE'    => 0.3202,
							  'Carp'   => 0,
							  'Net::Netmask' => 1.9012,
							  'Socket' => 0,
							  'Date::Format' => 0,
							  'POE::Filter::IRCD' => 1.4,
							  'POE::Filter::Zlib' => 0,
							  'POE::Component::Client::Ident' => 0,
							  'POE::Component::Client::DNS' => 0,
							  'POE::Component::IRC' => 4.75
							 },
			  'VERSION_FROM' => 'lib/POE/Component/Server/IRC.pm', # finds $VERSION
			  'dist' => { 'COMPRESS' => 'gzip --best' },
			 );
