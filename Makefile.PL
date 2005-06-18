use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
# Blah!

WriteMakefile(
			  'NAME'	=> 'POE::Component::Server::IRC',
			  'PREREQ_PM' => {
							  'AnyData' => 0.10,
							  'POE'    => 0.06_07,
							  'Carp'   => 0,
							  'Socket' => 0,
							  'Date::Format' => 0,
							  'POE::Filter::IRCD' => 0,
							  'POE::Component::Client::Ident' => 0,
							  'POE::Component::Client::DNS' => 0,
							  'POE::Component::IRC' => 4.62
							 },
			  'VERSION_FROM' => 'lib/POE/Component/Server/IRC.pm', # finds $VERSION
			  'dist' => { 'COMPRESS' => 'gzip --best' },
			 );
