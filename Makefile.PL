use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
# Blah!

WriteMakefile(
			  'NAME'	=> 'POE::Component::Server::IRC',
			  'PM'      => { 'IRC.pm' => '$(INST_LIBDIR)/IRC.pm',
					 'IRC-OperServ.pm' => '$(INST_LIBDIR)/IRC/OperServ.pm',
				       },
			  'PREREQ_PM' => {
							  'POE'    => 0.06_07,
							  'Carp'   => 0,
							  'Socket' => 0,
							  'Date::Format' => 0,
							  'POE::Filter::IRCD' => 0,
							  'POE::Component::Client::Ident' => 0.7,
							  'POE::Component::Client::DNS' => 0.98,
							 },
			  'VERSION_FROM' => 'IRC.pm', # finds $VERSION
			  'dist' => { 'COMPRESS' => 'gzip --best' },
			 );
