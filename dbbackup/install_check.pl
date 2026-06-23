# install_check.pl
# Lets Webmin auto-detect whether this module is usable on the host.

do './dbbackup-lib.pl';

# is_installed(mode) - return 2 when at least one supported database client OR
# Docker is present, 0 otherwise. Webmin uses this when refreshing modules.
sub is_installed
{
my ($mode) = @_;
my $eng = &host_engines();
return 2 if (%$eng);
return 2 if (&has_command("docker"));
return 0;
}

1;
