#!/usr/bin/perl
# dbbackup-run.pl - unattended backup runner.
#
# Invoked by cron through the Webmin cron wrapper (which sets up the Webmin
# environment and chdir's into this module directory), or manually for testing:
#
#     /usr/share/webmin/dbbackup/dbbackup-run.pl <schedule-id>
#
# The exit status is non-zero when any database failed, so cron mails the
# operator the captured output.

require './dbbackup-lib.pl';

my $id = $ARGV[0];
if (!$id || !&is_valid_id($id)) {
	print STDERR "Usage: dbbackup-run.pl <schedule-id>\n";
	exit(2);
	}
my $s = &get_schedule($id);
if (!$s) {
	print STDERR "dbbackup: unknown schedule '$id'\n";
	exit(2);
	}

my ($failed, $res) = &run_backup(&schedule_to_job($s));
my $logf = &write_job_log($id, $res->{'log'});
print $res->{'log'};
if ($failed) {
	print STDERR "dbbackup: schedule '$id' completed with errors (log: $logf)\n";
	exit(1);
	}
exit(0);
