#!/usr/bin/perl
# act.cgi - the single dispatcher for every state-changing action.
#
# Security properties:
#   * Reached only by POST (Webmin's trusted-referer check gates it; we also
#     reject non-POST as defence in depth).
#   * Each action is individually ACL-gated via &require_acl.
#   * Every value is validated by the lib helpers; nothing is shell-built here.
#   * Destructive actions (restore / delete) show a confirmation step.
#   * Secrets (DB passwords, cloud keys/tokens, passphrases) are never written
#     to the Webmin action log or echoed back in a redirect.

require './dbbackup-lib.pl';
&ReadParse();
&error_setup($text{'err_actionfailed'});

our (%config, %text, %in, %access, %ENGINE_DUMP, $STAMP_RE);
%access = &get_module_acl();

$ENV{'REQUEST_METHOD'} eq 'POST' || &error($text{'err_post'});
my $c = $in{'c'} || '';

# ---- helpers ---------------------------------------------------------------

sub redir
{
my ($dest, $msg, $err) = @_;
my @p;
push(@p, "msg=".&urlize($msg)) if (defined($msg) && $msg ne '');
push(@p, "err=".&urlize($err)) if (defined($err) && $err ne '');
$dest .= ($dest =~ /\?/ ? "&" : "?").join("&", @p) if (@p);
&redirect($dest);
exit;
}

sub render
{
my ($title, $output) = @_;
&ui_print_header(undef, $title, "");
print "<pre class='comment'>".&html_escape($output)."</pre>";
&ui_print_footer("index.cgi", $text{'index_return'});
print "<script type='text/javascript'>if (window.viewer_init) { viewer_init() }</script>";
exit;
}

sub confirm
{
my ($title, $prompt, $hidden, $button, $level) = @_;
return if ($in{'confirmed'} || !$config{'confirm_destructive'});
&ui_print_header(undef, $title, "");
print &ui_alert_box(&html_escape($prompt), $level || 'warn');
print &ui_form_start("act.cgi", "post");
for (my $i = 0; $i + 1 < scalar(@$hidden); $i += 2) {
	print &ui_hidden($hidden->[$i], $hidden->[$i + 1]);
	}
print &ui_hidden("confirmed", 1);
print &ui_form_end([ [ undef, $button ], [ "cancel", $text{'confirm_cancel'} ] ]);
&ui_print_footer("index.cgi", $text{'index_return'});
exit;
}

sub selected
{
my ($field) = @_;
return grep { defined($_) && $_ ne '' } split(/\0/, $in{$field});
}

# Gather the SQLite file-chooser rows (sqlite_0 .. sqlite_N) into a clean list.
sub sqlite_fields
{
my @out;
foreach my $i (0 .. 19) {
	my $v = $in{"sqlite_$i"};
	next if (!defined($v) || $v !~ /\S/);
	$v =~ s/^\s+|\s+$//g;
	push(@out, $v);
	}
return @out;
}

&redir("index.cgi") if ($in{'cancel'});

# ---- run a backup ----------------------------------------------------------

if ($c eq 'run_backup') {
	&require_acl('backup');
	my @pids = grep { &get_profile($_) } &selected('p');
	@pids || &redir("index.cgi", undef, $text{'err_noselection'});
	if ($in{'encrypt'} && (!defined($in{'passphrase'}) || $in{'passphrase'} eq '')) {
		&redir("backup.cgi", undef, $text{'err_nopass'});
		}
	# Per-profile database selection: db_<id> checkboxes narrow a profile to
	# specific databases; none ticked means "all databases in that profile".
	my @targets;
	foreach my $pid (@pids) {
		my @dbs = &selected("db_".$pid);
		push(@targets, { 'profile' => $pid,
			'databases' => (@dbs ? \@dbs : [ 'all' ]) });
		}
	my %job = (
		'targets'      => \@targets,
		'dir'          => (defined($in{'dir'}) && $in{'dir'} ne '') ? $in{'dir'} : $config{'backup_dir'},
		'compression'  => $in{'compression'},
		'level'        => (defined($in{'level'}) && $in{'level'} ne '') ? $in{'level'} : undef,
		'encrypt'      => $in{'encrypt'},
		'passphrase'   => $in{'passphrase'},
		'retain_count' => (defined($in{'retain_count'}) && $in{'retain_count'} ne '') ? $in{'retain_count'} : undef,
		'retain_days'  => (defined($in{'retain_days'}) && $in{'retain_days'} ne '') ? $in{'retain_days'} : undef,
		'remotes'      => [ &selected('remote') ],
		'remote_mode'  => $in{'remote_mode'},
		);
	my ($f, $res) = &run_backup(\%job);
	&write_job_log("manual", $res->{'log'});
	&webmin_log("backup", "databases", join(",", @pids),
		{ 'set' => $res->{'stamp'} }) if ($res->{'stamp'});
	&render($text{'backup_result'}, $res->{'log'});
	}

# ---- profiles --------------------------------------------------------------

elsif ($c eq 'save_profile') {
	&require_acl('profiles');
	my $id = $in{'id'};
	# Name is optional - derive one when blank (SQLite -> domain/file label;
	# Docker -> type+container; otherwise type+host).
	if (!$in{'editing'} && (!defined($id) || $id eq '')) {
		my @sp = &sqlite_fields();
		my $base;
		if (($in{'type'} || '') eq 'sqlite' && @sp) {
			$base = &sqlite_label($sp[0]);
			}
		elsif (($in{'source'} || '') eq 'docker' && defined($in{'container'}) && $in{'container'} ne '') {
			$base = ($in{'type'} || 'db')."-".$in{'container'};
			}
		else {
			$base = ($in{'type'} || 'db')."-".((defined($in{'host'}) && $in{'host'} ne '') ? $in{'host'} : 'local');
			}
		$id = &unique_profile_id($base);
		}
	&is_valid_id($id) || &redir("profiles.cgi", undef, $text{'err_badid'});
	my $existing = &get_profile($id);
	# Blank password on an edit means "keep the stored one".
	my $pass = $in{'password'};
	$pass = $existing->{'password'} if ($in{'editing'} && (!defined($pass) || $pass eq '') && $existing);
	my %p = (
		'id'           => $id,
		'type'         => $in{'type'},
		'source'       => $in{'source'},
		'container'    => $in{'container'},
		'host'         => $in{'host'},
		'port'         => $in{'port'},
		'user'         => $in{'user'},
		'password'     => $pass,
		'socket'       => $in{'socket'},
		'auth_db'      => $in{'auth_db'},
		'project_domain' => $in{'project_domain'},
		'sqlite_paths' => join("\t", &sqlite_fields()),
		'desc'         => $in{'desc'},
		);
	my ($f, $e) = &save_profile(\%p);
	&webmin_log("save", "profile", $id) if (!$f);   # never logs the password
	&redir("profiles.cgi", $f ? undef : $text{'msg_profile_saved'}, $f ? $e : undef);
	}
elsif ($c eq 'import_profile') {
	&require_acl('profiles');
	my $eng = $in{'type'};
	$ENGINE_DUMP{$eng} || &redir("profiles.cgi", undef, $text{'err_badid'});
	my $p;
	if (($in{'source'} || '') eq 'docker') {
		&is_valid_ref($in{'container'}) || &redir("profiles.cgi", undef, $text{'err_badid'});
		$p = &detected_docker_profile($eng, $in{'container'});
		}
	else {
		$p = &detected_host_profile($eng);
		}
	my ($f, $e) = &save_profile($p);
	# Never log the imported credentials.
	&webmin_log("import", "profile", $p->{'id'}, { 'type' => $eng }) if (!$f);
	&redir($f ? "profiles.cgi" : "profiles.cgi?edit=".&urlize($p->{'id'}),
		$f ? undef : $text{'msg_profile_imported'}, $f ? $e : undef);
	}
elsif ($c eq 'profile_delete') {
	&require_acl('profiles');
	my @ids = &selected('d');
	@ids || &redir("profiles.cgi", undef, $text{'err_noselection'});
	&confirm($text{'prof_delete_button'}, &text('prof_confirm_delete', scalar(@ids)),
		[ ("c", "profile_delete"), map { ("d", $_) } @ids ],
		$text{'prof_delete_button'}, 'danger');
	&delete_profile($_) foreach (@ids);
	&webmin_log("delete", "profile", join(",", @ids));
	&redir("profiles.cgi", $text{'msg_profile_deleted'});
	}

# ---- cloud remotes ---------------------------------------------------------

elsif ($c eq 'save_remote_s3') {
	&require_acl('remotes');
	&is_valid_id($in{'name'}) || &redir("remotes.cgi", undef, $text{'err_badname'});
	($in{'access_key_id'} ne '' && $in{'secret_access_key'} ne '')
		|| &redir("remotes.cgi", undef, $text{'err_s3creds'});
	my %kv = (
		'type'              => 's3',
		'provider'          => ($in{'provider'} || 'AWS'),
		'access_key_id'     => $in{'access_key_id'},
		'secret_access_key' => $in{'secret_access_key'},
		'acl'               => 'private',
		);
	$kv{'region'}   = $in{'region'}   if ($in{'region'}   ne '');
	$kv{'endpoint'} = $in{'endpoint'} if ($in{'endpoint'} ne '');
	my ($f, $e) = &save_remote($in{'name'}, \%kv);
	&webmin_log("save", "remote", $in{'name'}, { 'type' => 's3' }) if (!$f);
	&redir("remotes.cgi", $f ? undef : $text{'msg_remote_saved'}, $f ? $e : undef);
	}
elsif ($c eq 'save_remote_token') {
	&require_acl('remotes');
	&is_valid_id($in{'name'}) || &redir("remotes.cgi", undef, $text{'err_badname'});
	my $kind = ($in{'kind'} eq 'drive') ? 'drive' : 'dropbox';
	my $token = $in{'token'};
	$token =~ s/[\r\n]+//g if (defined($token));
	$token ne '' || &redir("remotes.cgi", undef, $text{'err_notoken'});
	my %kv = ( 'type' => $kind, 'token' => $token );
	if ($kind eq 'drive') {
		$kv{'scope'} = 'drive';
		$kv{'root_folder_id'} = $in{'root_folder_id'} if ($in{'root_folder_id'} ne '');
		}
	my ($f, $e) = &save_remote($in{'name'}, \%kv);
	&webmin_log("save", "remote", $in{'name'}, { 'type' => $kind }) if (!$f);
	&redir("remotes.cgi", $f ? undef : $text{'msg_remote_saved'}, $f ? $e : undef);
	}
elsif ($c eq 'save_remote_raw') {
	&require_acl('remotes');
	&is_valid_id($in{'name'}) || &redir("remotes.cgi", undef, $text{'err_badname'});
	my %kv;
	foreach my $line (split(/\r?\n/, $in{'body'} || '')) {
		next if ($line !~ /\S/ || $line =~ /^\s*[#;]/);
		if ($line =~ /^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/) { $kv{$1} = $2; }
		}
	$kv{'type'} || &redir("remotes.cgi", undef, $text{'err_rawtype'});
	my ($f, $e) = &save_remote($in{'name'}, \%kv);
	&webmin_log("save", "remote", $in{'name'}, { 'type' => $kv{'type'} }) if (!$f);
	&redir("remotes.cgi", $f ? undef : $text{'msg_remote_saved'}, $f ? $e : undef);
	}
elsif ($c eq 'import_remote') {
	&require_acl('remotes');
	my ($f, $e) = &import_system_remote($in{'name'});
	&webmin_log("import", "remote", $in{'name'}) if (!$f);
	&redir("remotes.cgi", $f ? undef : $text{'msg_remote_imported'}, $f ? $e : undef);
	}
elsif ($c eq 'delete_remote') {
	&require_acl('remotes');
	my ($f, $e) = &delete_remote($in{'name'});
	if (!$f && $config{'default_remote'} eq $in{'name'}) {
		$config{'default_remote'} = ''; &save_module_config();
		}
	&webmin_log("delete", "remote", $in{'name'}) if (!$f);
	&redir("remotes.cgi", $f ? undef : $text{'msg_remote_deleted'}, $f ? $e : undef);
	}
elsif ($c eq 'set_default_remote') {
	&require_acl('remotes');
	&get_remote($in{'name'}) || &redir("remotes.cgi", undef, $text{'err_badname'});
	$config{'default_remote'} = $in{'name'};
	&save_module_config();
	&webmin_log("default", "remote", $in{'name'});
	&redir("remotes.cgi", $text{'msg_default_set'});
	}

# ---- upload an existing set ------------------------------------------------

elsif ($c eq 'upload_set') {
	&require_acl('remotes');
	my $set = $in{'set'};
	$set =~ $STAMP_RE || &redir("browse.cgi", undef, $text{'err_badpath'});
	&get_remote($in{'remote'}) || &redir("browse.cgi?set=".&urlize($set), undef, $text{'err_badname'});
	my $setdir = &backup_set_path($config{'backup_dir'}, $set);
	$setdir || &redir("browse.cgi", undef, $text{'err_badpath'});
	my ($f, $o) = &rclone_upload($setdir, $set, $in{'remote'},
		$config{'remote_base'}, $config{'remote_mode'});
	&webmin_log("upload", "set", $set, { 'remote' => $in{'remote'} }) if (!$f);
	&render($text{'browse_upload'}, $o eq '' ? $text{'msg_uploaded'} : $o);
	}

# ---- restore ---------------------------------------------------------------

elsif ($c eq 'restore') {
	&require_acl('restore');
	my $p = &get_profile($in{'profile'});
	$p || &redir("restore.cgi", undef, $text{'err_badprofile'});
	my $file = $in{'file'};
	&valid_abs_path($file) || &redir("restore.cgi", undef, $text{'err_badpath'});
	# Only allow restoring from inside the configured backup directory.
	index($file, $config{'backup_dir'}."/") == 0
		|| &redir("restore.cgi", undef, $text{'err_outside'});
	# The passphrase is a secret, so it must never be reflected into the
	# confirmation page. On the first (unconfirmed) submission we stash it
	# server-side under a random token and carry only the token through the
	# confirm form; on confirmation we read it back and delete the stash.
	my $pass;
	if ($in{'confirmed'} || !$config{'confirm_destructive'}) {
		$pass = (defined($in{'passtoken'}) && $in{'passtoken'} ne '')
			? &unstash_secret($in{'passtoken'}) : $in{'passphrase'};
		}
	else {
		my $tok = &stash_secret($in{'passphrase'});
		&confirm($text{'restore_button'},
			&text('restore_confirm', &html_escape($in{'profile'})),
			[ ("c", "restore"), ("profile", $in{'profile'}), ("target", $in{'target'}),
			  ("file", $file), ("passtoken", $tok) ],
			$text{'restore_button'}, 'danger');
		}
	my ($f, $o) = &restore_database($p, $in{'target'}, $file,
		{ 'passphrase' => $pass });
	# Log the file and target, never the passphrase.
	&webmin_log("restore", "database", $in{'profile'},
		{ 'file' => $file, 'target' => $in{'target'} }) if (!$f);
	&render($text{'restore_button'}, $f ? $o : $text{'msg_restored'});
	}

# ---- delete backup sets ----------------------------------------------------

elsif ($c eq 'delete_set') {
	&require_acl('delete');
	$in{'set'} =~ $STAMP_RE || &redir("browse.cgi", undef, $text{'err_badpath'});
	&confirm($text{'browse_delete'}, &text('browse_confirm_delete', &html_escape($in{'set'})),
		[ ("c", "delete_set"), ("set", $in{'set'}) ], $text{'browse_delete'}, 'danger');
	my ($f, $e) = &safe_delete_set($config{'backup_dir'}, $in{'set'});
	&webmin_log("delete", "set", $in{'set'}) if (!$f);
	&redir("browse.cgi", $f ? undef : $text{'msg_set_deleted'}, $f ? $e : undef);
	}
elsif ($c eq 'delete_sets') {
	&require_acl('delete');
	my @sets = grep { $_ =~ $STAMP_RE } &selected('d');
	@sets || &redir("browse.cgi", undef, $text{'err_noselection'});
	&confirm($text{'browse_delete_sel'}, &text('browse_confirm_delete_n', scalar(@sets)),
		[ ("c", "delete_sets"), map { ("d", $_) } @sets ], $text{'browse_delete_sel'}, 'danger');
	my @err;
	foreach my $s (@sets) {
		my ($f, $e) = &safe_delete_set($config{'backup_dir'}, $s);
		push(@err, "$s: $e") if ($f);
		}
	&webmin_log("delete", "sets", join(",", @sets));
	&redir("browse.cgi", @err ? undef : $text{'msg_set_deleted'}, @err ? join("; ", @err) : undef);
	}

# ---- schedules -------------------------------------------------------------

elsif ($c eq 'save_schedule') {
	&require_acl('schedule');
	&cron_available() || &error($text{'sched_nocron'});
	&foreign_require("cron");
	my $id = $in{'id'};
	&is_valid_id($id) || &redir("schedule.cgi", undef, $text{'err_badid'});
	my @pids = grep { &get_profile($_) } &selected('p');
	@pids || &redir("schedule.cgi", undef, $text{'err_noselection'});
	my $existing = &get_schedule($id);
	my $pass = $in{'passphrase'};
	$pass = $existing->{'passphrase'} if ($in{'editing'} && (!defined($pass) || $pass eq '') && $existing);
	my %job;
	&cron::parse_times_input(\%job, \%in);
	my %s = (
		'id'           => $id,
		'layout'       => ($in{'layout'} || '') eq 'daily' ? 'daily' : 'timestamped',
		'profiles'     => join("\t", @pids),
		'dir'          => $in{'dir'},
		'compression'  => $in{'compression'},
		'level'        => $in{'level'},
		'encrypt'      => $in{'encrypt'} ? 1 : 0,
		'passphrase'   => $pass,
		'retain_count' => $in{'retain_count'},
		'retain_days'  => $in{'retain_days'},
		'remotes'      => join("\t", &selected('remote')),
		'remote_mode'  => $in{'remote_mode'},
		'mins'         => $job{'mins'},     'hours'    => $job{'hours'},
		'days'         => $job{'days'},     'months'   => $job{'months'},
		'weekdays'     => $job{'weekdays'},
		);
	my ($f, $e) = &save_schedule(\%s);
	$f && &redir("schedule.cgi", undef, $e);
	my ($cf, $ce) = &install_cron($id, \%s);
	&webmin_log("save", "schedule", $id) if (!$cf);
	&redir("schedule.cgi", $cf ? undef : $text{'msg_sched_saved'}, $cf ? $ce : undef);
	}
elsif ($c eq 'delete_schedule') {
	&require_acl('schedule');
	&is_valid_id($in{'id'}) || &redir("schedule.cgi", undef, $text{'err_badid'});
	&delete_schedule($in{'id'});
	&webmin_log("delete", "schedule", $in{'id'});
	&redir("schedule.cgi", $text{'msg_sched_deleted'});
	}
elsif ($c eq 'run_schedule') {
	&require_acl('schedule');
	my $s = &get_schedule($in{'id'});
	$s || &redir("schedule.cgi", undef, $text{'err_badid'});
	my ($f, $res) = &run_backup(&schedule_to_job($s));
	&write_job_log($s->{'id'}, $res->{'log'});
	&webmin_log("run", "schedule", $s->{'id'}, { 'set' => $res->{'stamp'} }) if ($res->{'stamp'});
	&render($text{'backup_result'}, $res->{'log'});
	}

else {
	&error($text{'err_unknown'});
	}
