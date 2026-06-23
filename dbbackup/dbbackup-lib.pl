# dbbackup-lib.pl
# Core library for the Database Backup Webmin module.
#
# SECURITY MODEL
# --------------
# Webmin's command runners (execute_command / backquote_command) execute through
# "/bin/sh -c", so every byte of a command string is shell-interpreted. This
# module therefore NEVER interpolates raw user input into a command string. The
# rules, enforced throughout:
#
#   1. Every value that originates from CGI input, a stored profile, a schedule
#      or Docker output is wrapped with &sq() (single-quote shell escaping)
#      before being placed in a command string. Constant flags are literals.
#   2. Identifiers (database names, profile ids, remote names, container refs)
#      are validated against an allowlist regex before use, and must never start
#      with "-" (so a value can never be smuggled in as a command-line option).
#   3. Database SECRETS are never placed on a command line / argv (where they
#      would be visible in "ps"). Instead:
#        * MySQL/MariaDB - a 0600 --defaults-extra-file holding [client] creds.
#        * PostgreSQL    - the PGPASSWORD environment variable.
#        * MongoDB       - a 0600 --config file holding "password:".
#        * Docker dumps  - the password is streamed on the child's STDIN into an
#                          environment variable (or temp config) INSIDE the
#                          container, so it never touches host argv.
#        * GnuPG / rclone- passphrases via --passphrase-fd 0 (STDIN); cloud
#                          tokens/keys are written to a 0600 rclone config file,
#                          never passed on argv.
#   4. Retention DELETION only ever touches direct children of the configured
#      backup directory whose names match this module's timestamp pattern. There
#      is no "rm -rf" and no "find -exec rm".
#   5. Read-only commands pass $safe=1; mutations pass $safe=0 so Webmin's
#      read-only-mode veto applies. State changes, ACL gating and &webmin_log
#      auditing live in the CGIs.

BEGIN { push(@INC, ".."); };

use strict;
use warnings;
use WebminCore;
use POSIX qw(strftime);
use File::Copy qw(move copy);

init_config();

our (%config, %text, %gconfig);
our ($module_config_directory, $module_name, $remote_user, $config_directory);

# JSON::PP ships with core Perl (>= 5.14). Load lazily, degrade gracefully.
my $have_json = eval { require JSON::PP; 1; };

# Per-module state directories (live under /etc/webmin/<module>, root-only).
our $profiles_dir  = "$module_config_directory/profiles";
our $schedules_dir = "$module_config_directory/schedules";
our $logs_dir      = "$module_config_directory/logs";
our $stash_dir     = "$module_config_directory/.stash";
our $rclone_config = "$module_config_directory/rclone.conf";

# Engine -> candidate dump / client tools (first found on the host wins).
our %ENGINE_DUMP = (
	'mysql'    => [ 'mysqldump', 'mariadb-dump' ],
	'mariadb'  => [ 'mariadb-dump', 'mysqldump' ],
	'postgres' => [ 'pg_dump' ],
	'mongodb'  => [ 'mongodump' ],
	'sqlite'   => [ 'sqlite3' ],
	);
our %ENGINE_CLIENT = (
	'mysql'    => [ 'mysql', 'mariadb' ],
	'mariadb'  => [ 'mariadb', 'mysql' ],
	'postgres' => [ 'psql' ],
	'mongodb'  => [ 'mongosh', 'mongo' ],
	'sqlite'   => [ 'sqlite3' ],
	);
our %ENGINE_LABEL = (
	'mysql'    => 'MySQL',
	'mariadb'  => 'MariaDB',
	'postgres' => 'PostgreSQL',
	'mongodb'  => 'MongoDB',
	'sqlite'   => 'SQLite',
	);

# For auto-detection of containerised databases: the environment variable that
# holds the admin password, and the conventional admin username, per engine.
our %ENGINE_DOCKER_PWENV = (
	'mysql'    => 'MYSQL_ROOT_PASSWORD',
	'mariadb'  => 'MARIADB_ROOT_PASSWORD',
	'postgres' => 'POSTGRES_PASSWORD',
	'mongodb'  => 'MONGO_INITDB_ROOT_PASSWORD',
	);
our %ENGINE_DEFAULT_USER = (
	'mysql'    => 'root',
	'mariadb'  => 'root',
	'postgres' => 'postgres',
	'mongodb'  => 'root',
	);

# ----------------------------------------------------------------------------
# Shell quoting and validation
# ----------------------------------------------------------------------------

# sq(STRING) - single-quote-escape ONE shell token for /bin/sh.
sub sq
{
my ($s) = @_;
$s = '' if (!defined($s));
$s =~ s/'/'\\''/g;
return "'".$s."'";
}

# A profile id / remote name / schedule id: our own safe identifier.
sub is_valid_id
{
my ($v) = @_;
return defined($v) && $v =~ /^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$/;
}

# A container name or 12-64 hex id.
sub is_valid_ref
{
my ($v) = @_;
return 0 if (!defined($v));
return 1 if ($v =~ /^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$/);
return 1 if ($v =~ /^[0-9a-f]{12,64}$/);
return 0;
}

# A database name. Conservative but practical; crucially never starts with "-"
# (which would otherwise be parsed as an option by the dump tool).
sub is_valid_dbname
{
my ($v) = @_;
return defined($v) && $v =~ /^[A-Za-z0-9_][A-Za-z0-9_\$.\-]{0,127}$/;
}

# A free token that must not contain control chars / NULs and not begin "-".
sub is_clean_token
{
my ($v) = @_;
return defined($v) && $v ne '' && $v !~ /[\0\n\r]/ && $v !~ /^-/;
}

# An absolute, traversal-free host path.
sub valid_abs_path
{
my ($p) = @_;
return 0 if (!defined($p) || $p eq '');
return 0 if ($p =~ /[\0\n\r]/);
return 0 if ($p !~ m!^/!);
return 0 if ($p =~ m!(^|/)\.\.(/|$)!);
return 1;
}

# A remote sub-path (relative, no traversal, no leading slash).
sub valid_remote_path
{
my ($p) = @_;
return 1 if (!defined($p) || $p eq '');
return 0 if ($p =~ /[\0\n\r]/);
return 0 if ($p =~ m!(^|/)\.\.(/|$)!);
return 0 if ($p =~ m!^/!);
return 1;
}

# A secret that is safe to store and stream (no newlines - the Docker STDIN
# helper reads exactly one line).
sub valid_secret
{
my ($v) = @_;
return 1 if (!defined($v) || $v eq '');
return $v !~ /[\0\n\r]/;
}

# sanitize a database name into a safe output filename component.
sub safe_filename
{
my ($v) = @_;
$v = 'db' if (!defined($v) || $v eq '');
$v =~ s/[^A-Za-z0-9_.\-]/_/g;
$v =~ s/^\.+//;
return $v eq '' ? 'db' : $v;
}

# parse_lines(TEXT) -> trimmed, non-empty lines (for textareas e.g. SQLite paths).
sub parse_lines
{
my ($v) = @_;
return grep { $_ ne '' } map { my $x = $_; $x =~ s/^\s+|\s+$//g; $x }
		split(/\r?\n/, defined($v) ? $v : "");
}

# scrub_record(\%h) - collapse CR/LF in every value to a single space, so an
# embedded newline can never corrupt Webmin's one-value-per-line config files.
# (sqlite_paths is tab-joined and never contains newlines.)
sub scrub_record
{
my ($h) = @_;
foreach my $k (keys %$h) {
	$h->{$k} =~ s/[\r\n]+/ /g if (defined($h->{$k}));
	}
}

# ----------------------------------------------------------------------------
# Low-level execution
# ----------------------------------------------------------------------------

# run_cmd(CMD, [STDIN_REF], [SAFE], [\%ENV]) -> ($failed, $stdout, $stderr)
# CMD must already be built from literal flags and &sq()-quoted values. Extra
# environment variables (e.g. PGPASSWORD) are applied only for this call.
sub run_cmd
{
my ($cmd, $stdin, $safe, $env) = @_;
$safe = 0 if (!defined($safe));
local %ENV = %ENV;
if (ref($env) eq 'HASH') {
	foreach my $k (keys %$env) { $ENV{$k} = $env->{$k}; }
	}
my ($out, $err);
my $status = &execute_command($cmd, $stdin, \$out, \$err, 0, $safe);
return (($status != 0 ? 1 : 0), defined($out) ? $out : '', defined($err) ? $err : '');
}

# Path of a tool, or undef.
sub tool { return scalar(&has_command($_[0])); }

# engine_tool(ENGINE, 'dump'|'client') -> host path of the best tool, or undef.
sub engine_tool
{
my ($eng, $which) = @_;
my $list = ($which && $which eq 'client') ? $ENGINE_CLIENT{$eng} : $ENGINE_DUMP{$eng};
return undef if (!$list);
foreach my $c (@$list) { my $p = &has_command($c); return $p if ($p); }
return undef;
}

# host_engines() -> { engine => dump-tool-path } for engines installed on host.
sub host_engines
{
my %e;
foreach my $eng (keys %ENGINE_DUMP) {
	my $p = &engine_tool($eng, 'dump');
	$e{$eng} = $p if ($p);
	}
return \%e;
}

# ----------------------------------------------------------------------------
# Docker helpers
# ----------------------------------------------------------------------------

sub docker_bin
{
my $p = &has_command("docker");
return $p ? &sq($p) : "docker";
}

sub context_flag
{
return $config{'docker_context'} ? " --context ".&sq($config{'docker_context'}) : "";
}

sub docker_available { return &has_command("docker") ? 1 : 0; }

# guess_engine(IMAGE) -> engine key, from a container image reference.
sub guess_engine
{
my ($image) = @_;
my $i = lc(defined($image) ? $image : '');
return 'mariadb'  if ($i =~ /mariadb/);
return 'mysql'    if ($i =~ /(^|\/)(mysql|percona)/ || $i =~ /mysql/);
return 'postgres' if ($i =~ /postgres|postgis|pgvector|timescale/);
return 'mongodb'  if ($i =~ /mongo/);
return undef;
}

# docker_db_containers() -> ($failed, \@list) of running containers that look
# like a database, each { id, name, image, engine }.
sub docker_db_containers
{
return (0, []) if (!&docker_available());
my ($f, $out, $err) = &run_cmd(
	&docker_bin().&context_flag().' ps --no-trunc --format "{{json .}}"', undef, 1);
return ($f, $err || $out) if ($f);
return (0, []) if (!$have_json);
my @list;
foreach my $line (split(/\r?\n/, $out)) {
	next if ($line !~ /\S/);
	my $o = eval { JSON::PP::decode_json($line) };
	next if (!$o || ref($o) ne 'HASH');
	my $eng = &guess_engine($o->{'Image'});
	next if (!$eng);
	push(@list, {
		'id'     => $o->{'ID'},
		'name'   => $o->{'Names'},
		'image'  => $o->{'Image'},
		'engine' => $eng,
		});
	}
return (0, \@list);
}

# ----------------------------------------------------------------------------
# Connection profiles (stored in $profiles_dir, one 0600 file each)
# ----------------------------------------------------------------------------

sub ensure_dir
{
my ($dir, $mode) = @_;
$mode = 0700 if (!defined($mode));
if (!-d $dir) { &make_dir($dir, $mode, 1); }
chmod($mode, $dir);
}

sub profile_file { return "$profiles_dir/".$_[0]; }

# list_profiles() -> @ of profile hashrefs (sorted by id).
sub list_profiles
{
&ensure_dir($profiles_dir);
my @out;
opendir(my $dh, $profiles_dir) || return ();
my @ids = grep { &is_valid_id($_) && -f "$profiles_dir/$_" } readdir($dh);
closedir($dh);
foreach my $id (sort @ids) {
	my $p = &get_profile($id);
	push(@out, $p) if ($p);
	}
return @out;
}

# get_profile(ID) -> hashref or undef.
sub get_profile
{
my ($id) = @_;
return undef if (!&is_valid_id($id));
my $f = &profile_file($id);
return undef if (!-r $f);
my %p;
&read_file($f, \%p);
$p{'id'} = $id;
return \%p;
}

# save_profile(\%p) - validate and persist a profile (0600). Returns ($f,$err).
sub save_profile
{
my ($p) = @_;
&is_valid_id($p->{'id'}) || return (1, "Invalid profile id");
$ENGINE_DUMP{$p->{'type'}} || return (1, "Unknown database type");
my $src = $p->{'source'} || 'host';
$src eq 'host' || $src eq 'docker' || return (1, "Invalid source");
&valid_secret($p->{'password'}) || return (1, "Password may not contain newlines");
if ($src eq 'docker') {
	&is_valid_ref($p->{'container'}) || return (1, "Invalid or missing container");
	}
if (defined($p->{'host'}) && $p->{'host'} ne '' && !&is_clean_token($p->{'host'})) {
	return (1, "Invalid host");
	}
if (defined($p->{'port'}) && $p->{'port'} ne '' && $p->{'port'} !~ /^\d{1,5}$/) {
	return (1, "Invalid port");
	}
if (defined($p->{'user'}) && $p->{'user'} ne '' && !&is_clean_token($p->{'user'})) {
	return (1, "Invalid username");
	}
if ($p->{'type'} eq 'sqlite') {
	my @paths = grep { $_ ne '' } map { my $x=$_; $x=~s/^\s+|\s+$//g; $x } split(/\t/, $p->{'sqlite_paths'} || '');
	@paths || return (1, "At least one SQLite file path is required");
	foreach my $sp (@paths) { &valid_abs_path($sp) || return (1, "Invalid SQLite path: $sp"); }
	$p->{'sqlite_paths'} = join("\t", @paths);
	}
&ensure_dir($profiles_dir);
my $f = &profile_file($p->{'id'});
my %store = %$p;
delete $store{'id'};
&scrub_record(\%store);
&write_file($f, \%store);
chmod(0600, $f);
return (0, undef);
}

sub delete_profile
{
my ($id) = @_;
&is_valid_id($id) || return (1, "Invalid profile id");
my $f = &profile_file($id);
unlink($f) if (-e $f);
return (0, undef);
}

# profile_label(\%p) - a human description for the UI.
sub profile_label
{
my ($p) = @_;
my $eng = $ENGINE_LABEL{$p->{'type'}} || $p->{'type'};
my $where = ($p->{'source'} || 'host') eq 'docker'
	? "container ".($p->{'container'} || '?')
	: ($p->{'host'} ? $p->{'host'}.($p->{'port'} ? ":".$p->{'port'} : '') : "localhost");
return "$eng \@ $where";
}

# unique_profile_id(BASE) - a free profile id derived from BASE.
sub unique_profile_id
{
my ($base) = @_;
$base = lc(defined($base) ? $base : 'db');
$base =~ s/[^a-z0-9_.\-]+/-/g;
$base =~ s/^[-.]+//;
$base = 'db' if (!&is_valid_id($base));
my $id = $base; my $n = 1;
while (-e &profile_file($id)) { $id = $base."-".(++$n); }
return $id;
}

# ----------------------------------------------------------------------------
# Auto-detection of credentials already present on the system
# ----------------------------------------------------------------------------

# webmin_db_config(KIND) - pull connection credentials from Webmin's own
# 'mysql' / 'postgresql' module config, or undef when unavailable. This lets the
# user import an already-working local connection in one click.
sub webmin_db_config
{
my ($kind) = @_;
my $base = $config_directory || $ENV{'WEBMIN_CONFIG'} || "/etc/webmin";
my $f = "$base/$kind/config";
return undef if (!-r $f);
my %c;
&read_file($f, \%c);
if ($kind eq 'mysql') {
	return { 'user' => $c{'login'}, 'password' => $c{'pass'},
		 'host' => $c{'host'}, 'port' => $c{'port'}, 'socket' => $c{'sock'} };
	}
return { 'user' => $c{'user'}, 'password' => $c{'pass'},
	 'host' => $c{'host'}, 'port' => $c{'port'} };
}

# container_env(CONTAINER, VAR) - value of an environment variable baked into a
# running container (e.g. MYSQL_ROOT_PASSWORD), or undef. Used to auto-fill the
# admin password for a containerised database.
sub container_env
{
my ($container, $var) = @_;
return undef if (!&is_valid_ref($container) || $var !~ /^[A-Za-z_][A-Za-z0-9_]*$/);
my ($f, $out) = &run_cmd(
	&docker_bin().&context_flag().' inspect --format '.
	&sq('{{range .Config.Env}}{{println .}}{{end}}').' '.&sq($container), undef, 1);
return undef if ($f);
foreach my $line (split(/\r?\n/, $out)) {
	return $1 if ($line =~ /^\Q$var\E=(.*)$/);
	}
return undef;
}

# detected_host_profile(ENGINE) -> \%p ready to save, importing credentials from
# the matching Webmin database module (mysql/postgresql). Always returns a hash
# (credentials may be blank - e.g. local socket auth, which is correct).
sub detected_host_profile
{
my ($eng) = @_;
my $cr = {};
if ($eng eq 'mysql' || $eng eq 'mariadb') { $cr = &webmin_db_config('mysql') || {}; }
elsif ($eng eq 'postgres')                { $cr = &webmin_db_config('postgresql') || {}; }
# MongoDB/SQLite have no Webmin credential module - create a bare local profile.
return {
	'id'       => &unique_profile_id($eng."-local"),
	'type'     => $eng,
	'source'   => 'host',
	'user'     => $cr->{'user'},
	'password' => $cr->{'password'},
	'host'     => $cr->{'host'},
	'port'     => $cr->{'port'},
	'socket'   => $cr->{'socket'},
	'desc'     => "Local $ENGINE_LABEL{$eng} (imported from Webmin)",
	};
}

# detected_docker_profile(ENGINE, CONTAINER) -> \%p ready to save, reading the
# admin user/password from the container's environment when present.
sub detected_docker_profile
{
my ($eng, $container) = @_;
my $user = $ENGINE_DEFAULT_USER{$eng} || 'root';
# Candidate password env vars (MariaDB images honour either name).
my @cand = ($eng eq 'mariadb') ? ('MARIADB_ROOT_PASSWORD', 'MYSQL_ROOT_PASSWORD')
	: ($ENGINE_DOCKER_PWENV{$eng} ? ($ENGINE_DOCKER_PWENV{$eng}) : ());
my $pw;
foreach my $v (@cand) { $pw = &container_env($container, $v); last if (defined($pw)); }
if ($eng eq 'mongodb') {
	$user = &container_env($container, 'MONGO_INITDB_ROOT_USERNAME') || $user;
	}
if ($eng eq 'postgres') {
	$user = &container_env($container, 'POSTGRES_USER') || $user;
	}
# When no password env is set, leave credentials blank (the DB may use trust /
# socket auth, or the operator will fill them in).
my $authed = defined($pw);
return {
	'id'        => &unique_profile_id($eng."-".$container),
	'type'      => $eng,
	'source'    => 'docker',
	'container' => $container,
	'user'      => $authed ? $user : '',
	'password'  => $authed ? $pw : '',
	'desc'      => "$ENGINE_LABEL{$eng} container \"$container\" (auto-detected)",
	};
}

# ----------------------------------------------------------------------------
# Credential files (hardened - never put a secret on argv)
# ----------------------------------------------------------------------------

# Double-quote a value for a MySQL option file, escaping backslash and quote.
sub cnf_quote
{
my ($v) = @_;
$v = '' if (!defined($v));
$v =~ s/([\\"])/\\$1/g;
return '"'.$v.'"';
}

# mysql_defaults_file(\%p) -> ($path, $err). 0600 file with a [client] section.
sub mysql_defaults_file
{
my ($p) = @_;
my $f = &transname();
open(my $fh, ">", $f) || return (undef, "Could not create credentials file");
chmod(0600, $f);
print $fh "[client]\n";
print $fh "user=".&cnf_quote($p->{'user'})."\n"     if (defined($p->{'user'}) && $p->{'user'} ne '');
print $fh "password=".&cnf_quote($p->{'password'})."\n" if (defined($p->{'password'}) && $p->{'password'} ne '');
print $fh "host=".&cnf_quote($p->{'host'})."\n"     if (defined($p->{'host'}) && $p->{'host'} ne '');
print $fh "port=".$p->{'port'}."\n"                 if (defined($p->{'port'}) && $p->{'port'} ne '');
print $fh "socket=".&cnf_quote($p->{'socket'})."\n" if (defined($p->{'socket'}) && $p->{'socket'} ne '');
close($fh);
return ($f, undef);
}

# mongo_config_file(\%p) -> ($path, $err). 0600 file with the password only.
sub mongo_config_file
{
my ($p) = @_;
my $f = &transname();
open(my $fh, ">", $f) || return (undef, "Could not create credentials file");
chmod(0600, $f);
print $fh "password: ".$p->{'password'}."\n";
close($fh);
return ($f, undef);
}

# ----------------------------------------------------------------------------
# Database enumeration
# ----------------------------------------------------------------------------

# excluded_dbs() -> hashref of system databases to skip (from module config).
sub excluded_dbs
{
my %ex;
foreach my $d (split(/\s+/, $config{'exclude_dbs'} || '')) {
	$ex{lc($d)} = 1 if ($d ne '');
	}
return \%ex;
}

# list_databases(\%p) -> ($failed, \@names). For SQLite, the configured files.
sub list_databases
{
my ($p) = @_;
my $eng = $p->{'type'};
my $src = $p->{'source'} || 'host';

if ($eng eq 'sqlite') {
	my @paths = grep { $_ ne '' } split(/\t/, $p->{'sqlite_paths'} || '');
	return (0, \@paths);
	}

if ($eng eq 'mysql' || $eng eq 'mariadb') {
	my $ex = &excluded_dbs();
	my $out;
	if ($src eq 'docker') {
		my $inner = 'IFS= read -r DBP; export MYSQL_PWD="$DBP"; '.
			'if command -v mariadb >/dev/null 2>&1; then C=mariadb; else C=mysql; fi; '.
			'exec "$C"'.&mysql_argv($p, 1).' --batch --skip-column-names -e '.&sq('SHOW DATABASES');
		my ($f, $o, $e) = &run_cmd(&docker_exec_prefix($p).' '.&sq($inner),
			\($p->{'password'}."\n"), 1);
		return (1, $e || $o) if ($f);
		$out = $o;
		}
	else {
		my $client = &engine_tool($eng, 'client') || return (1, "No MySQL/MariaDB client found on host");
		my ($df, $de) = &mysql_defaults_file($p);
		return (1, $de) if (!$df);
		my ($f, $o, $e) = &run_cmd(
			&sq($client).' --defaults-extra-file='.&sq($df).
			' --batch --skip-column-names -e '.&sq('SHOW DATABASES'), undef, 1);
		unlink($df);
		return (1, $e || $o) if ($f);
		$out = $o;
		}
	my @names = grep { /\S/ && !$ex->{lc($_)} && &is_valid_dbname($_) }
			map { my $x=$_; $x=~s/\s+$//; $x } split(/\r?\n/, $out);
	return (0, \@names);
	}

if ($eng eq 'postgres') {
	my $sql = "SELECT datname FROM pg_database WHERE datistemplate=false AND datallowconn=true";
	my $out;
	if ($src eq 'docker') {
		my $inner = 'IFS= read -r DBP; export PGPASSWORD="$DBP"; '.
			'exec psql'.&pg_argv($p).' --no-align --tuples-only --dbname postgres -c '.&sq($sql);
		my ($f, $o, $e) = &run_cmd(&docker_exec_prefix($p, 'postgres').' '.&sq($inner),
			\($p->{'password'}."\n"), 1);
		return (1, $e || $o) if ($f);
		$out = $o;
		}
	else {
		my $client = &engine_tool('postgres', 'client') || return (1, "No psql client found on host");
		my ($f, $o, $e) = &run_cmd(
			&sq($client).&pg_argv($p).' --no-align --tuples-only --dbname postgres -c '.&sq($sql),
			undef, 1, { 'PGPASSWORD' => $p->{'password'}, 'PGCONNECT_TIMEOUT' => 10 });
		return (1, $e || $o) if ($f);
		$out = $o;
		}
	my @names = grep { /\S/ && &is_valid_dbname($_) }
			map { my $x=$_; $x=~s/\s+$//; $x } split(/\r?\n/, $out);
	return (0, \@names);
	}

if ($eng eq 'mongodb') {
	# A single instance-wide archive is the natural unit for MongoDB.
	return (0, [ '_all' ]);
	}

return (1, "Unsupported database type: $eng");
}

# ----------------------------------------------------------------------------
# Argument fragments (identifiers only - never secrets)
# ----------------------------------------------------------------------------

# mysql_argv(\%p, $is_docker) - host/port/user flags for a docker mysql client
# (host source uses the defaults file instead).
sub mysql_argv
{
my ($p, $docker) = @_;
my $a = '';
$a .= ' --user='.&sq($p->{'user'}) if ($docker && defined($p->{'user'}) && $p->{'user'} ne '');
$a .= ' --host='.&sq($p->{'host'}) if (defined($p->{'host'}) && $p->{'host'} ne '');
$a .= ' --port='.&sq($p->{'port'}) if (defined($p->{'port'}) && $p->{'port'} ne '');
return $a;
}

sub pg_argv
{
my ($p) = @_;
my $a = '';
$a .= ' --host='.&sq($p->{'host'}) if (defined($p->{'host'}) && $p->{'host'} ne '');
$a .= ' --port='.&sq($p->{'port'}) if (defined($p->{'port'}) && $p->{'port'} ne '');
$a .= ' --username='.&sq($p->{'user'}) if (defined($p->{'user'}) && $p->{'user'} ne '');
return $a;
}

sub mongo_argv
{
my ($p) = @_;
my $a = '';
$a .= ' --host '.&sq($p->{'host'}) if (defined($p->{'host'}) && $p->{'host'} ne '');
$a .= ' --port '.&sq($p->{'port'}) if (defined($p->{'port'}) && $p->{'port'} ne '');
if (defined($p->{'user'}) && $p->{'user'} ne '') {
	$a .= ' --username '.&sq($p->{'user'});
	$a .= ' --authenticationDatabase '.&sq($p->{'auth_db'} || 'admin');
	}
return $a;
}

# docker_exec_prefix(\%p) - "docker exec -i <container> sh -c" prefix. The caller
# appends the &sq()'d inner script.
sub docker_exec_prefix
{
my ($p) = @_;
return &docker_bin().&context_flag().' exec -i '.&sq($p->{'container'}).' /bin/sh -c';
}

# ----------------------------------------------------------------------------
# Dumping a single database to a raw (uncompressed) temp file
# ----------------------------------------------------------------------------

# dump_one(\%p, $db, $rawfile) -> ($failed, $errtext)
sub dump_one
{
my ($p, $db, $raw) = @_;
my $eng = $p->{'type'};
my $src = $p->{'source'} || 'host';

# ---- MySQL / MariaDB ----
if ($eng eq 'mysql' || $eng eq 'mariadb') {
	&is_valid_dbname($db) || return (1, "Invalid database name");
	my $flags = ' --skip-dump-date';
	$flags .= ' --single-transaction --quick' if ($config{'single_transaction'});
	$flags .= ' --routines --triggers --events' if ($config{'include_routines'});
	$flags .= ' --databases '.&sq($db);
	if ($src eq 'docker') {
		my $inner = 'IFS= read -r DBP; export MYSQL_PWD="$DBP"; '.
			'if command -v mariadb-dump >/dev/null 2>&1; then D=mariadb-dump; else D=mysqldump; fi; '.
			'exec "$D"'.&mysql_argv($p, 1).$flags;
		my ($f, $o, $e) = &run_cmd(
			&docker_exec_prefix($p).' '.&sq($inner).' > '.&sq($raw),
			\($p->{'password'}."\n"), 0);
		return ($f, $e || $o);
		}
	else {
		my $dump = &engine_tool($eng, 'dump') || return (1, "mysqldump not found on host");
		my ($df, $de) = &mysql_defaults_file($p);
		return (1, $de) if (!$df);
		my ($f, $o, $e) = &run_cmd(
			&sq($dump).' --defaults-extra-file='.&sq($df).$flags.' > '.&sq($raw), undef, 0);
		unlink($df);
		return ($f, $e || $o);
		}
	}

# ---- PostgreSQL ----
if ($eng eq 'postgres') {
	&is_valid_dbname($db) || return (1, "Invalid database name");
	my $flags = ' --no-owner --no-privileges --format=plain --dbname='.&sq($db);
	if ($src eq 'docker') {
		my $inner = 'IFS= read -r DBP; export PGPASSWORD="$DBP"; '.
			'exec pg_dump'.&pg_argv($p).$flags;
		my ($f, $o, $e) = &run_cmd(
			&docker_exec_prefix($p).' '.&sq($inner).' > '.&sq($raw),
			\($p->{'password'}."\n"), 0);
		return ($f, $e || $o);
		}
	else {
		my $dump = &engine_tool('postgres', 'dump') || return (1, "pg_dump not found on host");
		my ($f, $o, $e) = &run_cmd(
			&sq($dump).&pg_argv($p).$flags.' > '.&sq($raw), undef, 0,
			{ 'PGPASSWORD' => $p->{'password'}, 'PGCONNECT_TIMEOUT' => 10 });
		return ($f, $e || $o);
		}
	}

# ---- MongoDB (whole instance, or a single db) ----
if ($eng eq 'mongodb') {
	my $dbflag = ($db && $db ne '_all') ? ' --db '.&sq($db) : '';
	&is_valid_dbname($db) || return (1, "Invalid database name") if ($db && $db ne '_all');
	my $authed = (defined($p->{'user'}) && $p->{'user'} ne '') ? 1 : 0;
	if ($src eq 'docker') {
		my ($inner, $stdin);
		if ($authed) {
			# Stream the password as a YAML config to a 0600 temp file inside
			# the container; mongodump reads it via --config (never on argv).
			$inner = 'umask 077; CF=$(mktemp); cat > "$CF"; '.
				'mongodump'.&mongo_argv($p).' --config "$CF"'.$dbflag.' --archive; '.
				'R=$?; rm -f "$CF"; exit $R';
			$stdin = \("password: ".$p->{'password'}."\n");
			}
		else {
			$inner = 'exec mongodump'.&mongo_argv($p).$dbflag.' --archive';
			$stdin = undef;
			}
		my ($f, $o, $e) = &run_cmd(
			&docker_exec_prefix($p).' '.&sq($inner).' > '.&sq($raw), $stdin, 0);
		return ($f, $e || $o);
		}
	else {
		my $dump = &engine_tool('mongodb', 'dump') || return (1, "mongodump not found on host");
		my $cfgflag = '';
		my $cf;
		if ($authed) {
			my $ce;
			($cf, $ce) = &mongo_config_file($p);
			return (1, $ce) if (!$cf);
			$cfgflag = ' --config '.&sq($cf);
			}
		my ($f, $o, $e) = &run_cmd(
			&sq($dump).&mongo_argv($p).$cfgflag.$dbflag.' --archive > '.&sq($raw), undef, 0);
		unlink($cf) if ($cf);
		return ($f, $e || $o);
		}
	}

# ---- SQLite (host file; "db" is the file path) ----
if ($eng eq 'sqlite') {
	&valid_abs_path($db) || return (1, "Invalid SQLite path");
	# Only back up files the profile actually declares (defends against a
	# crafted db_<id> selection asking for an arbitrary host file).
	my %ok = map { $_ => 1 } grep { $_ ne '' } split(/\t/, $p->{'sqlite_paths'} || '');
	return (1, "SQLite path not configured for this profile") if (%ok && !$ok{$db});
	return (1, "SQLite file not found: $db") if (!-r $db);
	my $sqlite = &has_command('sqlite3') || return (1, "sqlite3 not found on host");
	# An online ".backup" produces a consistent copy even while the DB is in use.
	my ($f, $o, $e) = &run_cmd(
		&sq($sqlite).' '.&sq($db).' '.&sq(".backup '".$raw."'"), undef, 0);
	# Older sqlite3 may not accept the quoted form; fall back to .dump (SQL text).
	if ($f) {
		($f, $o, $e) = &run_cmd(
			&sq($sqlite).' '.&sq($db).' '.&sq(".dump").' > '.&sq($raw), undef, 0);
		}
	return ($f, $e || $o);
	}

return (1, "Unsupported database type: $eng");
}

# sqlite_label(PATH) - a distinguishing label for a SQLite file derived from its
# location, so files that share a name (e.g. every site's "database.sqlite") do
# not collide. Picks the hosting account / domain out of common layouts.
sub sqlite_label
{
my ($path) = @_;
$path = '' if (!defined($path));
my $label = '';
if    ($path =~ m!/home/[^/]+/domains/([^/]+)/!) { $label = $1; }       # Virtualmin sub-domain
elsif ($path =~ m!/home/([^/]+)/!)               { $label = $1; }       # cPanel/Virtualmin account
elsif ($path =~ m!/var/www/(?:vhosts/)?([^/]+)/!){ $label = $1; }       # /var/www[/vhosts]/<site>
elsif ($path =~ m!/srv/(?:www|http)/([^/]+)/!)   { $label = $1; }
elsif ($path =~ m!/([A-Za-z0-9_-]+\.[A-Za-z]{2,})/[^/]*$!) { $label = $1; }  # a domain-looking dir
my $base = $path; $base =~ s!.*/!!; $base =~ s!\.[^.]+$!!;              # filename, no extension
$base = 'sqlite' if ($base eq '');
return &safe_filename($label ne '' && $label ne $base ? $label."_".$base : $base);
}

# default output base name (before compression / encryption suffixes).
sub dump_basename
{
my ($p, $db) = @_;
my $eng = $p->{'type'};
if ($eng eq 'mongodb') {
	return &safe_filename(($db && $db ne '_all') ? $db : ($p->{'id'}.'_all')).'.archive';
	}
if ($eng eq 'sqlite') {
	return &sqlite_label($db).'.sqlite';
	}
return &safe_filename($db).'.sql';
}

# unique_basename(BASE, \%used) - ensure an output filename is unique within a
# backup set; appends _2, _3 ... before the extension on collision.
sub unique_basename
{
my ($base, $used) = @_;
if (!$used->{$base}) { $used->{$base} = 1; return $base; }
my ($stem, $ext) = $base =~ /^(.*)(\.[^.]+)$/ ? ($1, $2) : ($base, '');
my $n = 1; my $cand;
do { $n++; $cand = $stem."_".$n.$ext; } while ($used->{$cand});
$used->{$cand} = 1;
return $cand;
}

# ----------------------------------------------------------------------------
# Compression, encryption, checksums
# ----------------------------------------------------------------------------

# compress_raw($raw, $destbase, $setdir, $comp, $level) -> ($failed, $path, $err)
sub compress_raw
{
my ($raw, $base, $setdir, $comp, $level) = @_;
$comp ||= 'none';
my %ext = ('gzip' => '.gz', 'zstd' => '.zst', 'xz' => '.xz', 'none' => '');
my $out = "$setdir/$base".($ext{$comp} || '');
if ($comp eq 'none') {
	if (!move($raw, $out)) { my $e = $!; unlink($raw); return (1, undef, "Could not move dump into place: $e"); }
	chmod(0600, $out);
	return (0, $out, undef);
	}
my %bin = ('gzip' => 'gzip', 'zstd' => 'zstd', 'xz' => 'xz');
my $tool = &has_command($bin{$comp});
if (!$tool) { unlink($raw); return (1, undef, "$bin{$comp} is not installed on the host"); }
my $lvl = (defined($level) && $level =~ /^\d+$/) ? " -".int($level) : '';
my $q = ($comp eq 'zstd') ? ' -q' : '';
my ($f, $o, $e) = &run_cmd(
	&sq($tool).$lvl.$q.' -c '.&sq($raw).' > '.&sq($out), undef, 0);
unlink($raw);
return (1, undef, $e || $o) if ($f);
chmod(0600, $out);
return (0, $out, undef);
}

# encrypt_file($path, $passphrase) -> ($failed, $newpath, $err). GnuPG symmetric.
sub encrypt_file
{
my ($path, $pass) = @_;
return (1, undef, "Encryption passphrase is empty") if (!defined($pass) || $pass eq '');
return (1, undef, "GnuPG passphrase may not contain newlines") if (!&valid_secret($pass));
my $gpg = &has_command('gpg') || &has_command('gpg2');
return (1, undef, "GnuPG (gpg) is not installed on the host") if (!$gpg);
my $out = $path.'.gpg';
# Passphrase is supplied on STDIN via --passphrase-fd 0; never on argv.
my ($f, $o, $e) = &run_cmd(
	&sq($gpg).' --batch --yes --pinentry-mode loopback --passphrase-fd 0'.
	' --cipher-algo AES256 --symmetric --output '.&sq($out).' '.&sq($path),
	\($pass."\n"), 0);
return (1, undef, $e || $o) if ($f);
unlink($path);
chmod(0600, $out);
return (0, $out, undef);
}

# sha256_of($path) -> hex digest or undef. Uses core Digest::SHA (no shell).
sub sha256_of
{
my ($path) = @_;
my $ok = eval { require Digest::SHA; 1; };
return undef if (!$ok);
my $sha = Digest::SHA->new(256);
eval { $sha->addfile($path); };
return $@ ? undef : $sha->hexdigest;
}

# ----------------------------------------------------------------------------
# Free space
# ----------------------------------------------------------------------------

# free_space_mb(DIR) -> integer MB available on the filesystem holding DIR, or undef.
sub free_space_mb
{
my ($dir) = @_;
my $probe = $dir;
$probe = "/" if (!-e $probe);
my ($f, $out) = &run_cmd("df -Pk ".&sq($probe), undef, 1);
return undef if ($f);
my @lines = split(/\r?\n/, $out);
return undef if (@lines < 2);
my @c = split(/\s+/, $lines[1]);
return undef if (@c < 4 || $c[3] !~ /^\d+$/);
return int($c[3] / 1024);
}

# fmt_bytes(N) -> "1.2 MB" style.
sub fmt_bytes
{
my ($n) = @_;
return '' if (!defined($n));
my @u = ('B', 'KB', 'MB', 'GB', 'TB');
my $i = 0;
while ($n >= 1024 && $i < $#u) { $n /= 1024; $i++; }
return sprintf($i ? "%.1f %s" : "%d %s", $n, $u[$i]);
}

# ----------------------------------------------------------------------------
# Backup sets & retention
# ----------------------------------------------------------------------------

our $STAMP_RE = qr/^\d{4}-\d\d-\d\d_\d{6}(?:_[A-Za-z0-9_.\-]{1,64})?$/;

sub now_stamp { return strftime("%Y-%m-%d_%H%M%S", localtime()); }

# list_backup_sets(DIR) -> @ of { name, path, mtime, bytes, files }.
sub list_backup_sets
{
my ($dir) = @_;
return () if (!$dir || !-d $dir);
opendir(my $dh, $dir) || return ();
my @names = grep { $_ =~ $STAMP_RE && !-l "$dir/$_" && -d "$dir/$_" } readdir($dh);
closedir($dh);
my @sets;
foreach my $n (@names) {
	my $path = "$dir/$n";
	my ($bytes, $files) = (0, 0);
	if (opendir(my $sd, $path)) {
		foreach my $fn (readdir($sd)) {
			next if ($fn eq '.' || $fn eq '..');
			my $fp = "$path/$fn";
			next if (!-f $fp);
			$bytes += (-s $fp) || 0;
			$files++ if ($fn !~ /^(manifest\.json|SHA256SUMS|backup\.log)$/);
			}
		closedir($sd);
		}
	push(@sets, { 'name' => $n, 'path' => $path,
		'mtime' => (stat($path))[9], 'bytes' => $bytes, 'files' => $files });
	}
return sort { $b->{'name'} cmp $a->{'name'} } @sets;   # newest first
}

# safe_delete_set(DIR, NAME) -> ($failed, $err). Refuses anything that is not a
# direct, stamp-named child directory of DIR.
sub safe_delete_set
{
my ($dir, $name) = @_;
return (1, "Invalid backup directory") if (!&valid_abs_path($dir));
return (1, "Invalid backup set name") if ($name !~ $STAMP_RE);
my $path = "$dir/$name";
# Never follow a symlink into a deletion (-l uses lstat). A timestamp-named
# symlink would otherwise let unlink_file recurse into the link's target.
return (1, "Refusing to delete a symlinked backup set") if (-l $path);
return (1, "Backup set not found") if (!-d $path);
# Defence in depth: the resolved path must still live directly under $dir.
return (1, "Refusing to delete outside the backup directory")
	if (index($path, "$dir/") != 0 || $path =~ m!\.\.!);
&unlink_file($path);     # Webmin's recursive delete
return (-e $path) ? (1, "Could not remove $path") : (0, undef);
}

# apply_retention(DIR, COUNT, DAYS) -> (\@deleted, \@errors).
sub apply_retention
{
my ($dir, $count, $days) = @_;
my @deleted; my @errors;
my @sets = &list_backup_sets($dir);     # newest first
my %doomed;
if (defined($count) && $count =~ /^\d+$/ && $count > 0 && @sets > $count) {
	$doomed{$_->{'name'}} = 1 foreach (@sets[$count .. $#sets]);
	}
if (defined($days) && $days =~ /^\d+$/ && $days > 0) {
	my $cutoff = time() - $days * 86400;
	foreach my $s (@sets) { $doomed{$s->{'name'}} = 1 if ($s->{'mtime'} && $s->{'mtime'} < $cutoff); }
	}
foreach my $name (sort keys %doomed) {
	my ($f, $e) = &safe_delete_set($dir, $name);
	if ($f) { push(@errors, "$name: $e"); } else { push(@deleted, $name); }
	}
return (\@deleted, \@errors);
}

# ----------------------------------------------------------------------------
# rclone / cloud remotes
# ----------------------------------------------------------------------------

sub rclone_bin { return scalar(&has_command('rclone')); }
sub rclone_installed { return &rclone_bin() ? 1 : 0; }

# read_rclone_conf([PATH]) -> ordered list of { name, \%kv } sections from an
# rclone config file (defaults to this module's own config).
sub read_rclone_conf
{
my ($path) = @_;
$path = $rclone_config if (!defined($path));
my @sections;
return @sections if (!-r $path);
open(my $fh, "<", $path) || return @sections;
my $cur;
while (my $line = <$fh>) {
	$line =~ s/\r?\n$//;
	if ($line =~ /^\s*\[([^\]]+)\]\s*$/) {
		$cur = { 'name' => $1, 'kv' => {} };
		push(@sections, $cur);
		}
	elsif ($cur && $line =~ /^\s*([^=#;][^=]*?)\s*=\s*(.*)$/) {
		$cur->{'kv'}{$1} = $2;
		}
	}
close($fh);
return @sections;
}

# list_remotes() -> @ of { name, type }.
sub list_remotes
{
my @r;
foreach my $s (&read_rclone_conf()) {
	push(@r, { 'name' => $s->{'name'}, 'type' => $s->{'kv'}{'type'} || '' });
	}
return @r;
}

# system_rclone_config() -> path of rclone's OWN default config (root's
# ~/.config/rclone/rclone.conf etc.), distinct from this module's config, or undef.
sub system_rclone_config
{
my $bin = &rclone_bin();
if ($bin) {
	# Ask rclone directly (WITHOUT our --config) where its default config lives.
	my ($f, $out) = &run_cmd(&sq($bin)." config file", undef, 1);
	if (!$f && $out =~ m!(/\S+\.conf)!) {
		my $p = $1;
		return $p if (-r $p && $p ne $rclone_config);
		}
	}
foreach my $p ("$ENV{'HOME'}/.config/rclone/rclone.conf",
	       "/root/.config/rclone/rclone.conf",
	       "$ENV{'HOME'}/.rclone.conf", "/root/.rclone.conf") {
	return $p if ($p && -r $p && $p ne $rclone_config);
	}
return undef;
}

# system_remotes() -> @ of { name, type } found in the system rclone config.
sub system_remotes
{
my $path = &system_rclone_config();
return () if (!$path);
my @r;
foreach my $s (&read_rclone_conf($path)) {
	push(@r, { 'name' => $s->{'name'}, 'type' => $s->{'kv'}{'type'} || '' });
	}
return @r;
}

# import_system_remote(NAME) - copy a remote's definition from the system rclone
# config into this module's own config. Returns ($failed, $err).
sub import_system_remote
{
my ($name) = @_;
&is_valid_id($name) || return (1, "Remote name has characters this module cannot import - copy it in via Advanced paste");
my $path = &system_rclone_config();
return (1, "No system rclone configuration was found") if (!$path);
my ($sec) = grep { $_->{'name'} eq $name } &read_rclone_conf($path);
return (1, "Remote not found in the system rclone configuration") if (!$sec);
return &save_remote($name, $sec->{'kv'});
}

sub get_remote
{
my ($name) = @_;
foreach my $s (&read_rclone_conf()) { return $s if ($s->{'name'} eq $name); }
return undef;
}

# write_rclone_conf(\@sections) - rewrite the 0600 config from a section list.
sub write_rclone_conf
{
my ($sections) = @_;
&ensure_dir($module_config_directory);
open(my $fh, ">", $rclone_config) || return (1, "Could not write rclone config");
chmod(0600, $rclone_config);
foreach my $s (@$sections) {
	print $fh "[".$s->{'name'}."]\n";
	foreach my $k (sort keys %{$s->{'kv'}}) {
		print $fh $k." = ".$s->{'kv'}{$k}."\n";
		}
	print $fh "\n";
	}
close($fh);
return (0, undef);
}

# save_remote(NAME, \%kv) - add or replace a remote section. We build the INI
# ourselves so access keys / tokens are NEVER passed to rclone on argv.
sub save_remote
{
my ($name, $kv) = @_;
&is_valid_id($name) || return (1, "Invalid remote name");
foreach my $v (values %$kv) {
	return (1, "Config values may not contain newlines") if (defined($v) && $v =~ /[\r\n]/);
	}
my @sections = grep { $_->{'name'} ne $name } &read_rclone_conf();
push(@sections, { 'name' => $name, 'kv' => $kv });
return &write_rclone_conf(\@sections);
}

sub delete_remote
{
my ($name) = @_;
&is_valid_id($name) || return (1, "Invalid remote name");
my @sections = grep { $_->{'name'} ne $name } &read_rclone_conf();
return &write_rclone_conf(\@sections);
}

# rclone_run(ARGSTRING, [SAFE]) -> ($failed, $output). Always uses our config.
sub rclone_run
{
my ($args, $safe) = @_;
my $bin = &rclone_bin() || return (1, "rclone is not installed on the host");
my ($f, $o, $e) = &run_cmd(
	&sq($bin).' --config '.&sq($rclone_config).' '.$args, undef, $safe);
return ($f, ($o || '').($e || ''));
}

sub test_remote
{
my ($name) = @_;
&is_valid_id($name) || return (1, "Invalid remote name");
return &rclone_run('lsd '.&sq($name.':'), 1);
}

# rclone_upload(SETDIR, STAMP, NAME, BASE, MODE) -> ($failed, $output).
sub rclone_upload
{
my ($setdir, $stamp, $name, $base, $mode) = @_;
&is_valid_id($name) || return (1, "Invalid remote name");
&valid_remote_path($base) || return (1, "Invalid remote base path");
return (1, "Invalid local set directory") if (!-d $setdir);
$mode = ($mode && $mode eq 'sync') ? 'sync' : 'copy';
my $dest = $name.':'.($base ne '' ? $base.'/' : '').$stamp;
if ($mode eq 'sync') {
	# Mirror the whole local backup tree (honours local retention on the remote).
	my $parent = $setdir; $parent =~ s!/[^/]+/?$!!;
	my $rbase = $name.':'.($base ne '' ? $base : '');
	return &rclone_run('sync '.&sq($parent).' '.&sq($rbase).' --stats-one-line', 0);
	}
return &rclone_run('copy '.&sq($setdir).' '.&sq($dest).' --stats-one-line', 0);
}

# ----------------------------------------------------------------------------
# The backup engine
# ----------------------------------------------------------------------------

# run_backup(\%job) -> ($failed, \%result)
#   job keys:
#     targets       => [ { profile => id, databases => ['all'] | [names...] } ]
#     dir           => destination directory (default: $config{backup_dir})
#     label         => optional suffix for the set directory name
#     compression   => gzip|zstd|xz|none      level => int
#     encrypt       => 0/1                     passphrase => string
#     checksum      => 0/1
#     remotes       => [ names ]   remote_mode => copy|sync   remote_base => path
#     retain_count  => int         retain_days => int
#     free_space_mb => int
#   result: { ok, stamp, setdir, items=>[...], deleted=>[...], uploads=>[...], log=>text }
sub run_backup
{
my ($job) = @_;
my @log;
my $say = sub { push(@log, strftime("%H:%M:%S", localtime())." ".$_[0]); };

my $dir = $job->{'dir'} || $config{'backup_dir'};
&valid_abs_path($dir) || return (1, { 'log' => "Invalid backup directory: ".($dir||'') });
&ensure_dir($dir, 0700);

# Free-space guard.
my $need = defined($job->{'free_space_mb'}) ? $job->{'free_space_mb'} : $config{'free_space_mb'};
if ($need && $need =~ /^\d+$/) {
	my $have = &free_space_mb($dir);
	if (defined($have) && $have < $need) {
		return (1, { 'log' => "Aborting: only ${have}MB free in $dir (need ${need}MB)" });
		}
	}

my $stamp = &now_stamp();
$stamp .= "_".&safe_filename($job->{'label'}) if (defined($job->{'label'}) && $job->{'label'} ne '');
my $setdir = "$dir/$stamp";
&make_dir($setdir, 0700);
chmod(0700, $setdir);
$say->("Backup set: $setdir");

my $comp  = $job->{'compression'} || $config{'compression'} || 'gzip';
my $level = defined($job->{'level'}) ? $job->{'level'} : $config{'compress_level'};
my $sums  = (defined($job->{'checksum'}) ? $job->{'checksum'} : $config{'checksum'}) ? 1 : 0;
my $enc   = $job->{'encrypt'} ? 1 : 0;

my @items; my $failures = 0; my %used_names;
foreach my $t (@{$job->{'targets'} || []}) {
	my $p = &get_profile($t->{'profile'});
	if (!$p) { $say->("Skipping unknown profile: ".($t->{'profile'}||'?')); $failures++; next; }
	my $plabel = &profile_label($p);

	my @dbs;
	if (ref($t->{'databases'}) eq 'ARRAY' && @{$t->{'databases'}} &&
	    !(@{$t->{'databases'}} == 1 && $t->{'databases'}[0] eq 'all')) {
		@dbs = @{$t->{'databases'}};
		}
	else {
		my ($lf, $list) = &list_databases($p);
		if ($lf) { $say->("[$plabel] could not list databases: $list"); $failures++; next; }
		@dbs = @$list;
		}
	if (!@dbs) { $say->("[$plabel] no databases to back up"); next; }

	foreach my $db (@dbs) {
		my $shown = ($p->{'type'} eq 'sqlite') ? $db : ($db eq '_all' ? 'all databases' : $db);
		my $raw = &transname();
		my ($df, $de) = &dump_one($p, $db, $raw);
		if ($df) {
			$say->("[$plabel] FAILED dumping $shown: ".&trim_err($de));
			unlink($raw); $failures++;
			push(@items, { profile => $p->{'id'}, db => $db, ok => 0, error => &trim_err($de) });
			next;
			}
		if (!-s $raw) {
			$say->("[$plabel] FAILED dumping $shown: empty dump");
			unlink($raw); $failures++;
			push(@items, { profile => $p->{'id'}, db => $db, ok => 0, error => "empty dump" });
			next;
			}
		my $base = &unique_basename(&dump_basename($p, $db), \%used_names);
		my ($cf, $path, $ce) = &compress_raw($raw, $base, $setdir, $comp, $level);
		if ($cf) { $say->("[$plabel] compression failed for $shown: ".&trim_err($ce)); $failures++;
			push(@items, { profile => $p->{'id'}, db => $db, ok => 0, error => &trim_err($ce) }); next; }
		if ($enc) {
			my ($ef, $epath, $ee) = &encrypt_file($path, $job->{'passphrase'});
			if ($ef) { unlink($path); $say->("[$plabel] encryption failed for $shown: ".&trim_err($ee)); $failures++;
				push(@items, { profile => $p->{'id'}, db => $db, ok => 0, error => &trim_err($ee) }); next; }
			$path = $epath;
			}
		my $bytes = (-s $path) || 0;
		my $sha = $sums ? &sha256_of($path) : undef;
		$say->("[$plabel] $shown -> ".&relname($path, $setdir)." (".&fmt_bytes($bytes).")");
		push(@items, { profile => $p->{'id'}, engine => $p->{'type'}, db => $db,
			file => &relname($path, $setdir), bytes => $bytes, sha256 => $sha, ok => 1 });
		}
	}

# Write SHA256SUMS + manifest.
if ($sums) {
	open(my $sfh, ">", "$setdir/SHA256SUMS");
	foreach my $it (@items) { next if (!$it->{'ok'} || !$it->{'sha256'});
		print $sfh $it->{'sha256'}."  ".$it->{'file'}."\n"; }
	close($sfh); chmod(0600, "$setdir/SHA256SUMS");
	}
&write_manifest($setdir, $stamp, \@items, $job);

# Cloud upload.
my @uploads;
my @remotes = @{$job->{'remotes'} || []};
@remotes = ($config{'default_remote'}) if (!@remotes && $config{'default_remote'});
foreach my $rname (@remotes) {
	next if (!defined($rname) || $rname eq '');
	$say->("Uploading to remote '$rname'...");
	my ($uf, $uo) = &rclone_upload($setdir, $stamp, $rname,
		(defined($job->{'remote_base'}) ? $job->{'remote_base'} : $config{'remote_base'}),
		$job->{'remote_mode'} || $config{'remote_mode'});
	if ($uf) { $say->("Upload to '$rname' FAILED: ".&trim_err($uo)); $failures++; }
	else { $say->("Upload to '$rname' complete"); }
	push(@uploads, { remote => $rname, ok => $uf ? 0 : 1, output => &trim_err($uo) });
	}

# Retention.
my $rc = defined($job->{'retain_count'}) ? $job->{'retain_count'} : $config{'retain_count'};
my $rd = defined($job->{'retain_days'})  ? $job->{'retain_days'}  : $config{'retain_days'};
my ($deleted, $rerr) = &apply_retention($dir, $rc, $rd);
$say->("Retention removed ".scalar(@$deleted)." old set(s)") if (@$deleted);
$say->("Retention error: $_") foreach (@$rerr);
$failures++ if (@$rerr);

my $ok = ($failures == 0 && grep { $_->{'ok'} } @items) ? 1 : 0;
$say->($ok ? "Backup completed successfully" :
	($failures ? "Backup completed with $failures error(s)" : "Nothing was backed up"));

my $logtext = join("\n", @log)."\n";
return (($failures ? 1 : 0), {
	'ok' => $ok, 'stamp' => $stamp, 'setdir' => $setdir,
	'items' => \@items, 'deleted' => $deleted, 'uploads' => \@uploads, 'log' => $logtext });
}

# trim_err(TEXT) - collapse a tool's stderr to a short single line for logs.
sub trim_err
{
my ($e) = @_;
$e = '' if (!defined($e));
$e =~ s/\s+/ /g; $e =~ s/^\s+|\s+$//g;
$e = substr($e, 0, 500)."..." if (length($e) > 500);
return $e eq '' ? "(no error output)" : $e;
}

sub relname { my ($p, $d) = @_; (my $r = $p) =~ s!^\Q$d\E/!!; return $r; }

sub write_manifest
{
my ($setdir, $stamp, $items, $job) = @_;
return if (!$have_json);
my %m = (
	'module'      => 'dbbackup',
	'created'     => $stamp,
	'host'        => &get_system_hostname(),
	'compression' => ($job->{'compression'} || $config{'compression'}),
	'encrypted'   => ($job->{'encrypt'} ? JSON::PP::true() : JSON::PP::false()),
	'items'       => $items,
	);
my $f = "$setdir/manifest.json";
open(my $fh, ">", $f) || return;
print $fh JSON::PP->new->pretty->canonical->encode(\%m);
close($fh);
chmod(0600, $f);
}

# ----------------------------------------------------------------------------
# Restore
# ----------------------------------------------------------------------------

# decompress_prefix(PATH) -> a shell fragment that writes the decompressed
# contents of PATH to stdout, or undef when the needed tool is missing.
sub decompress_prefix
{
my ($path) = @_;
if    ($path =~ /\.gz$/)  { my $b=&has_command('gzip'); return $b ? &sq($b).' -dc '.&sq($path) : undef; }
elsif ($path =~ /\.zst$/) { my $b=&has_command('zstd'); return $b ? &sq($b).' -dc '.&sq($path) : undef; }
elsif ($path =~ /\.xz$/)  { my $b=&has_command('xz');   return $b ? &sq($b).' -dc '.&sq($path) : undef; }
return 'cat '.&sq($path);
}

# restore_database(\%p, $target, $file, \%opts) -> ($failed, $message)
# Target semantics differ per engine:
#   mysql/mariadb - $target optional (the dump recreates its original database);
#                   when given it is used as the default connection database.
#   postgres      - $target REQUIRED (an existing database to load the dump into).
#   mongodb       - $target ignored (restored to original namespaces, --drop).
#   sqlite        - $target REQUIRED (the destination .sqlite file path).
sub restore_database
{
my ($p, $target, $file, $opts) = @_;
$opts ||= {};
my $eng = $p->{'type'};
my $src = $p->{'source'} || 'host';
&valid_abs_path($file) || return (1, "Invalid backup file path");
return (1, "Backup file not found") if (!-r $file);

# Decrypt first if needed, into a temp file.
my $work = $file;
my @cleanup;
if ($file =~ /\.gpg$/) {
	my $pass = $opts->{'passphrase'};
	return (1, "This backup is encrypted - a passphrase is required") if (!defined($pass) || $pass eq '');
	my $gpg = &has_command('gpg') || &has_command('gpg2');
	return (1, "GnuPG is not installed") if (!$gpg);
	my $tmp = &transname();
	my ($f, $o, $e) = &run_cmd(
		&sq($gpg).' --batch --yes --pinentry-mode loopback --passphrase-fd 0 -o '.&sq($tmp).' -d '.&sq($file),
		\($pass."\n"), 0);
	if ($f) { unlink(@cleanup); return (1, &trim_err($e || $o)); }
	$work = $tmp; push(@cleanup, $tmp);
	}

my $cat = &decompress_prefix($work);
if (!defined($cat)) { unlink(@cleanup); return (1, "Required decompression tool is not installed"); }

# Stage a single secret line into a 0600 temp file, returned as a path. The
# secret therefore never appears on argv; the in-container reader consumes the
# first line, leaving the rest of the pipe (the dump) for the client.
my $stage = sub {
	my ($line) = @_;
	my $pf = &transname();
	open(my $fh, ">", $pf) || return undef;
	chmod(0600, $pf);
	print $fh $line."\n";
	close($fh);
	push(@cleanup, $pf);
	return $pf;
	};

my ($failed, $errout);

if ($eng eq 'mysql' || $eng eq 'mariadb') {
	my $tgt = (defined($target) && $target ne '') ? $target : '';
	if ($tgt ne '' && !&is_valid_dbname($tgt)) { unlink(@cleanup); return (1, "Invalid target database"); }
	if ($src eq 'docker') {
		my $pf = &$stage($p->{'password'});
		if (!$pf) { unlink(@cleanup); return (1, "Could not stage credentials"); }
		my $inner = 'IFS= read -r DBP; export MYSQL_PWD="$DBP"; '.
			'if command -v mariadb >/dev/null 2>&1; then C=mariadb; else C=mysql; fi; '.
			'exec "$C"'.&mysql_argv($p, 1).($tgt ne '' ? ' '.&sq($tgt) : '');
		my $cmd = '{ cat '.&sq($pf).'; '.$cat.'; } | '.&docker_exec_prefix($p).' '.&sq($inner);
		($failed, my $o, my $e) = &run_cmd($cmd, undef, 0);
		$errout = $e || $o;
		}
	else {
		my $client = &engine_tool($eng, 'client');
		if (!$client) { unlink(@cleanup); return (1, "No MySQL/MariaDB client on host"); }
		my ($df, $de) = &mysql_defaults_file($p);
		if (!$df) { unlink(@cleanup); return (1, $de); }
		my $cmd = $cat.' | '.&sq($client).' --defaults-extra-file='.&sq($df).
			($tgt ne '' ? ' '.&sq($tgt) : '');
		($failed, my $o, my $e) = &run_cmd($cmd, undef, 0);
		unlink($df);
		$errout = $e || $o;
		}
	}
elsif ($eng eq 'postgres') {
	if (!&is_valid_dbname($target)) { unlink(@cleanup); return (1, "A valid target database is required for PostgreSQL restore"); }
	if ($src eq 'docker') {
		my $pf = &$stage($p->{'password'});
		if (!$pf) { unlink(@cleanup); return (1, "Could not stage credentials"); }
		my $inner = 'IFS= read -r DBP; export PGPASSWORD="$DBP"; '.
			'exec psql'.&pg_argv($p).' --set ON_ERROR_STOP=on --dbname '.&sq($target);
		my $cmd = '{ cat '.&sq($pf).'; '.$cat.'; } | '.&docker_exec_prefix($p).' '.&sq($inner);
		($failed, my $o, my $e) = &run_cmd($cmd, undef, 0);
		$errout = $e || $o;
		}
	else {
		my $client = &engine_tool('postgres', 'client');
		if (!$client) { unlink(@cleanup); return (1, "No psql client on host"); }
		my $cmd = $cat.' | '.&sq($client).&pg_argv($p).' --set ON_ERROR_STOP=on --dbname '.&sq($target);
		($failed, my $o, my $e) = &run_cmd($cmd, undef, 0, { 'PGPASSWORD' => $p->{'password'} });
		$errout = $e || $o;
		}
	}
elsif ($eng eq 'mongodb') {
	my $authed = (defined($p->{'user'}) && $p->{'user'} ne '') ? 1 : 0;
	if ($src eq 'docker') {
		my $cmd;
		if ($authed) {
			my $pf = &$stage("password: ".$p->{'password'});
			if (!$pf) { unlink(@cleanup); return (1, "Could not stage credentials"); }
			my $inner = 'umask 077; CF=$(mktemp); IFS= read -r L; printf \'%s\\n\' "$L" > "$CF"; '.
				'mongorestore'.&mongo_argv($p).' --config "$CF" --drop --archive; '.
				'R=$?; rm -f "$CF"; exit $R';
			$cmd = '{ cat '.&sq($pf).'; '.$cat.'; } | '.&docker_exec_prefix($p).' '.&sq($inner);
			}
		else {
			my $inner = 'exec mongorestore'.&mongo_argv($p).' --drop --archive';
			$cmd = $cat.' | '.&docker_exec_prefix($p).' '.&sq($inner);
			}
		($failed, my $o, my $e) = &run_cmd($cmd, undef, 0);
		$errout = $e || $o;
		}
	else {
		my $rest = &has_command('mongorestore');
		if (!$rest) { unlink(@cleanup); return (1, "mongorestore is not installed"); }
		my $cfgflag = ''; my $cf;
		if ($authed) {
			my $ce;
			($cf, $ce) = &mongo_config_file($p);
			if (!$cf) { unlink(@cleanup); return (1, $ce); }
			$cfgflag = ' --config '.&sq($cf);
			}
		my $cmd = $cat.' | '.&sq($rest).&mongo_argv($p).$cfgflag.' --drop --archive';
		($failed, my $o, my $e) = &run_cmd($cmd, undef, 0);
		unlink($cf) if ($cf);
		$errout = $e || $o;
		}
	}
elsif ($eng eq 'sqlite') {
	if (!&valid_abs_path($target)) { unlink(@cleanup); return (1, "A valid target SQLite file path is required"); }
	# A restore must not be a write-anywhere primitive: the target must be one
	# of the paths the profile already declares, and never a symlink.
	my %ok = map { $_ => 1 } grep { $_ ne '' } split(/\t/, $p->{'sqlite_paths'} || '');
	if (!$ok{$target}) { unlink(@cleanup); return (1, "Target must be one of the profile's configured SQLite paths"); }
	if (-l $target) { unlink(@cleanup); return (1, "Refusing to write through a symlink"); }
	my $sqlite = &has_command('sqlite3');
	if (!$sqlite) { unlink(@cleanup); return (1, "sqlite3 is not installed"); }
	# Peek at the first bytes: ".backup" output is a binary DB image, while a
	# ".dump" fallback is SQL text.
	my ($hf, $head) = &run_cmd($cat.' | head -c16', undef, 1);
	if (!$hf && $head =~ /^SQLite format/) {
		# Shell '>' truncates an existing file in place, preserving its mode.
		my ($df, $do, $de) = &run_cmd($cat.' > '.&sq($target), undef, 0);
		$failed = $df; $errout = $de || $do;
		}
	else {
		my $cmd = $cat.' | '.&sq($sqlite).' '.&sq($target);
		($failed, my $oo, my $ee) = &run_cmd($cmd, undef, 0);
		$errout = $ee || $oo;
		}
	}
else {
	unlink(@cleanup);
	return (1, "Unsupported database type: $eng");
	}

unlink(@cleanup);
return ($failed, &trim_err($errout));
}

# ----------------------------------------------------------------------------
# Schedules (stored in $schedules_dir) + cron integration
# ----------------------------------------------------------------------------

sub schedule_file { return "$schedules_dir/".$_[0]; }

sub list_schedules
{
&ensure_dir($schedules_dir);
my @out;
opendir(my $dh, $schedules_dir) || return ();
my @ids = grep { &is_valid_id($_) && -f "$schedules_dir/$_" } readdir($dh);
closedir($dh);
foreach my $id (sort @ids) { my $s = &get_schedule($id); push(@out, $s) if ($s); }
return @out;
}

sub get_schedule
{
my ($id) = @_;
return undef if (!&is_valid_id($id));
my $f = &schedule_file($id);
return undef if (!-r $f);
my %s; &read_file($f, \%s); $s{'id'} = $id;
return \%s;
}

sub save_schedule
{
my ($s) = @_;
&is_valid_id($s->{'id'}) || return (1, "Invalid schedule id");
&ensure_dir($schedules_dir);
my $f = &schedule_file($s->{'id'});
my %store = %$s; delete $store{'id'};
&scrub_record(\%store);
&write_file($f, \%store);
chmod(0600, $f);
return (0, undef);
}

sub delete_schedule
{
my ($id) = @_;
&is_valid_id($id) || return (1, "Invalid schedule id");
&remove_cron($id);
my $f = &schedule_file($id);
unlink($f) if (-e $f);
return (0, undef);
}

# schedule_to_job(\%s) -> a \%job suitable for &run_backup, filling unset
# fields from the module configuration defaults.
sub schedule_to_job
{
my ($s) = @_;
my @targets = map { { 'profile' => $_, 'databases' => [ 'all' ] } }
		grep { $_ ne '' } split(/\t/, $s->{'profiles'} || '');
my $orblank = sub { my ($v, $def) = @_; (defined($v) && $v ne '') ? $v : $def; };
return {
	'targets'      => \@targets,
	'dir'          => $s->{'dir'} || $config{'backup_dir'},
	'label'        => $s->{'id'},
	'compression'  => $s->{'compression'} || $config{'compression'},
	'level'        => &$orblank($s->{'level'}, $config{'compress_level'}),
	'encrypt'      => $s->{'encrypt'} ? 1 : 0,
	'passphrase'   => $s->{'passphrase'},
	'checksum'     => $config{'checksum'},
	'remotes'      => [ grep { $_ ne '' } split(/\t/, $s->{'remotes'} || '') ],
	'remote_mode'  => $s->{'remote_mode'} || $config{'remote_mode'},
	'remote_base'  => $config{'remote_base'},
	'retain_count' => &$orblank($s->{'retain_count'}, $config{'retain_count'}),
	'retain_days'  => &$orblank($s->{'retain_days'}, $config{'retain_days'}),
	};
}

sub cron_available { return &foreign_available("cron") ? 1 : 0; }

sub cron_wrapper
{
&foreign_require("cron");
# create_wrapper() WRITES the wrapper to $path and returns its chmod result, not
# the path - so build the path ourselves and return that (matches Webmin's own
# status-lib.pl idiom). install_cron() and remove_cron() then agree on the exact
# command string.
my $path = "$module_config_directory/dbbackup-cron.pl";
&cron::create_wrapper($path, $module_name, "dbbackup-run.pl");
return $path;
}

# install_cron(ID, \%timing) - (re)create the cron job for a schedule.
# %timing holds mins/hours/days/months/weekdays as Webmin cron fields.
sub install_cron
{
my ($id, $timing) = @_;
return (1, "Cron module is not available") if (!&cron_available());
&is_valid_id($id) || return (1, "Invalid schedule id");
&foreign_require("cron");
&remove_cron($id);
my $wrapper = &cron_wrapper();
my %job = (
	'user'     => 'root',
	'active'   => 1,
	'command'  => $wrapper." ".$id,
	'mins'     => defined($timing->{'mins'})     ? $timing->{'mins'}     : 0,
	'hours'    => defined($timing->{'hours'})    ? $timing->{'hours'}    : 2,
	'days'     => defined($timing->{'days'})     ? $timing->{'days'}     : '*',
	'months'   => defined($timing->{'months'})   ? $timing->{'months'}   : '*',
	'weekdays' => defined($timing->{'weekdays'}) ? $timing->{'weekdays'} : '*',
	);
&cron::create_cron_job(\%job);
return (0, undef);
}

# remove_cron(ID) - delete any cron jobs this module created for the schedule.
sub remove_cron
{
my ($id) = @_;
return if (!&cron_available());
&foreign_require("cron");
my $wrapper = "$module_config_directory/dbbackup-cron.pl";
my @jobs = &cron::list_cron_jobs();
foreach my $j (reverse @jobs) {
	next if (!defined($j->{'command'}));
	if ($j->{'command'} eq "$wrapper $id" ||
	    $j->{'command'} =~ /\Q$wrapper\E\s+\Q$id\E\s*$/) {
		&cron::delete_cron_job($j);
		}
	}
}

# ----------------------------------------------------------------------------
# Job logs
# ----------------------------------------------------------------------------

sub write_job_log
{
my ($tag, $text) = @_;
&ensure_dir($logs_dir);
$tag = &safe_filename($tag || 'backup');
my $f = "$logs_dir/$tag-".&now_stamp().".log";
open(my $fh, ">", $f) || return undef;
chmod(0600, $f);
print $fh $text;
close($fh);
return $f;
}

sub list_job_logs
{
&ensure_dir($logs_dir);
opendir(my $dh, $logs_dir) || return ();
my @f = grep { /\.log$/ && -f "$logs_dir/$_" } readdir($dh);
closedir($dh);
return map { "$logs_dir/$_" } sort { $b cmp $a } @f;
}

# ----------------------------------------------------------------------------
# Shared UI helpers
# ----------------------------------------------------------------------------

# bulk_select_links(FORMID, FIELD) - "select all / invert" links scoped to a
# specific form by id. Both arguments are module constants, so no untrusted data
# reaches the emitted JavaScript.
sub bulk_select_links
{
my ($formid, $field) = @_;
my $loop = "var f=document.getElementById('$formid');if(f){for(var i=0;i<f.elements.length;i++){if(f.elements[i].name=='$field')";
return "<a href='#' onclick=\"".$loop."f.elements[i].checked=true;}}return false;\">".
		($text{'select_all'} || 'Select all')."</a> | ".
	"<a href='#' onclick=\"".$loop."f.elements[i].checked=!f.elements[i].checked;}}return false;\">".
		($text{'select_invert'} || 'Invert selection')."</a>";
}

# ----------------------------------------------------------------------------
# Confirmation secret stash
# ----------------------------------------------------------------------------
# A destructive action (restore) shows a confirmation page before running. So a
# secret (the decryption passphrase) is NEVER reflected into that page's HTML,
# it is written to a short-lived 0600 file under a random token; only the opaque
# token travels through the confirm form. The token is consumed (read + deleted)
# when the action is confirmed.

sub random_token
{
my $t = '';
if (open(my $u, "<", "/dev/urandom")) {
	binmode($u); my $b = ''; read($u, $b, 16); close($u);
	$t = unpack("H*", $b);
	}
$t = sprintf("%08x%08x%08x", time(), $$, int(rand(0xffffffff))) if (length($t) < 16);
return $t;
}

# stash_secret(VALUE) -> token. Also sweeps stale (>1h) stash files.
sub stash_secret
{
my ($val) = @_;
return '' if (!defined($val) || $val eq '');
&ensure_dir($stash_dir, 0700);
if (opendir(my $dh, $stash_dir)) {
	my $cut = time() - 3600;
	foreach my $f (readdir($dh)) {
		next if ($f !~ /^[0-9a-f]{16,64}$/);
		my $m = (stat("$stash_dir/$f"))[9];
		unlink("$stash_dir/$f") if (defined($m) && $m < $cut);
		}
	closedir($dh);
	}
my $token = &random_token();
my $f = "$stash_dir/$token";
open(my $fh, ">", $f) || return '';
chmod(0600, $f);
print $fh $val;
close($fh);
return $token;
}

# unstash_secret(TOKEN) -> value (or undef), deleting the stash file.
sub unstash_secret
{
my ($token) = @_;
return undef if (!defined($token) || $token !~ /^[0-9a-f]{16,64}$/);
my $f = "$stash_dir/$token";
return undef if (!-r $f);
my $val = &read_file_contents($f);
unlink($f);
return $val;
}

# ----------------------------------------------------------------------------
# ACL helpers
# ----------------------------------------------------------------------------

sub can
{
my ($key) = @_;
our %access;
%access = &get_module_acl() if (!%access);
return $access{$key} ? 1 : 0;
}

sub require_acl
{
my ($key) = @_;
&can($key) || &error($text{'err_noperm'} || "You are not permitted to perform this action");
}

1;
