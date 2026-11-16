#!/usr/bin/perl
# schedule.cgi - scheduled (cron) backups. Each schedule stores a job definition
# and a cron entry that runs dbbackup-run.pl through the Webmin cron wrapper.

require './dbbackup-lib.pl';
&ReadParse();

our (%config, %text, %in, %access, %ENGINE_LABEL);
%access = &get_module_acl();
&can('schedule') || &error($text{'err_noperm'});

&ui_print_header(undef, $text{'sched_title'}, "");

print &ui_alert_box(&html_escape($in{'msg'}), 'success') if ($in{'msg'});
print &ui_alert_box(&html_escape($in{'err'}), 'danger') if ($in{'err'});

if (!&cron_available()) {
	print &ui_alert_box($text{'sched_nocron'}, 'danger');
	&ui_print_footer("index.cgi", $text{'index_return'});
	exit;
	}
&foreign_require("cron");

my @profiles = &list_profiles();
my @remotes  = &list_remotes();

# ---- Existing schedules ----------------------------------------------------
print &ui_subheading($text{'sched_existing'});
my @scheds = &list_schedules();
if (!@scheds) {
	print "<p>".$text{'sched_none'}."</p>";
	}
else {
	print &ui_columns_start([ $text{'sched_id'}, $text{'sched_profiles'},
		$text{'sched_when'}, $text{'sched_dest'}, "" ], 100);
	foreach my $s (@scheds) {
		my $when = join(" ", map { defined($s->{$_}) && $s->{$_} ne '' ? $s->{$_} : '*' }
				qw(mins hours days months weekdays));
		my $plist = join(", ", split(/\t/, $s->{'profiles'} || ''));
		my $act =
			&post_link("run_schedule", { 'id' => $s->{'id'} }, $text{'sched_runnow'})." | ".
			&ui_link("schedule.cgi?edit=".&urlize($s->{'id'}), $text{'sched_edit'})." | ".
			&post_link("delete_schedule", { 'id' => $s->{'id'} }, $text{'sched_delete'},
				$text{'sched_confirm_delete'});
		print &ui_columns_row([
			&html_escape($s->{'id'}),
			&html_escape($plist),
			"<tt>".&html_escape($when)."</tt>",
			"<tt>".&html_escape($s->{'dir'} || $config{'backup_dir'})."</tt>",
			$act,
			]);
		}
	print &ui_columns_end();
	}

# ---- Add / edit ------------------------------------------------------------
print &ui_hr();
my $edit = ($in{'edit'} && &get_schedule($in{'edit'})) ? &get_schedule($in{'edit'}) : undef;
my %d = $edit ? %$edit : ();
my %sel_p = map { $_ => 1 } split(/\t/, $d{'profiles'} || '');
my %sel_r = map { $_ => 1 } split(/\t/, $d{'remotes'} || '');
my %job = $edit ? (
	'mins'     => $d{'mins'},     'hours'    => $d{'hours'},
	'days'     => $d{'days'},     'months'   => $d{'months'},
	'weekdays' => $d{'weekdays'},
	) : ( 'mins' => 0, 'hours' => 2, 'days' => '*', 'months' => '*', 'weekdays' => '*' );

print &ui_form_start("act.cgi", "post");
print &ui_hidden("c", "save_schedule");
print &ui_hidden("editing", $edit ? 1 : 0);
print &ui_table_start($edit ? &text('sched_edit_of', &html_escape($edit->{'id'})) : $text{'sched_add'}, undef, 2);

if ($edit) {
	print &ui_table_row($text{'sched_id'}, "<tt>".&html_escape($edit->{'id'})."</tt>".
		&ui_hidden("id", $edit->{'id'}));
	}
else {
	print &ui_table_row($text{'sched_id'}, &ui_textbox("id", "", 30)."<br>".
		"<small>".$text{'prof_id_hint'}."</small>");
	}

# Profiles to include.
if (!@profiles) {
	print &ui_table_row($text{'sched_profiles'}, &ui_link("profiles.cgi", $text{'sched_addprofile'}));
	}
else {
	my $boxes = join("<br>", map {
		&ui_checkbox("p", $_->{'id'}, $_->{'id'}." (".&profile_label($_).")", $sel_p{$_->{'id'}})
		} @profiles);
	print &ui_table_row($text{'sched_profiles'}, $boxes);
	}

print &ui_table_row($text{'opt_dir'},
	&ui_textbox("dir", $d{'dir'} || $config{'backup_dir'}, 50)." ".&file_chooser_button("dir", 1));
print &ui_table_row($text{'sched_layout'},
	&ui_select("layout", $d{'layout'} || 'timestamped',
		[ [ 'timestamped', $text{'sched_layout_timestamped'} ], [ 'daily', $text{'sched_layout_daily'} ] ]).
	"<br><small>".$text{'sched_layout_hint'}."</small>");
print &ui_table_row($text{'opt_compression'},
	&ui_select("compression", $d{'compression'} || $config{'compression'},
		[ [ "gzip", "gzip" ], [ "zstd", "zstd" ], [ "xz", "xz" ], [ "none", $text{'opt_none'} ] ]).
	" &nbsp; ".$text{'opt_level'}." ".
	&ui_textbox("level", defined($d{'level'}) ? $d{'level'} : $config{'compress_level'}, 3));
print &ui_table_row($text{'opt_retain_count'},
	&ui_textbox("retain_count", defined($d{'retain_count'}) ? $d{'retain_count'} : $config{'retain_count'}, 5));
print &ui_table_row($text{'opt_retain_days'},
	&ui_textbox("retain_days", defined($d{'retain_days'}) ? $d{'retain_days'} : $config{'retain_days'}, 5));
print &ui_table_row($text{'opt_encrypt'},
	&ui_yesno_radio("encrypt", $d{'encrypt'} ? 1 : 0)." ".
	$text{'opt_passphrase'}." ".&ui_password("passphrase", "", 25).
	($edit && $d{'passphrase'} ne '' ? "<br><small>".$text{'sched_pass_keep'}."</small>" : ""));

if (@remotes) {
	print &ui_table_row($text{'opt_remote'},
		&ui_select("remote",
			[ grep { $sel_r{$_} } map { $_->{'name'} } @remotes ],
			[ map { [ $_->{'name'}, $_->{'name'} ] } @remotes ], 3, 1, 1));
	print &ui_table_row($text{'opt_remote_mode'},
		&ui_select("remote_mode", $d{'remote_mode'} || $config{'remote_mode'},
			[ [ "copy", $text{'opt_mode_copy'} ], [ "sync", $text{'opt_mode_sync'} ] ]));
	}

print &ui_table_row($text{'sched_when'}, &cron::show_times_input(\%job));
print &ui_table_end();
print &ui_form_end([ [ undef, $edit ? $text{'sched_save'} : $text{'sched_add_button'} ] ]);

&ui_print_footer("index.cgi", $text{'index_return'});
print "<script type='text/javascript'>if (window.viewer_init) { viewer_init() }</script>";

# post_link(CMD, \%hidden, LABEL, [CONFIRM]) - inline POST as a link-styled button.
sub post_link
{
my ($cmd, $hidden, $label, $confirm) = @_;
my $onsub = $confirm ? " onsubmit=\"return confirm('".&quote_escape($confirm)."')\"" : "";
my $h = &ui_hidden("c", $cmd);
foreach my $k (keys %$hidden) { $h .= &ui_hidden($k, $hidden->{$k}); }
return "<form action='act.cgi' method='post' style='display:inline'$onsub>".$h.
	"<input type='submit' value='".&html_escape($label)."' ".
	"style='border:none;background:none;color:#2a6496;cursor:pointer;padding:0;text-decoration:underline'></form>";
}
