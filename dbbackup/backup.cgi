#!/usr/bin/perl
# backup.cgi - choose what to back up, where, how, and to which cloud remote.

require './dbbackup-lib.pl';
&ReadParse();

our (%config, %text, %in, %access, %ENGINE_LABEL);
%access = &get_module_acl();
&can('backup') || &error($text{'err_noperm'});

&ui_print_header(undef, $text{'backup_title'}, "");

print &ui_alert_box(&html_escape($in{'msg'}), 'success') if ($in{'msg'});
print &ui_alert_box(&html_escape($in{'err'}), 'danger') if ($in{'err'});

my @profiles = &list_profiles();
if (!@profiles) {
	print &ui_alert_box(&text('quick_noprofiles', "profiles.cgi"), 'info');
	&ui_print_footer("index.cgi", $text{'index_return'});
	exit;
	}

print &ui_form_start("act.cgi", "post", undef, "id='bform'");
print &ui_hidden("c", "run_backup");

# ---- Databases to back up --------------------------------------------------
# Each profile is enumerated so the operator can include the whole profile and,
# optionally, narrow it to specific databases. Leaving the per-database boxes
# unticked backs up every database in that profile.
print &ui_subheading($text{'backup_what'});
print "<p>".$text{'backup_what_hint'}."</p>";
print &bulk_select_links('bform', 'p')."<br><br>\n";
foreach my $p (@profiles) {
	my $pid = $p->{'id'};
	print "<div style='margin:0 0 1em 0'>";
	print &ui_checkbox("p", $pid, "<b>".&html_escape($pid)."</b> &mdash; ".
		&html_escape(&profile_label($p)), 1);
	if ($p->{'type'} eq 'mongodb') {
		print "<div style='margin:.3em 0 0 2.2em;color:#777'>".$text{'backup_whole'}."</div>";
		}
	else {
		my ($lf, $dbs) = &list_databases($p);
		if ($lf) {
			print "<div style='margin:.3em 0 0 2.2em'>".
				&ui_text_color(&text('backup_listerr', &html_escape($dbs)), 'warn')."</div>";
			}
		elsif (@$dbs) {
			my $label = ($p->{'type'} eq 'sqlite') ? $text{'backup_files_label'}
								: $text{'backup_dbs_label'};
			print "<div style='margin:.3em 0 0 2.2em'>".$label."<br>";
			foreach my $db (@$dbs) {
				my $show = ($p->{'type'} eq 'sqlite') ? ($db =~ s!.*/!!r) : $db;
				print &ui_checkbox("db_".$pid, $db, &html_escape($show), 0)." ";
				}
			print "<br><small>".$text{'backup_db_hint'}."</small></div>";
			}
		else {
			print "<div style='margin:.3em 0 0 2.2em;color:#777'>".$text{'backup_nodbs'}."</div>";
			}
		}
	print "</div>";
	}

# ---- Destination & options -------------------------------------------------
print &ui_table_start($text{'backup_opts'}, undef, 2);

print &ui_table_row($text{'opt_dir'},
	&ui_textbox("dir", $config{'backup_dir'}, 50)." ".&file_chooser_button("dir", 1));

print &ui_table_row($text{'opt_compression'},
	&ui_select("compression", $config{'compression'},
		[ [ "gzip", "gzip" ], [ "zstd", "zstd" ], [ "xz", "xz" ], [ "none", $text{'opt_none'} ] ]).
	" &nbsp; ".$text{'opt_level'}." ".
	&ui_textbox("level", $config{'compress_level'}, 3));

print &ui_table_row($text{'opt_retain_count'},
	&ui_textbox("retain_count", $config{'retain_count'}, 5)." ".$text{'opt_sets'});
print &ui_table_row($text{'opt_retain_days'},
	&ui_textbox("retain_days", $config{'retain_days'}, 5)." ".$text{'opt_days'});

# Encryption.
print &ui_table_row($text{'opt_encrypt'},
	&ui_yesno_radio("encrypt", $config{'encrypt'} ? 1 : 0)." ".
	$text{'opt_passphrase'}." ".&ui_password("passphrase", "", 25));

# Cloud upload.
my @remotes = &list_remotes();
if (@remotes) {
	print &ui_table_row($text{'opt_remote'},
		&ui_select("remote", [ grep { $_ ne '' } ($config{'default_remote'}) ],
			[ map { [ $_->{'name'}, $_->{'name'}." (".$_->{'type'}.")" ] } @remotes ],
			3, 1, 0));   # size 3, multiple, no add-if-missing (avoids phantom blank)
	print &ui_table_row($text{'opt_remote_mode'},
		&ui_select("remote_mode", $config{'remote_mode'},
			[ [ "copy", $text{'opt_mode_copy'} ], [ "sync", $text{'opt_mode_sync'} ] ]));
	}
else {
	print &ui_table_row($text{'opt_remote'},
		&ui_link("remotes.cgi", $text{'opt_remote_add'}));
	}
print &ui_table_end();

print &ui_form_end([ [ undef, $text{'backup_run'} ] ]);

&ui_print_footer("index.cgi", $text{'index_return'});
print "<script type='text/javascript'>if (window.viewer_init) { viewer_init() }</script>";
