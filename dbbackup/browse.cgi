#!/usr/bin/perl
# browse.cgi - browse backup sets: list, verify checksums, download, upload to a
# remote, or delete. Downloads are streamed only for validated paths that live
# directly under the configured backup directory.

require './dbbackup-lib.pl';
&ReadParse();

our (%config, %text, %in, %access);
%access = &get_module_acl();

my $dir = $config{'backup_dir'};

# ---- Secure file download (must run before any HTML header) ----------------
if (defined($in{'download'}) && defined($in{'set'})) {
	my $set  = $in{'set'};
	my $file = $in{'download'};
	&error($text{'err_badpath'}) if ($set !~ $STAMP_RE);
	&error($text{'err_badpath'}) if ($file !~ /^[A-Za-z0-9][A-Za-z0-9_.\-]*$/);
	my $path = "$dir/$set/$file";
	&error($text{'err_badpath'}) if (index($path, "$dir/") != 0 || $path =~ /\.\./);
	&error($text{'err_nofile'}) if (!-f $path);
	my $size = (-s $path) || 0;
	print "Content-type: application/octet-stream\n";
	print "Content-Disposition: attachment; filename=\"$file\"\n";
	print "Content-Length: $size\n\n";
	binmode(STDOUT);
	open(my $fh, "<", $path) || &error($text{'err_nofile'});
	binmode($fh);
	my $buf;
	print $buf while (read($fh, $buf, 65536));
	close($fh);
	exit;
	}

&ui_print_header(undef, $text{'browse_title'}, "");

print &ui_alert_box(&html_escape($in{'msg'}), 'success') if ($in{'msg'});
print &ui_alert_box(&html_escape($in{'err'}), 'danger') if ($in{'err'});
print "<p>".&text('dash_dest', "<tt>".&html_escape($dir)."</tt>")."</p>";

# ---- Single set view -------------------------------------------------------
if ($in{'set'} && $in{'set'} =~ $STAMP_RE && -d "$dir/$in{'set'}") {
	my $set  = $in{'set'};
	my $sdir = "$dir/$set";
	print &ui_subheading(&html_escape($set));

	# Load recorded checksums.
	my %sums;
	if (open(my $sf, "<", "$sdir/SHA256SUMS")) {
		while (my $l = <$sf>) { $sums{$2} = $1 if ($l =~ /^(\S+)\s+(.+?)\s*$/); }
		close($sf);
		}

	# Optional verification pass.
	my %verify;
	if ($in{'verify'}) {
		foreach my $fn (keys %sums) {
			my $got = &sha256_of("$sdir/$fn");
			$verify{$fn} = (defined($got) && $got eq $sums{$fn}) ? 'ok' : 'bad';
			}
		}

	opendir(my $dh, $sdir);
	my @files = sort grep { -f "$sdir/$_" && $_ !~ /^(SHA256SUMS|manifest\.json|backup\.log)$/ } readdir($dh);
	closedir($dh);

	print &ui_columns_start([ $text{'browse_file'}, $text{'browse_size'},
		$text{'browse_sha'}, $text{'browse_actions'} ], 100);
	foreach my $fn (@files) {
		my $sz = (-s "$sdir/$fn") || 0;
		my $shacell = $sums{$fn} ? substr($sums{$fn}, 0, 12)."&hellip;" : "-";
		if ($in{'verify'} && $verify{$fn}) {
			$shacell .= " ".($verify{$fn} eq 'ok'
				? &ui_text_color($text{'browse_ok'}, 'success')
				: &ui_text_color($text{'browse_bad'}, 'danger'));
			}
		my $act = &ui_link("browse.cgi?set=".&urlize($set)."&download=".&urlize($fn), $text{'browse_download'});
		$act .= " | ".&ui_link("restore.cgi?file=".&urlize("$sdir/$fn"), $text{'browse_restore'}) if (&can('restore'));
		print &ui_columns_row([ &html_escape($fn), &fmt_bytes($sz), $shacell, $act ]);
		}
	print &ui_columns_end();

	print "<p>".&ui_link("browse.cgi?set=".&urlize($set)."&verify=1", $text{'browse_verify'})." &nbsp;|&nbsp; ".
		&ui_link("browse.cgi", $text{'browse_back'})."</p>";

	# Upload this set to a remote.
	my @remotes = &list_remotes();
	if (&can('remotes') && @remotes) {
		print &ui_form_start("act.cgi", "post");
		print &ui_hidden("c", "upload_set");
		print &ui_hidden("set", $set);
		print &ui_table_start($text{'browse_upload'}, undef, 2);
		print &ui_table_row($text{'opt_remote'},
			&ui_select("remote", $config{'default_remote'},
				[ map { [ $_->{'name'}, $_->{'name'} ] } @remotes ]));
		print &ui_table_end();
		print &ui_form_end([ [ undef, $text{'browse_upload_button'} ] ]);
		}

	# Delete this set.
	if (&can('delete')) {
		print &ui_form_start("act.cgi", "post");
		print &ui_hidden("c", "delete_set");
		print &ui_hidden("set", $set);
		print &ui_form_end([ [ undef, $text{'browse_delete'} ] ]);
		}
	}

# ---- All sets --------------------------------------------------------------
else {
	my @sets = &list_backup_sets($dir);
	if (!@sets) {
		print &ui_alert_box($text{'recent_none'}, 'info');
		}
	else {
		print &ui_form_start("act.cgi", "post", undef, "id='setform'");
		print &ui_hidden("c", "delete_sets");
		print &bulk_select_links('setform', 'd')."<br>\n" if (&can('delete'));
		print &ui_columns_start([ (&can('delete') ? "" : ()), $text{'recent_set'},
			$text{'recent_files'}, $text{'recent_size'}, $text{'recent_when'} ], 100);
		foreach my $s (@sets) {
			my @cols = (
				&ui_link("browse.cgi?set=".&urlize($s->{'name'}), &html_escape($s->{'name'})),
				$s->{'files'},
				&fmt_bytes($s->{'bytes'}),
				&make_date($s->{'mtime'}),
				);
			if (&can('delete')) {
				print &ui_checked_columns_row(\@cols, undef, "d", $s->{'name'});
				}
			else {
				print &ui_columns_row(\@cols);
				}
			}
		print &ui_columns_end();
		print &ui_form_end(&can('delete') ? [ [ undef, $text{'browse_delete_sel'} ] ] : []);
		}
	}

&ui_print_footer("index.cgi", $text{'index_return'});
print "<script type='text/javascript'>if (window.viewer_init) { viewer_init() }</script>";
