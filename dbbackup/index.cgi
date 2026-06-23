#!/usr/bin/perl
# index.cgi - Database Backup dashboard.
# READ-ONLY: every state change is POSTed to act.cgi (covered by Webmin's
# trusted-referer check).

require './dbbackup-lib.pl';
&ReadParse();

our (%config, %text, %in, %access, %ENGINE_LABEL);
%access = &get_module_acl();

&ui_print_header(undef, $text{'index_title'}, "", undef, 1, 1);

# Feedback from act.cgi redirects.
print &ui_alert_box(&html_escape($in{'msg'}), 'success') if ($in{'msg'});
print &ui_alert_box(&html_escape($in{'err'}), 'danger') if ($in{'err'});

my $engines  = &host_engines();
my ($dcfail, $dcons) = &docker_db_containers();
my @profiles = &list_profiles();
my $dir      = $config{'backup_dir'};
my @sets     = &list_backup_sets($dir);
my $free     = &free_space_mb($dir);

# ---- Status cards ----------------------------------------------------------
my @cells;
push(@cells, &card($text{'dash_profiles'}, scalar(@profiles), 'info'));
push(@cells, &card($text{'dash_sets'}, scalar(@sets), 'success'));
push(@cells, &card($text{'dash_engines'}, scalar(keys %$engines), 'info'));
push(@cells, &card($text{'dash_free'},
	defined($free) ? &fmt_bytes($free * 1024 * 1024) : '?',
	(defined($free) && $config{'free_space_mb'} && $free < $config{'free_space_mb'}) ? 'danger' : 'success'));
print &ui_grid_table(\@cells, 4, 100,
	[ map { "width=25% style='text-align:center'" } (1..4) ]);
print "<p>".&text('dash_dest', "<tt>".&html_escape($dir)."</tt>")."</p>";

# ---- Navigation ------------------------------------------------------------
my @nav;
push(@nav, &ui_link("backup.cgi", $text{'nav_backup'}))     if (&can('backup'));
push(@nav, &ui_link("browse.cgi", $text{'nav_browse'}));
push(@nav, &ui_link("restore.cgi", $text{'nav_restore'}))   if (&can('restore'));
push(@nav, &ui_link("profiles.cgi", $text{'nav_profiles'})) if (&can('profiles'));
push(@nav, &ui_link("remotes.cgi", $text{'nav_remotes'}))   if (&can('remotes'));
push(@nav, &ui_link("schedule.cgi", $text{'nav_schedule'})) if (&can('schedule') && &cron_available());
print "<p>".join(" &nbsp;|&nbsp; ", @nav)."</p>";
print &ui_hr();

# ---- Quick backup ----------------------------------------------------------
if (&can('backup')) {
	print &ui_subheading($text{'quick_heading'});
	if (!@profiles) {
		print &ui_alert_box(&text('quick_noprofiles',
			"profiles.cgi"), 'info');
		}
	else {
		print &ui_form_start("act.cgi", "post", undef, "id='quickform'");
		print &ui_hidden("c", "run_backup");
		print &bulk_select_links('quickform', 'p')."<br>\n";
		print &ui_columns_start([ "", $text{'prof_id'}, $text{'prof_type'},
			$text{'prof_where'} ], 100);
		foreach my $p (@profiles) {
			print &ui_checked_columns_row([
				&html_escape($p->{'id'}),
				&html_escape($ENGINE_LABEL{$p->{'type'}} || $p->{'type'}),
				&html_escape(&profile_label($p)),
				], undef, "p", $p->{'id'}, 1);
			}
		print &ui_columns_end();
		my @remotes = &list_remotes();
		if (@remotes) {
			print "<p>".$text{'quick_remote'}." ".
				&ui_select("remote", $config{'default_remote'},
				[ [ "", $text{'quick_noremote'} ],
				  map { [ $_->{'name'}, $_->{'name'} ] } @remotes ])."</p>";
			}
		print &ui_form_end([ [ undef, $text{'quick_button'} ] ]);
		}
	}

# ---- Detected sources ------------------------------------------------------
print &ui_hr();
print &ui_subheading($text{'detect_heading'});
my @rows;
foreach my $eng (sort keys %$engines) {
	push(@rows, [ &html_escape($ENGINE_LABEL{$eng} || $eng), $text{'detect_host'},
		"<tt>".&html_escape($engines->{$eng})."</tt>",
		&can('profiles') ? &ui_link("profiles.cgi?new=1&type=".&urlize($eng)."&source=host",
			$text{'detect_new'}) : "" ]);
	}
if (!$dcfail) {
	foreach my $c (@$dcons) {
		push(@rows, [ &html_escape($ENGINE_LABEL{$c->{'engine'}} || $c->{'engine'}),
			&text('detect_docker', &html_escape($c->{'name'})),
			"<tt>".&html_escape($c->{'image'})."</tt>",
			&can('profiles') ? &ui_link("profiles.cgi?new=1&type=".&urlize($c->{'engine'}).
				"&source=docker&container=".&urlize($c->{'name'}), $text{'detect_new'}) : "" ]);
		}
	}
if (@rows) {
	print &ui_columns_start([ $text{'detect_engine'}, $text{'detect_loc'},
		$text{'detect_detail'}, "" ], 100);
	print &ui_columns_row($_) foreach (@rows);
	print &ui_columns_end();
	}
else {
	print &ui_alert_box($text{'detect_none'}, 'warn');
	}
print "<p>".$text{'detect_rclone'}." ".
	(&rclone_installed() ? &ui_text_color($text{'yes'}, 'success')
			     : &ui_text_color($text{'no'}, 'danger'))."</p>";

# ---- Recent backups --------------------------------------------------------
print &ui_hr();
print &ui_subheading($text{'recent_heading'});
if (!@sets) {
	print "<p>".$text{'recent_none'}."</p>";
	}
else {
	print &ui_columns_start([ $text{'recent_set'}, $text{'recent_files'},
		$text{'recent_size'}, $text{'recent_when'} ], 100);
	my $n = 0;
	foreach my $s (@sets) {
		last if ($n++ >= 10);
		print &ui_columns_row([
			&ui_link("browse.cgi?set=".&urlize($s->{'name'}), &html_escape($s->{'name'})),
			$s->{'files'},
			&fmt_bytes($s->{'bytes'}),
			&make_date($s->{'mtime'}),
			]);
		}
	print &ui_columns_end();
	print "<p>".&ui_link("browse.cgi", $text{'recent_all'})."</p>";
	}

&ui_print_footer("/", $text{'index_return_main'});
print "<script type='text/javascript'>if (window.viewer_init) { viewer_init() }</script>";

# card(LABEL, VALUE, LEVEL) - a big coloured number for the summary grid.
sub card
{
my ($label, $value, $level) = @_;
$value = 0 if (!defined($value));
return "<div style='font-size:200%'>".
	&ui_text_color(&html_escape($value), $level)."</div>".
	"<div>".&html_escape($label)."</div>";
}
