#!/usr/bin/perl
# restore.cgi - restore a backup file into a database (or SQLite file).

require './dbbackup-lib.pl';
&ReadParse();

our (%config, %text, %in, %access, %ENGINE_LABEL, $DAILY_RE);
%access = &get_module_acl();
&can('restore') || &error($text{'err_noperm'});

&ui_print_header(undef, $text{'restore_title'}, "");

print &ui_alert_box(&html_escape($in{'msg'}), 'success') if ($in{'msg'});
print &ui_alert_box(&html_escape($in{'err'}), 'danger') if ($in{'err'});

my @profiles = &list_profiles();
if (!@profiles) {
	print &ui_alert_box(&text('quick_noprofiles', "profiles.cgi"), 'info');
	&ui_print_footer("index.cgi", $text{'index_return'});
	exit;
	}

# Build a list of available backup files (value = absolute path).
my $dir = $config{'backup_dir'};
my @fileopts;
foreach my $s (&list_backup_sets($dir)) {
	foreach my $fn (&backup_files($s->{'path'}, $s->{'name'} =~ $DAILY_RE)) {
		push(@fileopts, [ "$s->{'path'}/$fn", "$s->{'name'} / $fn" ]);
		}
	}

print &ui_alert_box($text{'restore_warning'}, 'warn');

print &ui_form_start("act.cgi", "post");
print &ui_hidden("c", "restore");
print &ui_table_start($text{'restore_heading'}, undef, 2);

if (@fileopts) {
	print &ui_table_row($text{'restore_file'},
		&ui_select("file", ($in{'file'} || ""), \@fileopts, 1, 0, 0, 0,
			"style='max-width:40em'"));
	}
else {
	print &ui_table_row($text{'restore_file'},
		&ui_textbox("file", ($in{'file'} || ""), 60)."<br>".
		"<small>".$text{'restore_file_hint'}."</small>");
	}

print &ui_table_row($text{'restore_target_profile'},
	&ui_select("profile", "",
		[ map { [ $_->{'id'}, $_->{'id'}." (".&profile_label($_).")" ] } @profiles ]));
print &ui_table_row($text{'restore_target_db'},
	&ui_textbox("target", "", 30)."<br>".
	"<small>".$text{'restore_target_hint'}."</small>");
print &ui_table_row($text{'restore_passphrase'},
	&ui_password("passphrase", "", 30)."<br>".
	"<small>".$text{'restore_passphrase_hint'}."</small>");

print &ui_table_end();
print &ui_form_end([ [ undef, $text{'restore_button'} ] ]);

&ui_print_footer("index.cgi", $text{'index_return'}, "browse.cgi", $text{'nav_browse'});
print "<script type='text/javascript'>if (window.viewer_init) { viewer_init() }</script>";
