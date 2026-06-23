#!/usr/bin/perl
# remotes.cgi - manage cloud upload destinations (rclone remotes). We build the
# rclone config file ourselves, so access keys / OAuth tokens are NEVER passed
# to rclone on the command line.

require './dbbackup-lib.pl';
&ReadParse();

our (%config, %text, %in, %access);
%access = &get_module_acl();
&can('remotes') || &error($text{'err_noperm'});

&ui_print_header(undef, $text{'rem_title'}, "");

print &ui_alert_box(&html_escape($in{'msg'}), 'success') if ($in{'msg'});
print &ui_alert_box(&html_escape($in{'err'}), 'danger') if ($in{'err'});

if (!&rclone_installed()) {
	print &ui_alert_box($text{'rem_norclone'}, 'danger');
	}

# ---- Test result -----------------------------------------------------------
if ($in{'test'}) {
	my ($f, $o) = &test_remote($in{'test'});
	print &ui_subheading(&text('rem_test_of', &html_escape($in{'test'})));
	print $f ? &ui_alert_box(&html_escape($o || $text{'rem_test_fail'}), 'danger')
		 : &ui_alert_box($text{'rem_test_ok'}."<pre class='comment'>".&html_escape($o)."</pre>", 'success');
	print &ui_hr();
	}

# ---- Existing remotes ------------------------------------------------------
print &ui_subheading($text{'rem_existing'});
my @remotes = &list_remotes();
if (!@remotes) {
	print "<p>".$text{'rem_none'}."</p>";
	}
else {
	print &ui_columns_start([ $text{'rem_name'}, $text{'rem_type'}, $text{'rem_default'}, "" ], 100);
	foreach my $r (@remotes) {
		my $isdef = ($config{'default_remote'} && $config{'default_remote'} eq $r->{'name'});
		my $actions =
			&post_link("set_default_remote", { 'name' => $r->{'name'} }, $text{'rem_makedefault'})." | ".
			&ui_link("remotes.cgi?test=".&urlize($r->{'name'}), $text{'rem_test'})." | ".
			&post_link("delete_remote", { 'name' => $r->{'name'} }, $text{'rem_delete'},
				$text{'rem_confirm_delete'});
		print &ui_columns_row([
			&html_escape($r->{'name'}),
			&html_escape($r->{'type'}),
			$isdef ? &ui_text_color($text{'yes'}, 'success') : "",
			$actions,
			]);
		}
	print &ui_columns_end();
	}

# ---- Detected remotes (import from the system rclone config) ----------------
my @sysrem = &system_remotes();
if (@sysrem) {
	my %have = map { $_->{'name'} => 1 } @remotes;
	print &ui_hr();
	print &ui_subheading($text{'rem_detected'});
	print "<p>".$text{'rem_detected_hint'}."</p>";
	print &ui_columns_start([ $text{'rem_name'}, $text{'rem_type'}, "" ], 100);
	foreach my $r (@sysrem) {
		my $act = $have{$r->{'name'}}
			? &ui_text_color($text{'rem_already'}, 'success')
			: &post_link("import_remote", { 'name' => $r->{'name'} }, $text{'rem_import'});
		print &ui_columns_row([ &html_escape($r->{'name'}), &html_escape($r->{'type'}), $act ]);
		}
	print &ui_columns_end();
	}

# ---- Add: S3 / AWS (and S3-compatible) -------------------------------------
print &ui_hr();
print &ui_form_start("act.cgi", "post");
print &ui_hidden("c", "save_remote_s3");
print &ui_table_start($text{'rem_add_s3'}, undef, 2);
print &ui_table_row($text{'rem_name'}, &ui_textbox("name", "", 30));
print &ui_table_row($text{'rem_provider'},
	&ui_select("provider", "AWS",
		[ "AWS", "Minio", "Wasabi", "Ceph", "DigitalOcean", "Other" ]));
print &ui_table_row($text{'rem_access'}, &ui_textbox("access_key_id", "", 40));
print &ui_table_row($text{'rem_secret'}, &ui_password("secret_access_key", "", 40));
print &ui_table_row($text{'rem_region'}, &ui_textbox("region", "", 20));
print &ui_table_row($text{'rem_endpoint'}, &ui_textbox("endpoint", "", 40)."<br>".
	"<small>".$text{'rem_endpoint_hint'}."</small>");
print &ui_table_end();
print &ui_form_end([ [ undef, $text{'rem_add_button'} ] ]);

# ---- Add: Dropbox / Google Drive (token based) -----------------------------
print &ui_form_start("act.cgi", "post");
print &ui_hidden("c", "save_remote_token");
print &ui_table_start($text{'rem_add_token'}, undef, 2);
print &ui_table_row($text{'rem_name'}, &ui_textbox("name", "", 30));
print &ui_table_row($text{'rem_kind'},
	&ui_select("kind", "dropbox", [ [ "dropbox", "Dropbox" ], [ "drive", "Google Drive" ] ]));
print &ui_table_row($text{'rem_token'}, &ui_textarea("token", "", 4, 60)."<br>".
	"<small>".$text{'rem_token_hint'}."</small>");
print &ui_table_row($text{'rem_drive_root'}, &ui_textbox("root_folder_id", "", 40)."<br>".
	"<small>".$text{'rem_drive_root_hint'}."</small>");
print &ui_table_end();
print &ui_form_end([ [ undef, $text{'rem_add_button'} ] ]);

# ---- Add: advanced raw paste -----------------------------------------------
print &ui_form_start("act.cgi", "post");
print &ui_hidden("c", "save_remote_raw");
print &ui_table_start($text{'rem_add_raw'}, undef, 2);
print &ui_table_row($text{'rem_name'}, &ui_textbox("name", "", 30));
print &ui_table_row($text{'rem_raw'}, &ui_textarea("body", "", 6, 60)."<br>".
	"<small>".$text{'rem_raw_hint'}."</small>");
print &ui_table_end();
print &ui_form_end([ [ undef, $text{'rem_add_button'} ] ]);

&ui_print_footer("index.cgi", $text{'index_return'});
print "<script type='text/javascript'>if (window.viewer_init) { viewer_init() }</script>";

# post_link(CMD, \%hidden, LABEL, [CONFIRM]) - render a tiny inline POST form as
# a link-styled button so read-only pages never trigger state changes via GET.
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
