#!/usr/bin/perl
# profiles.cgi - manage database connection profiles (which hold credentials).

require './dbbackup-lib.pl';
&ReadParse();

our (%config, %text, %in, %access, %ENGINE_LABEL);
%access = &get_module_acl();
&can('profiles') || &error($text{'err_noperm'});

&ui_print_header(undef, $text{'prof_title'}, "");

print &ui_alert_box(&html_escape($in{'msg'}), 'success') if ($in{'msg'});
print &ui_alert_box(&html_escape($in{'err'}), 'danger') if ($in{'err'});

# ---- Test connection (read-only) -------------------------------------------
if ($in{'test'}) {
	my $p = &get_profile($in{'test'});
	if ($p) {
		my ($f, $list) = &list_databases($p);
		print &ui_subheading(&text('prof_test_of', &html_escape($p->{'id'})));
		if ($f) {
			print &ui_alert_box(&html_escape($list), 'danger');
			}
		else {
			print &ui_alert_box(&text('prof_test_ok', scalar(@$list)), 'success');
			print "<pre class='comment'>".&html_escape(join("\n", @$list))."</pre>" if (@$list);
			}
		print &ui_hr();
		}
	}

# ---- Existing profiles -----------------------------------------------------
print &ui_subheading($text{'prof_existing'});
my @profiles = &list_profiles();
if (!@profiles) {
	print "<p>".$text{'prof_none'}."</p>";
	}
else {
	print &ui_form_start("act.cgi", "post", undef, "id='profform'");
	print &ui_hidden("c", "profile_delete");
	print &bulk_select_links('profform', 'd')."<br>\n";
	print &ui_columns_start([ "", $text{'prof_id'}, $text{'prof_type'},
		$text{'prof_where'}, $text{'prof_desc'}, "" ], 100);
	foreach my $p (@profiles) {
		my $links = &ui_link("profiles.cgi?edit=".&urlize($p->{'id'}), $text{'prof_edit'})." | ".
			&ui_link("profiles.cgi?test=".&urlize($p->{'id'}), $text{'prof_test'});
		print &ui_checked_columns_row([
			&html_escape($p->{'id'}),
			&html_escape($ENGINE_LABEL{$p->{'type'}} || $p->{'type'}),
			&html_escape(&profile_label($p)),
			&html_escape($p->{'desc'} || ''),
			$links,
			], undef, "d", $p->{'id'});
		}
	print &ui_columns_end();
	print &ui_form_end([ [ undef, $text{'prof_delete_button'} ] ]);
	}

# ---- Detected sources (one-click import) -----------------------------------
print &ui_hr();
print &ui_subheading($text{'prof_detected'});
my $engines = &host_engines();
my ($dcfail, $dcons) = &docker_db_containers();
my @drows;
foreach my $eng (sort keys %$engines) {
	if ($eng eq 'sqlite') {
		push(@drows, [ &html_escape($ENGINE_LABEL{$eng}), $text{'detect_host'},
			$text{'prof_det_sqlite'},
			&ui_link("profiles.cgi?new=1&type=sqlite&source=host#dbbaddform", $text{'prof_det_add'}) ]);
		next;
		}
	my $cr;
	if    ($eng eq 'mysql' || $eng eq 'mariadb') { $cr = &webmin_db_config('mysql'); }
	elsif ($eng eq 'postgres')                   { $cr = &webmin_db_config('postgresql'); }
	push(@drows, [ &html_escape($ENGINE_LABEL{$eng}), $text{'detect_host'},
		($cr ? $text{'prof_det_hascreds'} : $text{'prof_det_nocreds'}),
		&post_link("import_profile", { 'type' => $eng, 'source' => 'host' }, $text{'prof_det_import'}) ]);
	}
foreach my $cc (@{$dcons || []}) {
	push(@drows, [ &html_escape($ENGINE_LABEL{$cc->{'engine'}} || $cc->{'engine'}),
		&text('detect_docker', &html_escape($cc->{'name'})),
		"<tt>".&html_escape($cc->{'image'})."</tt>",
		&post_link("import_profile",
			{ 'type' => $cc->{'engine'}, 'source' => 'docker', 'container' => $cc->{'name'} },
			$text{'prof_det_import'}) ]);
	}
if (@drows) {
	print "<p>".$text{'prof_detected_hint'}."</p>";
	print &ui_columns_start([ $text{'detect_engine'}, $text{'detect_loc'}, $text{'detect_detail'}, "" ], 100);
	print &ui_columns_row($_) foreach (@drows);
	print &ui_columns_end();
	}
else {
	print "<p>".$text{'detect_none'}."</p>";
	}

# ---- Add / edit (manual) ---------------------------------------------------
print &ui_hr();
print "<a id='dbbaddform' name='dbbaddform'></a>";
my $edit = ($in{'edit'} && &get_profile($in{'edit'})) ? &get_profile($in{'edit'}) : undef;
my %d = $edit ? %$edit : (
	'type'      => ($in{'type'} || 'mysql'),
	'source'    => ($in{'source'} || 'host'),
	'container' => ($in{'container'} || ''),
	);

print &ui_form_start("act.cgi", "post");
print &ui_hidden("c", "save_profile");
print &ui_hidden("editing", $edit ? 1 : 0);
print &ui_table_start($edit ? &text('prof_edit_of', &html_escape($edit->{'id'})) : $text{'prof_add'}, undef, 2);

if ($edit) {
	print &ui_table_row($text{'prof_id'}, "<tt>".&html_escape($edit->{'id'})."</tt>".
		&ui_hidden("id", $edit->{'id'}));
	}
else {
	print &ui_table_row($text{'prof_id'}, &ui_textbox("id", $in{'id'} || "", 30)."<br>".
		"<small>".$text{'prof_id_hint'}."</small>");
	}

print &ui_table_row($text{'prof_type'},
	&ui_select("type", $d{'type'},
		[ map { [ $_, $ENGINE_LABEL{$_} ] } qw(mysql mariadb postgres mongodb sqlite) ]));

print &ui_table_row($text{'prof_source'},
	&ui_radio("source", $d{'source'} || 'host',
		[ [ "host", $text{'prof_src_host'} ], [ "docker", $text{'prof_src_docker'} ] ]));

my @contopts = map { [ $_->{'name'}, $_->{'name'}." (".$ENGINE_LABEL{$_->{'engine'}}.")" ] } @{$dcons || []};
if (@contopts) {
	# Pick from the running database containers we detected (add-if-missing keeps
	# a prefilled but currently-stopped container selectable).
	print &ui_table_row($text{'prof_container'},
		&ui_select("container", $d{'container'} || "",
			[ [ "", $text{'prof_container_choose'} ], @contopts ], 1, 0, 1)."<br>".
		"<small>".$text{'prof_container_hint'}."</small>");
	}
else {
	print &ui_table_row($text{'prof_container'},
		&ui_textbox("container", $d{'container'} || "", 30)."<br>".
		"<small>".$text{'prof_container_hint'}."</small>");
	}

print &ui_table_row($text{'prof_host'}, &ui_textbox("host", $d{'host'} || "", 30)."<br>".
	"<small>".$text{'prof_host_hint'}."</small>");
print &ui_table_row($text{'prof_port'}, &ui_textbox("port", $d{'port'} || "", 8));
print &ui_table_row($text{'prof_user'}, &ui_textbox("user", $d{'user'} || "", 30));
print &ui_table_row($text{'prof_password'},
	&ui_password("password", "", 30).
	($edit ? "<br><small>".$text{'prof_password_keep'}."</small>" : ""));
print &ui_table_row($text{'prof_socket'}, &ui_textbox("socket", $d{'socket'} || "", 30)."<br>".
	"<small>".$text{'prof_socket_hint'}."</small>");
print &ui_table_row($text{'prof_authdb'}, &ui_textbox("auth_db", $d{'auth_db'} || "", 20)."<br>".
	"<small>".$text{'prof_authdb_hint'}."</small>");
# SQLite files: a "Browse..." chooser per row. Up to 20 rows are pre-rendered
# (each with a working chooser button); extra empty rows stay hidden until the
# "Add another file" button reveals them.
my @spaths = split(/\t/, $d{'sqlite_paths'} || "");
my $total = 20;
my $visible = scalar(@spaths) + 1;
$visible = 5 if ($visible < 5);
$visible = $total if ($visible > $total);
my $sqhtml = "";
for (my $i = 0; $i < $total; $i++) {
	my $hide = ($i >= $visible) ? " style='display:none'" : "";
	$sqhtml .= "<div id='sqrow_$i'$hide>".
		&ui_filebox("sqlite_$i", defined($spaths[$i]) ? $spaths[$i] : "", 50)."</div>";
	}
$sqhtml .= "<input type='button' id='sqaddbtn' value='".&html_escape($text{'prof_sqlite_more'}).
	"' onclick='dbbAddSqliteRow()'>";
$sqhtml .= "<br><small>".$text{'prof_sqlite_hint'}."</small>";
$sqhtml .= "<script>var dbbSqliteShown=$visible,dbbSqliteTotal=$total;".
	"function dbbAddSqliteRow(){var r=document.getElementById('sqrow_'+dbbSqliteShown);".
	"if(r){r.style.display='';dbbSqliteShown++;}".
	"if(dbbSqliteShown>=dbbSqliteTotal){var b=document.getElementById('sqaddbtn');if(b){b.style.display='none';}}}</script>";
print &ui_table_row($text{'prof_sqlite'}, $sqhtml);
print &ui_table_row($text{'prof_desc'}, &ui_textbox("desc", $d{'desc'} || "", 40));

print &ui_table_end();
print &ui_form_end([ [ undef, $edit ? $text{'prof_save'} : $text{'prof_add_button'} ] ]);

&ui_print_footer("index.cgi", $text{'index_return'});
print "<script type='text/javascript'>if (window.viewer_init) { viewer_init() }</script>";

# post_link(CMD, \%hidden, LABEL, [CONFIRM]) - inline POST rendered as a link-styled
# button, so the read-only listing page never triggers a state change via GET.
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
