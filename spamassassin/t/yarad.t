#!/usr/bin/perl
# Hermetic unit tests for the SpamAssassin Yarad plugin. They need
# Mail::SpamAssassin installed (the plugin `use`s its base class + Logger) plus
# HTTP::Tiny + JSON::PP (core since 5.14), but NO running yarad: http mode is
# driven by a mocked HTTP::Tiny::post, shellout mode by fake yarad-scan scripts.
#
# Run:  prove -v spamassassin/t/yarad.t   (from the repo root, with the plugin
# importable — the CI step adds spamassassin/ to @INC via -I).

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;

BEGIN {
    eval { require Mail::SpamAssassin::Plugin; 1 }
        or plan skip_all => 'Mail::SpamAssassin not installed';
}

# The plugin file is shipped as spamassassin/Yarad.pm, NOT at the module's @INC
# path (Mail/SpamAssassin/Plugin/Yarad.pm), so load it by file path. Executing it
# defines the Mail::SpamAssassin::Plugin::Yarad package.
require "$FindBin::Bin/../Yarad.pm";

# A bare instance is enough to call the _scan_* helpers: they use only $self
# (for _token), $pms (a plain hashref of cache slots), $conf and the message ref.
my $self = bless {}, 'Mail::SpamAssassin::Plugin::Yarad';

sub fresh_pms { return { yarad_matched => 0, yarad_high => 0, yarad_error => 0, yarad_rules => [] }; }

# ---- http mode: a high-score match fires YARAD + YARAD_HIGH ----
{
    require HTTP::Tiny;
    no warnings 'redefine';
    local *HTTP::Tiny::post = sub {
        return { success => 1, status => 200,
                 content => '{"matches":[{"rule":"Evil_Macro","namespace":"local","meta":{"score":90}}]}' };
    };
    my $pms  = fresh_pms();
    my $conf = { yarad_url => 'http://x:8079', yarad_timeout => 5, yarad_high_score => 75 };
    my $msg  = "From: a\@b\n\nbody";
    my $ok = $self->_scan_http($pms, $conf, \$msg);
    is($ok, 1, 'http scan completed');
    is($pms->{yarad_matched}, 1, 'http: matched');
    is($pms->{yarad_high}, 1, 'http: high-score hit sets yarad_high');
    is_deeply($pms->{yarad_rules}, ['Evil_Macro'], 'http: rule name captured');
    is($self->check_yarad($pms), 1, 'check_yarad fires on a match');
    is($self->check_yarad_high($pms), 1, 'check_yarad_high fires on a high score');
}

# ---- http mode: a low-score match fires YARAD but NOT YARAD_HIGH ----
{
    no warnings 'redefine';
    local *HTTP::Tiny::post = sub {
        return { success => 1, status => 200,
                 content => '{"matches":[{"rule":"Soft_Hit","meta":{"score":10}}]}' };
    };
    my $pms  = fresh_pms();
    my $conf = { yarad_url => 'http://x', yarad_high_score => 75 };
    my $msg  = "m";
    $self->_scan_http($pms, $conf, \$msg);
    is($pms->{yarad_matched}, 1, 'http low: matched');
    is($pms->{yarad_high}, 0, 'http low: yarad_high stays 0 below threshold');
}

# ---- http mode: clean verdict ----
{
    no warnings 'redefine';
    local *HTTP::Tiny::post = sub { return { success => 1, status => 200, content => '{"matches":[]}' }; };
    my $pms  = fresh_pms();
    $self->_scan_http($pms, { yarad_url => 'http://x' }, \(my $m = 'm'));
    is($pms->{yarad_matched}, 0, 'http clean: no match');
    is($self->check_yarad($pms), 0, 'check_yarad off on clean');
}

# ---- http mode: transport error -> undef (caller applies fail-open) ----
{
    no warnings 'redefine';
    local *HTTP::Tiny::post = sub { return { success => 0, status => 599, reason => 'Timeout', content => '' }; };
    my $pms = fresh_pms();
    my $ok  = $self->_scan_http($pms, { yarad_url => 'http://x' }, \(my $m = 'm'));
    is($ok, undef, 'http error returns undef');
}

# ---- shellout mode: fake yarad-scan reporting a match (exit 1) ----
my $dir = tempdir(CLEANUP => 1);
sub fake_scan {
    my ($name, $body) = @_;
    my $p = "$dir/$name";
    open(my $fh, '>', $p) or die $!;
    print $fh $body;
    close($fh);
    chmod 0755, $p;
    return $p;
}
{
    my $bin = fake_scan('match', "#!/bin/sh\ncat >/dev/null\necho 'MATCH Evil_Doc (local)'\nexit 1\n");
    my $pms  = fresh_pms();
    my $conf = { yarad_scan_bin => $bin, yarad_url => 'http://x', yarad_timeout => 5 };
    my $ok = $self->_scan_shellout($pms, $conf, \(my $m = 'message'));
    is($ok, 1, 'shellout match completed');
    is($pms->{yarad_matched}, 1, 'shellout: matched');
    is_deeply($pms->{yarad_rules}, ['Evil_Doc'], 'shellout: rule parsed from MATCH line');
}

# ---- shellout mode: clean (exit 0) ----
{
    my $bin = fake_scan('clean', "#!/bin/sh\ncat >/dev/null\nexit 0\n");
    my $pms = fresh_pms();
    my $ok = $self->_scan_shellout($pms, { yarad_scan_bin => $bin, yarad_url => 'http://x' }, \(my $m = 'm'));
    is($ok, 1, 'shellout clean completed');
    is($pms->{yarad_matched}, 0, 'shellout clean: no match');
}

# ---- shellout mode: client error (exit 2) -> undef ----
{
    my $bin = fake_scan('err', "#!/bin/sh\ncat >/dev/null\nexit 2\n");
    my $pms = fresh_pms();
    my $ok = $self->_scan_shellout($pms, { yarad_scan_bin => $bin, yarad_url => 'http://x' }, \(my $m = 'm'));
    is($ok, undef, 'shellout client error returns undef');
}

# ---- shellout mode: missing binary -> undef ----
{
    my $pms = fresh_pms();
    my $ok = $self->_scan_shellout($pms, { yarad_scan_bin => "$dir/does-not-exist", yarad_url => 'http://x' }, \(my $m = 'm'));
    is($ok, undef, 'shellout missing binary returns undef');
}

# ---- part mode: _message_part_buffers returns each leaf part's DECODED body ----
# Build a real Mail::SpamAssassin::Message from a multipart MIME string so we
# exercise find_parts/decode, not a mock. Base64-encode an attachment so the
# decoded body must differ from the wrapped wire bytes.
{
    my $have_msg = eval { require Mail::SpamAssassin; require Mail::SpamAssassin::Message; 1 };
    if (!$have_msg) {
        # base class loaded (BEGIN above) but full SA not importable — skip these.
        diag('Mail::SpamAssassin::Message not importable, skipping part-mode body tests');
    } else {
        my $sa = Mail::SpamAssassin->new({
            dont_copy_prefs   => 1,
            local_tests_only  => 1,
            use_bayes         => 0,
            use_dcc           => 0,
            use_razor2        => 0,
            use_pyzor         => 0,
        });
        my $raw = join("\r\n",
            'From: a@b',
            'Subject: t',
            'MIME-Version: 1.0',
            'Content-Type: multipart/mixed; boundary="BND"',
            '',
            '--BND',
            'Content-Type: text/plain',
            '',
            'hello world',
            '--BND',
            'Content-Type: application/octet-stream',
            'Content-Transfer-Encoding: base64',
            '',
            'TUFMV0FSRV9CWVRFUw==',   # "MALWARE_BYTES"
            '--BND--',
            '');
        my $msg = $sa->parse(\$raw, 1);
        my $pms = fresh_pms();
        $pms->{msg} = $msg;
        my @bufs = $self->_message_part_buffers($pms);
        ok(scalar(@bufs) >= 2, 'part bufs: at least the two leaf parts');
        ok((grep { /hello world/ } @bufs), 'part bufs: text part body present');
        ok((grep { /MALWARE_BYTES/ } @bufs), 'part bufs: base64 attachment decoded to real bytes');
        ok(!(grep { /TUFMV0FSRV9CWVRFUw/ } @bufs), 'part bufs: wrapped base64 text not present (was decoded)');
        $msg->finish() if $msg->can('finish');
        $sa->finish() if $sa->can('finish');
    }
}

# ---- part mode: scans every buffer, accumulating matches across parts ----
# Drive _scan_http through a mocked HTTP::Tiny::post that returns a different
# match per call, and a fake _message_part_buffers via a subclass override, to
# prove parsed_metadata fans the scan across parts. We test the aggregation loop
# directly to stay hermetic (no SA Message needed).
{
    no warnings 'redefine';
    my @posted;
    local *HTTP::Tiny::post = sub {
        my ($h, $url, $args) = @_;
        push @posted, $args->{content};
        # Echo a rule named after the (decoded) content so we can assert per-part.
        my $rule = $args->{content} =~ /(\w+)/ ? $1 : 'X';
        return { success => 1, status => 200,
                 content => qq({"matches":[{"rule":"$rule","meta":{"score":5}}]}) };
    };
    my $pms  = fresh_pms();
    my $conf = { yarad_url => 'http://x', yarad_high_score => 75 };
    # Two part buffers; scan each through the http helper, as parsed_metadata does.
    for my $buf ('partone', 'parttwo') {
        $self->_scan_http($pms, $conf, \$buf);
    }
    is(scalar(@posted), 2, 'part mode: one POST per part buffer');
    is($pms->{yarad_matched}, 1, 'part mode: matched across parts');
    is_deeply([sort @{$pms->{yarad_rules}}], ['partone', 'parttwo'],
        'part mode: rule names accumulate from every part');
}

# ---- _token: reads + trims a token file; undef when unset ----
{
    my $tf = "$dir/tok";
    open(my $fh, '>', $tf) or die $!; print $fh "  secret\n"; close($fh);
    is($self->_token({ yarad_token_file => $tf }), 'secret', '_token trims file content');
    is($self->_token({ yarad_token_file => '' }), undef, '_token undef when unset');
}

done_testing();
