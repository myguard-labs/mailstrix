#!/usr/bin/perl
# Hermetic unit tests for the SpamAssassin Mailstrix plugin. They need
# Mail::SpamAssassin installed (the plugin `use`s its base class + Logger) plus
# HTTP::Tiny + JSON::PP (core since 5.14), but NO running strixd: http mode is
# driven by a mocked HTTP::Tiny::post, shellout mode by fake strix-scan scripts.
#
# Run:  prove -v spamassassin/t/mailstrix.t   (from the repo root, with the plugin
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

# The plugin file is shipped as spamassassin/Mailstrix.pm, NOT at the module's @INC
# path (Mail/SpamAssassin/Plugin/Mailstrix.pm), so load it by file path. Executing it
# defines the Mail::SpamAssassin::Plugin::Mailstrix package.
require "$FindBin::Bin/../Mailstrix.pm";

# A bare instance is enough to call the _scan_* helpers: they use only $self
# (for _token), $pms (a plain hashref of cache slots), $conf and the message ref.
my $self = bless {}, 'Mail::SpamAssassin::Plugin::Mailstrix';

sub fresh_pms { return { mailstrix_matched => 0, mailstrix_high => 0, mailstrix_error => 0, mailstrix_rules => [] }; }

# ---- http mode: a high-score match fires MAILSTRIX + MAILSTRIX_HIGH ----
{
    require HTTP::Tiny;
    no warnings 'redefine';
    local *HTTP::Tiny::post = sub {
        return { success => 1, status => 200,
                 content => '{"matches":[{"rule":"Evil_Macro","namespace":"local","meta":{"score":90}}]}' };
    };
    my $pms  = fresh_pms();
    my $conf = { mailstrix_url => 'http://x:8079', mailstrix_timeout => 5, mailstrix_high_score => 75 };
    my $msg  = "From: a\@b\n\nbody";
    my $ok = $self->_scan_http($pms, $conf, \$msg);
    is($ok, 1, 'http scan completed');
    is($pms->{mailstrix_matched}, 1, 'http: matched');
    is($pms->{mailstrix_high}, 1, 'http: high-score hit sets mailstrix_high');
    is_deeply($pms->{mailstrix_rules}, ['Evil_Macro'], 'http: rule name captured');
    is($self->check_mailstrix($pms), 1, 'check_mailstrix fires on a match');
    is($self->check_mailstrix_high($pms), 1, 'check_mailstrix_high fires on a high score');
}

# ---- http mode: a low-score match fires MAILSTRIX but NOT MAILSTRIX_HIGH ----
{
    no warnings 'redefine';
    local *HTTP::Tiny::post = sub {
        return { success => 1, status => 200,
                 content => '{"matches":[{"rule":"Soft_Hit","meta":{"score":10}}]}' };
    };
    my $pms  = fresh_pms();
    my $conf = { mailstrix_url => 'http://x', mailstrix_high_score => 75 };
    my $msg  = "m";
    $self->_scan_http($pms, $conf, \$msg);
    is($pms->{mailstrix_matched}, 1, 'http low: matched');
    is($pms->{mailstrix_high}, 0, 'http low: mailstrix_high stays 0 below threshold');
}

# ---- http mode: clean verdict ----
{
    no warnings 'redefine';
    local *HTTP::Tiny::post = sub { return { success => 1, status => 200, content => '{"matches":[]}' }; };
    my $pms  = fresh_pms();
    $self->_scan_http($pms, { mailstrix_url => 'http://x' }, \(my $m = 'm'));
    is($pms->{mailstrix_matched}, 0, 'http clean: no match');
    is($self->check_mailstrix($pms), 0, 'check_mailstrix off on clean');
}

# ---- http mode: canary / allowlisted matches are log-only ----
{
    for my $case (
        ['canary', '{"matches":[{"rule":"Shadow_Hit","meta":{"mailstrix_canary":"1","score":99}}]}'],
        ['allow',  '{"matches":[{"rule":"Noisy_Hit","meta":{"mailstrix_allow":"1","score":99}}]}'],
    ) {
        my ($name, $json) = @$case;
        no warnings 'redefine';
        local *HTTP::Tiny::post = sub {
            return { success => 1, status => 200, content => $json };
        };
        my $pms = fresh_pms();
        $self->_scan_http($pms, { mailstrix_url => 'http://x', mailstrix_high_score => 75 }, \(my $m = 'm'));
        is($pms->{mailstrix_matched}, 0, "http $name: log-only match does not score");
        is($pms->{mailstrix_high}, 0, "http $name: log-only high score ignored");
        is_deeply($pms->{mailstrix_rules}, [], "http $name: log-only rule not added to scoring list");
    }
}

# ---- http mode: mixed log-only + actionable still scores the actionable hit ----
{
    no warnings 'redefine';
    local *HTTP::Tiny::post = sub {
        return { success => 1, status => 200,
                 content => '{"matches":[{"rule":"Shadow","meta":{"mailstrix_canary":"1","score":99}},{"rule":"Real","meta":{"score":10}}]}' };
    };
    my $pms = fresh_pms();
    $self->_scan_http($pms, { mailstrix_url => 'http://x', mailstrix_high_score => 75 }, \(my $m = 'm'));
    is($pms->{mailstrix_matched}, 1, 'http mixed: actionable match still scores');
    is($pms->{mailstrix_high}, 0, 'http mixed: canary high score ignored');
    is_deeply($pms->{mailstrix_rules}, ['Real'], 'http mixed: only actionable rule captured');
}

# ---- http mode: transport error -> undef (caller applies fail-open) ----
{
    no warnings 'redefine';
    local *HTTP::Tiny::post = sub { return { success => 0, status => 599, reason => 'Timeout', content => '' }; };
    my $pms = fresh_pms();
    my $ok  = $self->_scan_http($pms, { mailstrix_url => 'http://x' }, \(my $m = 'm'));
    is($ok, undef, 'http error returns undef');
}

# ---- shellout mode: fake strix-scan reporting a match (exit 1) ----
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
    my $conf = { mailstrix_scan_bin => $bin, mailstrix_url => 'http://x', mailstrix_timeout => 5 };
    my $ok = $self->_scan_shellout($pms, $conf, \(my $m = 'message'));
    is($ok, 1, 'shellout match completed');
    is($pms->{mailstrix_matched}, 1, 'shellout: matched');
    is_deeply($pms->{mailstrix_rules}, ['Evil_Doc'], 'shellout: rule parsed from MATCH line');
}

# ---- shellout mode: clean (exit 0) ----
{
    my $bin = fake_scan('clean', "#!/bin/sh\ncat >/dev/null\nexit 0\n");
    my $pms = fresh_pms();
    my $ok = $self->_scan_shellout($pms, { mailstrix_scan_bin => $bin, mailstrix_url => 'http://x' }, \(my $m = 'm'));
    is($ok, 1, 'shellout clean completed');
    is($pms->{mailstrix_matched}, 0, 'shellout clean: no match');
}

# ---- shellout mode: client error (exit 2) -> undef ----
{
    my $bin = fake_scan('err', "#!/bin/sh\ncat >/dev/null\nexit 2\n");
    my $pms = fresh_pms();
    my $ok = $self->_scan_shellout($pms, { mailstrix_scan_bin => $bin, mailstrix_url => 'http://x' }, \(my $m = 'm'));
    is($ok, undef, 'shellout client error returns undef');
}

# ---- shellout mode: missing binary -> undef ----
{
    my $pms = fresh_pms();
    my $ok = $self->_scan_shellout($pms, { mailstrix_scan_bin => "$dir/does-not-exist", mailstrix_url => 'http://x' }, \(my $m = 'm'));
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
        my @parts = $self->_message_part_buffers($pms);
        ok(scalar(@parts) >= 2, 'part bufs: at least the two leaf parts');
        my @bodies = map { $_->[0] } @parts;
        ok((grep { /hello world/ } @bodies), 'part bufs: text part body present');
        ok((grep { /MALWARE_BYTES/ } @bodies), 'part bufs: base64 attachment decoded to real bytes');
        ok(!(grep { /TUFMV0FSRV9CWVRFUw/ } @bodies), 'part bufs: wrapped base64 text not present (was decoded)');
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
    my $conf = { mailstrix_url => 'http://x', mailstrix_high_score => 75 };
    # Two part buffers; scan each through the http helper, as parsed_metadata does.
    for my $buf ('partone', 'parttwo') {
        $self->_scan_http($pms, $conf, \$buf);
    }
    is(scalar(@posted), 2, 'part mode: one POST per part buffer');
    is($pms->{mailstrix_matched}, 1, 'part mode: matched across parts');
    is_deeply([sort @{$pms->{mailstrix_rules}}], ['partone', 'parttwo'],
        'part mode: rule names accumulate from every part');
}

# ---- _token: reads + trims a token file; undef when unset ----
{
    my $tf = "$dir/tok";
    open(my $fh, '>', $tf) or die $!; print $fh "  secret\n"; close($fh);
    is($self->_token({ mailstrix_token_file => $tf }), 'secret', '_token trims file content');
    is($self->_token({ mailstrix_token_file => '' }), undef, '_token undef when unset');
}

# ---- part mode strict errors: any errored part must fire MAILSTRIX_ERROR ----
# Drives the REAL parsed_metadata (not a re-implemented loop) in part mode. We
# override _message_part_buffers to yield two part buffers (no SA Message needed)
# and mock HTTP::Tiny::post so the FIRST part errors and the SECOND completes
# clean. Under fail_open=0, parsed_metadata must set mailstrix_error even though the
# second part scanned OK (the bug masked the error via the defined aggregate).
# test_part_mode_strict_error_any_part
{
    require HTTP::Tiny;
    no warnings 'redefine';

    # Two leaf part buffers, regardless of message structure.
    local *Mail::SpamAssassin::Plugin::Mailstrix::_message_part_buffers = sub {
        return (['part1', undef], ['part2', undef]);
    };

    # First call errors (transport failure -> _scan_http returns undef),
    # second call is a clean completed scan.
    my $call_count = 0;
    local *HTTP::Tiny::post = sub {
        $call_count++;
        return $call_count == 1
            ? { success => 0, status => 599, reason => 'Connection refused', content => '' }
            : { success => 1, status => 200, content => '{"matches":[]}' };
    };

    # parsed_metadata reads $pms->{conf}; $pms->{msg} is unused because
    # _message_part_buffers is overridden, but give it a harmless stub.
    my $conf = {
        mailstrix_url        => 'http://x:8079',
        mailstrix_timeout    => 5,
        mailstrix_mode       => 'http',
        mailstrix_max_size   => 0,
        mailstrix_part_mode  => 1,
        mailstrix_fail_open  => 0,      # strict
        mailstrix_high_score => 75,
    };
    my $pms = fresh_pms();
    $pms->{conf} = $conf;
    $pms->{msg}  = bless {}, 'main::FakeMsg';   # never dereferenced (override)

    $self->parsed_metadata({ permsgstatus => $pms });
    is($call_count, 2, 'part mode strict: parsed_metadata scanned both parts');
    is($pms->{mailstrix_error}, 1,
        'part mode strict: parsed_metadata fires mailstrix_error when ANY part errored');
}

# ---- companion: same setup but fail_open=1 -> mailstrix_error must stay 0 ----
{
    require HTTP::Tiny;
    no warnings 'redefine';

    local *Mail::SpamAssassin::Plugin::Mailstrix::_message_part_buffers = sub {
        return (['part1', undef], ['part2', undef]);
    };
    my $call_count = 0;
    local *HTTP::Tiny::post = sub {
        $call_count++;
        return $call_count == 1
            ? { success => 0, status => 599, reason => 'Connection refused', content => '' }
            : { success => 1, status => 200, content => '{"matches":[]}' };
    };
    my $conf = {
        mailstrix_url        => 'http://x:8079',
        mailstrix_timeout    => 5,
        mailstrix_mode       => 'http',
        mailstrix_max_size   => 0,
        mailstrix_part_mode  => 1,
        mailstrix_fail_open  => 1,      # fail open
        mailstrix_high_score => 75,
    };
    my $pms = fresh_pms();
    $pms->{conf} = $conf;
    $pms->{msg}  = bless {}, 'main::FakeMsg';

    $self->parsed_metadata({ permsgstatus => $pms });
    is($pms->{mailstrix_error}, 0,
        'part mode fail-open: a part error does not fire mailstrix_error (one part completed)');
}

# ---- part mode filename: http mode forwards X-MAILSTRIX-Filename (base64) ----
# Drive parsed_metadata in part mode with a mocked _message_part_buffers that
# returns one part WITH a filename. Assert the header is present and base64-correct.
{
    require HTTP::Tiny;
    require MIME::Base64;
    no warnings 'redefine';

    local *Mail::SpamAssassin::Plugin::Mailstrix::_message_part_buffers = sub {
        return (['fake attachment bytes', 'invoice.exe']);
    };

    my $captured_headers;
    local *HTTP::Tiny::post = sub {
        my ($h, $url, $args) = @_;
        $captured_headers = $args->{headers};
        return { success => 1, status => 200, content => '{"matches":[]}' };
    };

    my $conf = {
        mailstrix_url        => 'http://x:8079',
        mailstrix_timeout    => 5,
        mailstrix_mode       => 'http',
        mailstrix_max_size   => 0,
        mailstrix_part_mode  => 1,
        mailstrix_fail_open  => 1,
        mailstrix_high_score => 75,
    };
    my $pms = fresh_pms();
    $pms->{conf} = $conf;
    $pms->{msg}  = bless {}, 'main::FakeMsg';

    $self->parsed_metadata({ permsgstatus => $pms });
    ok(defined $captured_headers, 'http filename: POST was made');
    ok(defined $captured_headers->{'X-MAILSTRIX-Filename'},
        'http filename: X-MAILSTRIX-Filename header present');
    my $decoded = MIME::Base64::decode_base64($captured_headers->{'X-MAILSTRIX-Filename'} // '');
    is($decoded, 'invoice.exe', 'http filename: header decodes to the part filename');
}

# ---- part mode filename: http mode omits X-MAILSTRIX-Filename when no name ----
{
    require HTTP::Tiny;
    no warnings 'redefine';

    local *Mail::SpamAssassin::Plugin::Mailstrix::_message_part_buffers = sub {
        return (['body bytes', undef]);   # no filename
    };

    my $captured_headers;
    local *HTTP::Tiny::post = sub {
        my ($h, $url, $args) = @_;
        $captured_headers = $args->{headers};
        return { success => 1, status => 200, content => '{"matches":[]}' };
    };

    my $conf = {
        mailstrix_url        => 'http://x:8079',
        mailstrix_timeout    => 5,
        mailstrix_mode       => 'http',
        mailstrix_max_size   => 0,
        mailstrix_part_mode  => 1,
        mailstrix_fail_open  => 1,
        mailstrix_high_score => 75,
    };
    my $pms = fresh_pms();
    $pms->{conf} = $conf;
    $pms->{msg}  = bless {}, 'main::FakeMsg';

    $self->parsed_metadata({ permsgstatus => $pms });
    ok(!defined $captured_headers->{'X-MAILSTRIX-Filename'},
        'http filename: X-MAILSTRIX-Filename absent when part has no name');
}

# ---- part mode filename: shellout mode passes -filename arg ----
# The fake strix-scan prints its own argv so we can assert -filename is present.
{
    my $argv_log = "$dir/argv.txt";
    my $bin = fake_scan('fname_check',
        "#!/bin/sh\ncat >/dev/null\necho \"\$@\" > $argv_log\nexit 0\n");
    my $pms  = fresh_pms();
    my $conf = { mailstrix_scan_bin => $bin, mailstrix_url => 'http://x', mailstrix_timeout => 5 };
    my $body = 'attachment bytes';
    my $ok = $self->_scan_shellout($pms, $conf, \$body, 'report.pdf');
    is($ok, 1, 'shellout filename: scan completed');
    open(my $fh, '<', $argv_log) or die "cannot read argv log: $!";
    my $argv = do { local $/; <$fh> };
    close($fh);
    like($argv, qr/-filename/, 'shellout filename: -filename flag in argv');
    like($argv, qr/report\.pdf/, 'shellout filename: filename value in argv');
}

# ---- part mode filename: shellout mode omits -filename when no name ----
{
    my $argv_log2 = "$dir/argv2.txt";
    my $bin = fake_scan('no_fname',
        "#!/bin/sh\ncat >/dev/null\necho \"\$@\" > $argv_log2\nexit 0\n");
    my $pms  = fresh_pms();
    my $conf = { mailstrix_scan_bin => $bin, mailstrix_url => 'http://x', mailstrix_timeout => 5 };
    my $body = 'body';
    my $ok = $self->_scan_shellout($pms, $conf, \$body, undef);
    is($ok, 1, 'shellout no-filename: scan completed');
    open(my $fh, '<', $argv_log2) or die "cannot read argv log2: $!";
    my $argv = do { local $/; <$fh> };
    close($fh);
    unlike($argv, qr/-filename/, 'shellout no-filename: -filename flag absent when no name');
}

# ---- http mode: degraded reply (AUD-12a) -> unknown, not clean ----
# A degraded reply with no actionable match must behave like shellout mode's
# exit-2 (undef = backend error), never as a completed clean scan. An actionable
# match in a degraded reply is still a detection.
{
    require HTTP::Tiny;
    no warnings 'redefine';
    my $conf = { mailstrix_url => 'http://x', mailstrix_high_score => 75 };
    my $allow = '{"rule":"MAILSTRIX_SCAN_DEGRADED","meta":{"mailstrix_allow":"1"}}';
    my %cases = (
        'degraded no match'       => ['{"matches":[],"degraded":"incomplete"}', undef, 0],
        'degraded busy'           => ['{"matches":[],"degraded":"busy"}', undef, 0],
        'degraded log-only marker'=> ["{\"matches\":[$allow],\"degraded\":\"error\"}", undef, 0],
        'degraded canary only'    => ['{"matches":[{"rule":"S","meta":{"mailstrix_canary":"1"}}],"degraded":"error"}', undef, 0],
        'degraded actionable'     => ['{"matches":[{"rule":"Real","meta":{"score":10}}],"degraded":"incomplete"}', 1, 1],
        'not degraded no match'   => ['{"matches":[]}', 1, 0],
        'empty degraded string'   => ['{"matches":[],"degraded":""}', 1, 0],
        'degraded wrong type'     => ['{"matches":[],"degraded":["x"]}', 1, 0],
        'degraded number'         => ['{"matches":[],"degraded":0}', 1, 0],
    );
    for my $name (sort keys %cases) {
        my ($json, $want_ret, $want_match) = @{$cases{$name}};
        local *HTTP::Tiny::post = sub { return { success => 1, status => 200, content => $json }; };
        my $pms = fresh_pms();
        my $ret = $self->_scan_http($pms, $conf, \(my $m = 'm'));
        is($ret, $want_ret, "http $name: return value");
        is($pms->{mailstrix_matched}, $want_match, "http $name: matched flag");
    }

    # End to end through parsed_metadata: unknown follows fail-open policy like a backend error.
    local *Mail::SpamAssassin::Plugin::Mailstrix::_message_part_buffers = sub { return (['p', undef]); };
    local *HTTP::Tiny::post = sub {
        return { success => 1, status => 200, content => '{"matches":[],"degraded":"busy"}' };
    };
    for my $fail_open (0, 1) {
        my $pms = fresh_pms();
        $pms->{conf} = { mailstrix_url => 'http://x', mailstrix_mode => 'http', mailstrix_max_size => 0,
                         mailstrix_part_mode => 1, mailstrix_fail_open => $fail_open, mailstrix_high_score => 75 };
        $pms->{msg} = bless {}, 'main::FakeMsg';
        $self->parsed_metadata({ permsgstatus => $pms });
        is($pms->{mailstrix_error}, $fail_open ? 0 : 1, "degraded unknown: fail_open=$fail_open error flag");
        is($pms->{mailstrix_matched}, 0, "degraded unknown: fail_open=$fail_open not a match");
    }
}

# ---- shellout parity: client exit 2 (its degraded mapping) is also undef ----
{
    my $bin = fake_scan('degraded', "#!/bin/sh\ncat >/dev/null\nexit 2\n");
    my $pms = fresh_pms();
    my $ok = $self->_scan_shellout($pms, { mailstrix_scan_bin => $bin, mailstrix_url => 'http://x' }, \(my $m = 'm'));
    is($ok, undef, 'shellout degraded (client exit 2): undef, same as http degraded');
}

done_testing();
