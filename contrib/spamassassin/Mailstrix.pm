# Mail::SpamAssassin::Plugin::Mailstrix — scan each message through a central strixd.
#
# Project:  https://github.com/eilandert/mailstrix
# Write-up: https://deb.myguard.nl/2026/06/yara-malware-scanning-mailstrix/
#
# This is the SpamAssassin sibling of the rspamd `mailstrix.lua` plugin and the
# Dovecot/Sieve `strix-scan` client: it hands the raw message to a central
# `strixd serve` and turns the YARA verdict into SpamAssassin rule hits, so the
# malware signal lands in the spam score alongside everything else.
#
# Two modes (mailstrix_mode):
#
#   http      — the plugin POSTs the message to <mailstrix_url>/scan itself with the
#               core Perl HTTP::Tiny (no extra binary on the box) and parses the
#               JSON verdict. This is the RICH mode: it sees every matched rule's
#               name, namespace, tags and meta.score, so it can fire graduated
#               symbols (MAILSTRIX on any hit, MAILSTRIX_HIGH on a high-score hit) and
#               expose the matched rule names as a tag for headers/logging.
#
#   shellout  — the plugin pipes the message to the lean, CGO-free `strix-scan`
#               client (the same binary the Sieve path uses) and reads its exit
#               code: 0 clean, 1 match. Hit/no-hit only — no per-rule score — but
#               it reuses one audited client and one fail-open code path. Use this
#               when you already deploy `strix-scan` and want a single transport.
#
# Both modes FAIL OPEN by default (mailstrix_fail_open 1): a scanner outage, timeout
# or transport error is treated as CLEAN so a down backend never tags every
# message. Set mailstrix_fail_open 0 to make a backend failure fire MAILSTRIX_ERROR
# instead (useful on a host where a silent miss is worse than a visible error).
#
# Install: see README.md in this directory. In short — drop this file somewhere
# SpamAssassin can read, point a `loadplugin` line at it (strixd.pre), and ship
# strixd.cf with the rule scores.

package Mail::SpamAssassin::Plugin::Mailstrix;

use strict;
use warnings;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use MIME::Base64 ();
use POSIX ();

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
    my ($class, $mailsa) = @_;
    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsa);
    bless($self, $class);

    # The eval rules this plugin answers. Defined (with scores) in strixd.cf.
    $self->register_eval_rule('check_mailstrix');           # any YARA rule matched
    $self->register_eval_rule('check_mailstrix_high');      # a high meta.score match (http mode only)
    $self->register_eval_rule('check_mailstrix_error');     # backend unreachable and fail-open off

    $self->set_config($mailsa->{conf});
    return $self;
}

sub set_config {
    my ($self, $conf) = @_;
    my @cmds;

    # Transport: 'http' (plugin POSTs itself, rich verdict) or 'shellout'
    # (pipe to the strix-scan client, hit/no-hit only).
    push @cmds, {
        setting => 'mailstrix_mode',
        default => 'http',
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    };

    # http mode: base URL of the central `strixd serve`.
    push @cmds, {
        setting => 'mailstrix_url',
        default => 'http://strixd.internal:8079',
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    };

    # Shared secret. Read from a file so it never appears in a process list or
    # this config. Empty (the default) = talk to a token-less strixd.
    push @cmds, {
        setting => 'mailstrix_token_file',
        default => '',
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    };

    # shellout mode: the lean client binary (same one the Sieve path uses).
    push @cmds, {
        setting => 'mailstrix_scan_bin',
        default => '/usr/local/bin/strix-scan',
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    };

    # Per-request timeout, seconds.
    push @cmds, {
        setting => 'mailstrix_timeout',
        default => 10,
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    };

    # Don't send messages larger than this many bytes (matches the strix-scan
    # client's -max-body default of 8 MiB). 0 = no cap.
    push @cmds, {
        setting => 'mailstrix_max_size',
        default => 8 * 1024 * 1024,
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    };

    # Fail open (1, default): a backend error is treated as clean. 0: a backend
    # error fires MAILSTRIX_ERROR.
    push @cmds, {
        setting => 'mailstrix_fail_open',
        default => 1,
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
    };

    # http mode: a matched rule whose meta.score is >= this (0..100) also fires
    # check_mailstrix_high, so a confident malware hit can score harder than a soft one.
    push @cmds, {
        setting => 'mailstrix_high_score',
        default => 75,
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    };

    # Part mode (0, default): scan the whole pristine message in one request, as
    # before. 1: scan each leaf MIME part's DECODED body as its own request,
    # accumulating matches. Per-part decoding lets a base64 attachment be scanned
    # as its real bytes and keeps each request under mailstrix_max_size; the trade is
    # one backend round-trip per part. The strixd backend still does its own
    # container/MIME extraction, so whole-message mode is the right default.
    push @cmds, {
        setting => 'mailstrix_part_mode',
        default => 0,
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
    };

    $conf->{parser}->register_commands(\@cmds);
}

# parsed_metadata runs once per message, before rules are evaluated. We do the
# scan here and stash the result; the check_* eval rules just read the cache so
# the (network) scan happens at most once regardless of how many rules consult it.
sub parsed_metadata {
    my ($self, $opts) = @_;
    my $pms  = $opts->{permsgstatus};
    my $conf = $pms->{conf};

    # Cache slots.
    $pms->{mailstrix_matched} = 0;
    $pms->{mailstrix_high}    = 0;
    $pms->{mailstrix_error}   = 0;
    $pms->{mailstrix_rules}   = [];

    my $max  = $conf->{mailstrix_max_size} || 0;
    my $mode = lc($conf->{mailstrix_mode} || 'http');
    my $helper = $mode eq 'shellout' ? '_scan_shellout' : '_scan_http';

    # Build the list of (buffer, filename) pairs to scan. Whole-message mode
    # (default) scans the pristine message once with no filename. Part mode scans
    # each decoded leaf MIME part; the attachment filename (if any) travels with
    # the buffer so the backend can set YARA filename/extension external variables.
    # Part mode falls back to the pristine message when no leaf part yields a body.
    my @parts;  # array of [ $body_scalar, $filename_or_undef ]
    if ($conf->{mailstrix_part_mode}) {
        my @raw = $self->_message_part_buffers($pms);
        if (!@raw) {
            dbg("strixd: part mode found no part bodies, falling back to whole message");
            @parts = ([ $pms->{msg}->get_pristine(), undef ]);
        } else {
            dbg("strixd: part mode scanning %d part(s)", scalar @raw);
            @parts = @raw;  # each element is already [ $body, $filename ]
        }
    } else {
        @parts = ([ $pms->{msg}->get_pristine(), undef ]);
    }

    # Scan each buffer through the chosen helper. A buffer over mailstrix_max_size is
    # skipped (continue), not fatal. $ok aggregates to defined if ANY buffer
    # completed a scan; it stays undef only when every buffer errored (or all
    # were skipped for size) so fail-open is honoured exactly as in single-scan.
    # $err tracks whether any scanned (non-size-skipped) buffer errored (returned undef).
    my $ok;
    my $err = 0;
    for my $part (@parts) {
        my ($buf, $fname) = @$part;
        if ($max > 0 && length($buf) > $max) {
            dbg("strixd: buffer %d bytes > mailstrix_max_size %d, skipping", length($buf), $max);
            next;
        }
        my $r = $self->$helper($pms, $conf, \$buf, $fname);
        if (defined $r) {
            $ok = $r;   # a completed scan makes the aggregate defined
        } else {
            $err = 1;   # a scanned buffer errored
        }
    }

    # $ok is undef on a backend error (no buffer completed). Honour fail-open.
    if (!defined $ok) {
        if ($conf->{mailstrix_fail_open}) {
            dbg("strixd: backend error, failing open (clean)");
        } else {
            $pms->{mailstrix_error} = 1;
        }
        return;
    }

    # In part mode with strict errors (fail_open 0), any errored buffer must fire
    # MAILSTRIX_ERROR even if another buffer completed. Size-skipped buffers do not count.
    if ($err && !$conf->{mailstrix_fail_open}) {
        dbg("strixd: part error under strict mode, firing MAILSTRIX_ERROR");
        $pms->{mailstrix_error} = 1;
        return;
    }

    if (@{$pms->{mailstrix_rules}}) {
        # Expose the matched rule names for headers / logging: add_header ... _MAILSTRIXRULES_
        $pms->set_tag('MAILSTRIXRULES', join(',', @{$pms->{mailstrix_rules}}));
    }
}

# _scan_http POSTs the message to <mailstrix_url>/scan and fills the cache from the
# JSON verdict. Returns 1 on a completed scan (match or clean), undef on a
# transport/HTTP error. $fname (optional) is the attachment filename forwarded
# as a base64 X-MAILSTRIX-Filename header so name/extension-keyed YARA rules fire.
sub _scan_http {
    my ($self, $pms, $conf, $msgref, $fname) = @_;

    my $have = eval { require HTTP::Tiny; require JSON::PP; 1 };
    if (!$have) {
        info("strixd: http mode needs HTTP::Tiny + JSON::PP (core since Perl 5.14); error: %s", $@);
        return undef;
    }

    my $url = $conf->{mailstrix_url};
    $url =~ s{/+$}{};
    $url .= '/scan';

    my %headers = (
        'Content-Type' => 'application/octet-stream',
        'Accept'       => 'application/json',
        'User-Agent'   => 'spamassassin-strixd',
    );
    my $tok = $self->_token($conf);
    $headers{'X-MAILSTRIX-Token'} = $tok if defined $tok && length $tok;
    # Forward the attachment filename so name/extension-keyed YARA rules can fire.
    # Base64-encode (same wire format as mailstrix.lua) to keep embedded newlines / control
    # bytes from injecting HTTP headers. Omit the header entirely when no name.
    if (defined $fname && length $fname) {
        $headers{'X-MAILSTRIX-Filename'} = MIME::Base64::encode_base64($fname, '');
    }

    my $http = HTTP::Tiny->new(
        timeout => $conf->{mailstrix_timeout} || 10,
        # A /scan endpoint never legitimately 3xx; following one would copy the
        # token header onto the redirect target. Refuse redirects.
        max_redirect => 0,
    );
    my $res = $http->post($url, { headers => \%headers, content => $$msgref });

    if (!$res->{success}) {
        info("strixd: POST %s failed: %s %s", $url, $res->{status} // '?', $res->{reason} // '');
        return undef;
    }

    my $data = eval { JSON::PP::decode_json($res->{content}) };
    if (!$data || ref($data->{matches}) ne 'ARRAY') {
        info("strixd: could not parse verdict JSON: %s", $@ || 'no matches array');
        return undef;
    }

    my $high = $conf->{mailstrix_high_score} // 75;
    for my $m (@{$data->{matches}}) {
        my $name = $m->{rule} // next;
        push @{$pms->{mailstrix_rules}}, $name;
        $pms->{mailstrix_matched} = 1;
        my $score = $m->{meta} && defined $m->{meta}{score} ? $m->{meta}{score} + 0 : undef;
        $pms->{mailstrix_high} = 1 if defined $score && $score >= $high;
    }
    dbg("strixd: http scan matched %d rule(s)%s",
        scalar(@{$pms->{mailstrix_rules}}),
        $pms->{mailstrix_high} ? ' (high)' : '');
    return 1;
}

# _scan_shellout pipes the message to the strix-scan client and reads its exit
# code (0 clean, 1 match). It can't see per-rule score, so MAILSTRIX_HIGH never fires
# in this mode; the matched rule names are parsed from the client's stdout.
# Returns 1 on a completed scan, undef on a spawn/transport failure. $fname
# (optional) is forwarded via the client's -filename flag so name/extension-keyed
# YARA rules fire on attachments.
sub _scan_shellout {
    my ($self, $pms, $conf, $msgref, $fname) = @_;

    my $bin = $conf->{mailstrix_scan_bin};
    if (!defined $bin || !-x $bin) {
        info("strixd: shellout mode: strix-scan binary not executable: %s", $bin // '(unset)');
        return undef;
    }

    my @args = ($bin,
        '-url',     $conf->{mailstrix_url},
        '-timeout', ($conf->{mailstrix_timeout} || 10) . 's',
        # The plugin owns fail-open policy, so make the client surface errors
        # (exit 2) and we decide; -quiet keeps stdout to the MATCH lines.
        '-fail-open=false',
    );
    my $tf = $conf->{mailstrix_token_file};
    push @args, ('-token-file', $tf) if defined $tf && length $tf && -r $tf;
    # Forward the attachment filename so name/extension-keyed YARA rules fire.
    push @args, ('-filename', $fname) if defined $fname && length $fname;

    # Bidirectional spawn: write the message to the child's stdin, read its
    # stdout. (open2 would do, but a manual fork keeps the dependency surface to
    # core modules and lets us _exit cleanly on an exec failure.)
    local $SIG{PIPE} = 'IGNORE';
    my ($pid, $out);
    my ($rd, $wr);
    pipe($rd, my $cwr) or do { info("strixd: pipe: %s", $!); return undef; };
    pipe(my $crd, $wr) or do { info("strixd: pipe: %s", $!); return undef; };
    $pid = fork();
    if (!defined $pid) { info("strixd: fork: %s", $!); return undef; }
    if ($pid == 0) {
        # child
        open(STDIN,  '<&', $crd) or POSIX::_exit(2);
        open(STDOUT, '>&', $cwr) or POSIX::_exit(2);
        close($rd); close($wr); close($crd); close($cwr);
        { exec(@args); }   # only returns on failure
        POSIX::_exit(2);
    }
    # parent
    close($crd); close($cwr);
    print $wr $$msgref;
    close($wr);
    local $/;
    $out = <$rd>;
    close($rd);
    waitpid($pid, 0);
    my $code = $? >> 8;

    if ($code == 0) {
        dbg("strixd: shellout clean");
        return 1;
    } elsif ($code == 1) {
        # MATCH lines look like:  MATCH <rule> (<namespace>)
        for my $line (split /\n/, ($out // '')) {
            if ($line =~ /^MATCH\s+(\S+)/) {
                push @{$pms->{mailstrix_rules}}, $1;
            }
        }
        $pms->{mailstrix_matched} = 1;
        dbg("strixd: shellout matched %d rule(s)", scalar(@{$pms->{mailstrix_rules}}));
        return 1;
    }
    # exit 2 = the client's own error (we set -fail-open=false). Treat as backend error.
    info("strixd: shellout client exit %d", $code);
    return undef;
}

# _message_part_buffers returns an array of [ $decoded_body, $filename_or_undef ]
# pairs, one per leaf MIME part with a non-empty body, in message order.
# find_parts(qr/./, 1) walks leaf parts only (onlyleaves=1); ->decode() undoes
# transfer encoding (base64/quoted-printable) so a base64 attachment is scanned
# as its real bytes. The attachment filename — from Content-Disposition or
# Content-Type — travels alongside the body so HTTP mode can send X-MAILSTRIX-Filename
# and shellout mode can pass -filename, enabling name/extension-keyed YARA rules.
# Returns an empty list when the message has no leaf bodies (caller falls back to
# the pristine message, which has no filename).
sub _message_part_buffers {
    my ($self, $pms) = @_;
    my @out;
    my @parts = eval { $pms->{msg}->find_parts(qr/./, 1) };
    if ($@) {
        info("strixd: find_parts failed: %s", $@);
        return ();
    }
    for my $part (@parts) {
        my $body = eval { $part->decode() };
        next unless defined $body && length $body;
        # Prefer the filename from Content-Disposition (RFC 2183); fall back to
        # the name= parameter of Content-Type.
        my $fname = eval { $part->get_header('content-disposition') };
        if (defined $fname && $fname =~ /filename\*?=(?:"([^"]+)"|(\S+))/i) {
            $fname = $1 // $2;
            $fname =~ s/;\s*$//;    # trim trailing semicolons
        } else {
            $fname = eval { $part->get_header('content-type') };
            if (defined $fname && $fname =~ /name\s*=\s*(?:"([^"]+)"|(\S+))/i) {
                $fname = $1 // $2;
                $fname =~ s/;\s*$//;
            } else {
                $fname = undef;
            }
        }
        # Sanitize: strip directory components and trim whitespace.
        if (defined $fname) {
            $fname =~ s/^\s+|\s+$//g;
            $fname =~ s{.*/}{};     # basename only
            $fname = undef unless length $fname;
        }
        push @out, [ $body, $fname ];
    }
    return @out;
}

# _token reads the shared secret from mailstrix_token_file, trimmed. Returns undef
# when no file is configured (a token-less strixd).
sub _token {
    my ($self, $conf) = @_;
    my $f = $conf->{mailstrix_token_file};
    return undef unless defined $f && length $f;
    open(my $fh, '<', $f) or do { info("strixd: token file %s: %s", $f, $!); return undef; };
    local $/;
    my $t = <$fh>;
    close($fh);
    $t =~ s/^\s+|\s+$//g if defined $t;
    return $t;
}

sub check_mailstrix      { my ($self, $pms) = @_; return $pms->{mailstrix_matched} ? 1 : 0; }
sub check_mailstrix_high { my ($self, $pms) = @_; return $pms->{mailstrix_high}    ? 1 : 0; }
sub check_mailstrix_error { my ($self, $pms) = @_; return $pms->{mailstrix_error}  ? 1 : 0; }

1;
