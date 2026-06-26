# Mail::SpamAssassin::Plugin::Yarad — scan each message through a central yarad.
#
# Project:  https://github.com/eilandert/rspamd-yarad
# Write-up: https://deb.myguard.nl/2026/06/yara-malware-scanning-rspamd-yarad/
#
# This is the SpamAssassin sibling of the rspamd `yara.lua` plugin and the
# Dovecot/Sieve `yarad-scan` client: it hands the raw message to a central
# `yarad serve` and turns the YARA verdict into SpamAssassin rule hits, so the
# malware signal lands in the spam score alongside everything else.
#
# Two modes (yarad_mode):
#
#   http      — the plugin POSTs the message to <yarad_url>/scan itself with the
#               core Perl HTTP::Tiny (no extra binary on the box) and parses the
#               JSON verdict. This is the RICH mode: it sees every matched rule's
#               name, namespace, tags and meta.score, so it can fire graduated
#               symbols (YARAD on any hit, YARAD_HIGH on a high-score hit) and
#               expose the matched rule names as a tag for headers/logging.
#
#   shellout  — the plugin pipes the message to the lean, CGO-free `yarad-scan`
#               client (the same binary the Sieve path uses) and reads its exit
#               code: 0 clean, 1 match. Hit/no-hit only — no per-rule score — but
#               it reuses one audited client and one fail-open code path. Use this
#               when you already deploy `yarad-scan` and want a single transport.
#
# Both modes FAIL OPEN by default (yarad_fail_open 1): a scanner outage, timeout
# or transport error is treated as CLEAN so a down backend never tags every
# message. Set yarad_fail_open 0 to make a backend failure fire YARAD_ERROR
# instead (useful on a host where a silent miss is worse than a visible error).
#
# Install: see README.md in this directory. In short — drop this file somewhere
# SpamAssassin can read, point a `loadplugin` line at it (yarad.pre), and ship
# yarad.cf with the rule scores.

package Mail::SpamAssassin::Plugin::Yarad;

use strict;
use warnings;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use POSIX ();

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
    my ($class, $mailsa) = @_;
    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsa);
    bless($self, $class);

    # The eval rules this plugin answers. Defined (with scores) in yarad.cf.
    $self->register_eval_rule('check_yarad');           # any YARA rule matched
    $self->register_eval_rule('check_yarad_high');      # a high meta.score match (http mode only)
    $self->register_eval_rule('check_yarad_error');     # backend unreachable and fail-open off

    $self->set_config($mailsa->{conf});
    return $self;
}

sub set_config {
    my ($self, $conf) = @_;
    my @cmds;

    # Transport: 'http' (plugin POSTs itself, rich verdict) or 'shellout'
    # (pipe to the yarad-scan client, hit/no-hit only).
    push @cmds, {
        setting => 'yarad_mode',
        default => 'http',
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    };

    # http mode: base URL of the central `yarad serve`.
    push @cmds, {
        setting => 'yarad_url',
        default => 'http://yarad.internal:8079',
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    };

    # Shared secret. Read from a file so it never appears in a process list or
    # this config. Empty (the default) = talk to a token-less yarad.
    push @cmds, {
        setting => 'yarad_token_file',
        default => '',
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    };

    # shellout mode: the lean client binary (same one the Sieve path uses).
    push @cmds, {
        setting => 'yarad_scan_bin',
        default => '/usr/local/bin/yarad-scan',
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    };

    # Per-request timeout, seconds.
    push @cmds, {
        setting => 'yarad_timeout',
        default => 10,
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    };

    # Don't send messages larger than this many bytes (matches the yarad-scan
    # client's -max-body default of 8 MiB). 0 = no cap.
    push @cmds, {
        setting => 'yarad_max_size',
        default => 8 * 1024 * 1024,
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    };

    # Fail open (1, default): a backend error is treated as clean. 0: a backend
    # error fires YARAD_ERROR.
    push @cmds, {
        setting => 'yarad_fail_open',
        default => 1,
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
    };

    # http mode: a matched rule whose meta.score is >= this (0..100) also fires
    # check_yarad_high, so a confident malware hit can score harder than a soft one.
    push @cmds, {
        setting => 'yarad_high_score',
        default => 75,
        type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
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
    $pms->{yarad_matched} = 0;
    $pms->{yarad_high}    = 0;
    $pms->{yarad_error}   = 0;
    $pms->{yarad_rules}   = [];

    my $msg = $pms->{msg}->get_pristine();
    my $max = $conf->{yarad_max_size} || 0;
    if ($max > 0 && length($msg) > $max) {
        dbg("yarad: message %d bytes > yarad_max_size %d, not scanning", length($msg), $max);
        return;
    }

    my $mode = lc($conf->{yarad_mode} || 'http');
    my $ok;
    if ($mode eq 'shellout') {
        $ok = $self->_scan_shellout($pms, $conf, \$msg);
    } else {
        $ok = $self->_scan_http($pms, $conf, \$msg);
    }

    # $ok is undef on a backend error. Honour fail-open.
    if (!defined $ok) {
        if ($conf->{yarad_fail_open}) {
            dbg("yarad: backend error, failing open (clean)");
        } else {
            $pms->{yarad_error} = 1;
        }
        return;
    }

    if (@{$pms->{yarad_rules}}) {
        # Expose the matched rule names for headers / logging: add_header ... _YARADRULES_
        $pms->set_tag('YARADRULES', join(',', @{$pms->{yarad_rules}}));
    }
}

# _scan_http POSTs the message to <yarad_url>/scan and fills the cache from the
# JSON verdict. Returns 1 on a completed scan (match or clean), undef on a
# transport/HTTP error.
sub _scan_http {
    my ($self, $pms, $conf, $msgref) = @_;

    my $have = eval { require HTTP::Tiny; require JSON::PP; 1 };
    if (!$have) {
        info("yarad: http mode needs HTTP::Tiny + JSON::PP (core since Perl 5.14); error: %s", $@);
        return undef;
    }

    my $url = $conf->{yarad_url};
    $url =~ s{/+$}{};
    $url .= '/scan';

    my %headers = (
        'Content-Type' => 'application/octet-stream',
        'Accept'       => 'application/json',
        'User-Agent'   => 'spamassassin-yarad',
    );
    my $tok = $self->_token($conf);
    $headers{'X-YARAD-Token'} = $tok if defined $tok && length $tok;

    my $http = HTTP::Tiny->new(
        timeout => $conf->{yarad_timeout} || 10,
        # A /scan endpoint never legitimately 3xx; following one would copy the
        # token header onto the redirect target. Refuse redirects.
        max_redirect => 0,
    );
    my $res = $http->post($url, { headers => \%headers, content => $$msgref });

    if (!$res->{success}) {
        info("yarad: POST %s failed: %s %s", $url, $res->{status} // '?', $res->{reason} // '');
        return undef;
    }

    my $data = eval { JSON::PP::decode_json($res->{content}) };
    if (!$data || ref($data->{matches}) ne 'ARRAY') {
        info("yarad: could not parse verdict JSON: %s", $@ || 'no matches array');
        return undef;
    }

    my $high = $conf->{yarad_high_score} // 75;
    for my $m (@{$data->{matches}}) {
        my $name = $m->{rule} // next;
        push @{$pms->{yarad_rules}}, $name;
        $pms->{yarad_matched} = 1;
        my $score = $m->{meta} && defined $m->{meta}{score} ? $m->{meta}{score} + 0 : undef;
        $pms->{yarad_high} = 1 if defined $score && $score >= $high;
    }
    dbg("yarad: http scan matched %d rule(s)%s",
        scalar(@{$pms->{yarad_rules}}),
        $pms->{yarad_high} ? ' (high)' : '');
    return 1;
}

# _scan_shellout pipes the message to the yarad-scan client and reads its exit
# code (0 clean, 1 match). It can't see per-rule score, so YARAD_HIGH never fires
# in this mode; the matched rule names are parsed from the client's stdout.
# Returns 1 on a completed scan, undef on a spawn/transport failure.
sub _scan_shellout {
    my ($self, $pms, $conf, $msgref) = @_;

    my $bin = $conf->{yarad_scan_bin};
    if (!defined $bin || !-x $bin) {
        info("yarad: shellout mode: yarad-scan binary not executable: %s", $bin // '(unset)');
        return undef;
    }

    my @args = ($bin,
        '-url',     $conf->{yarad_url},
        '-timeout', ($conf->{yarad_timeout} || 10) . 's',
        # The plugin owns fail-open policy, so make the client surface errors
        # (exit 2) and we decide; -quiet keeps stdout to the MATCH lines.
        '-fail-open=false',
    );
    my $tf = $conf->{yarad_token_file};
    push @args, ('-token-file', $tf) if defined $tf && length $tf && -r $tf;

    # Bidirectional spawn: write the message to the child's stdin, read its
    # stdout. (open2 would do, but a manual fork keeps the dependency surface to
    # core modules and lets us _exit cleanly on an exec failure.)
    local $SIG{PIPE} = 'IGNORE';
    my ($pid, $out);
    my ($rd, $wr);
    pipe($rd, my $cwr) or do { info("yarad: pipe: %s", $!); return undef; };
    pipe(my $crd, $wr) or do { info("yarad: pipe: %s", $!); return undef; };
    $pid = fork();
    if (!defined $pid) { info("yarad: fork: %s", $!); return undef; }
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
        dbg("yarad: shellout clean");
        return 1;
    } elsif ($code == 1) {
        # MATCH lines look like:  MATCH <rule> (<namespace>)
        for my $line (split /\n/, ($out // '')) {
            if ($line =~ /^MATCH\s+(\S+)/) {
                push @{$pms->{yarad_rules}}, $1;
            }
        }
        $pms->{yarad_matched} = 1;
        dbg("yarad: shellout matched %d rule(s)", scalar(@{$pms->{yarad_rules}}));
        return 1;
    }
    # exit 2 = the client's own error (we set -fail-open=false). Treat as backend error.
    info("yarad: shellout client exit %d", $code);
    return undef;
}

# _token reads the shared secret from yarad_token_file, trimmed. Returns undef
# when no file is configured (a token-less yarad).
sub _token {
    my ($self, $conf) = @_;
    my $f = $conf->{yarad_token_file};
    return undef unless defined $f && length $f;
    open(my $fh, '<', $f) or do { info("yarad: token file %s: %s", $f, $!); return undef; };
    local $/;
    my $t = <$fh>;
    close($fh);
    $t =~ s/^\s+|\s+$//g if defined $t;
    return $t;
}

sub check_yarad      { my ($self, $pms) = @_; return $pms->{yarad_matched} ? 1 : 0; }
sub check_yarad_high { my ($self, $pms) = @_; return $pms->{yarad_high}    ? 1 : 0; }
sub check_yarad_error { my ($self, $pms) = @_; return $pms->{yarad_error}  ? 1 : 0; }

1;
