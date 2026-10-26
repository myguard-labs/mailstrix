#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;
our $wait_fault;
BEGIN {
    # Reap the actual owned child even while injecting a failed wait result.
    *CORE::GLOBAL::waitpid = sub {
        my ($pid, $flags) = @_;
        my $result = CORE::waitpid($pid, $flags);
        if ($main::wait_fault) {
            $? = $main::wait_fault eq 'status' ? -1 : 0;
            return $main::wait_fault eq 'status' ? $result : -1;
        }
        return $result;
    };
}
require "$FindBin::Bin/../contrib/spamassassin/Mailstrix.pm";  ## no critic (Modules::RequireBarewordIncludes) - shipped filename differs from package path
{
    package ChildStatusMessage;
    sub get_pristine { return 'message'; }
    package ChildStatusPMS;
    sub set_tag { return; }
}
my $self = bless {}, 'Mail::SpamAssassin::Plugin::Mailstrix';
my $dir = tempdir(CLEANUP => 1);
pipe(my $bystander_rd, my $bystander_wr) or die $!;
my $bystander = fork();
die $! unless defined $bystander;
if (!$bystander) {
    close $bystander_wr;
    my $unused = <$bystander_rd>;
    POSIX::_exit(0);
}
close $bystander_rd;
for my $case (
    ['clean', 'exit 0', 1, 0],
    ['match', 'print "MATCH Evil (local)\n"; exit 1', 1, 1],
    ['error', 'exit 2', undef, 0],
    ['term', 'kill "TERM", $$; exit 99', undef, 0],
    ['kill', 'kill "KILL", $$; exit 99', undef, 0],
    ['waiterror', 'exit 0', undef, 0, 'result'],
    ['invalidstatus', 'exit 0', undef, 0, 'status'],
) {
    my ($name, $body, $complete, $matched, $fault) = @$case;
    subtest "child-status-$name" => sub {
        my $bin = "$dir/$name";
        open(my $fh, '>', $bin) or die $!;
        print $fh "#!$^X\nlocal \$/; my \$input = <STDIN>; $body;\n";
        close $fh;
        chmod 0755, $bin;
        my $conf = { mailstrix_mode => 'shellout', mailstrix_scan_bin => $bin,
                     mailstrix_url => 'http://unused', mailstrix_timeout => 5 };
        my $pms = { mailstrix_rules => [], mailstrix_matched => 0 };
        local $wait_fault = $fault;
        my $ok = $self->_scan_shellout($pms, $conf, \(my $msg = 'message'));
        is($ok, $complete, 'abnormal wait or signal never completes a scan');
        is($pms->{mailstrix_matched}, $matched, 'match state retained');
        is_deeply($pms->{mailstrix_rules}, $matched ? ['Evil'] : [], 'rules retained');
        for my $fail_open (0, 1) {
            my $state = bless { conf => { %$conf, mailstrix_fail_open => $fail_open },
                                msg => bless({}, 'ChildStatusMessage') }, 'ChildStatusPMS';
            $self->parsed_metadata({ permsgstatus => $state });
            is($state->{mailstrix_error}, !$complete && !$fail_open ? 1 : 0,
               "configured error policy fail_open=$fail_open");
            is($state->{mailstrix_matched}, $matched, 'policy preserves detection');
        }
    };
}
is(CORE::waitpid($bystander, 1), 0, 'unrelated bystander survived signal controls');
close $bystander_wr;
is(CORE::waitpid($bystander, 0), $bystander, 'bystander reaped after normal EOF');
is($?, 0, 'bystander exited normally');
done_testing();
