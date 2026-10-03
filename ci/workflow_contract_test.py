"""Execute the workflow's classifier and required-check scripts with fixtures."""

import itertools
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml'
APPLICATION_JOBS = ('docker', 'parity-isolation', 'lint')


def jobs():
    """Return top-level job bodies using YAML indentation, not formatting regexes."""
    lines = WORKFLOW.read_text().splitlines(keepends=True)
    jobs_start = lines.index('jobs:\n') + 1
    found = {}
    name = None
    body = []
    for line in lines[jobs_start:]:
        if (line.startswith('  ') and not line.startswith('   ')
                and line.rstrip().endswith(':')):
            if name is not None:
                found[name] = ''.join(body)
            name = line.strip()[:-1]
            body = []
        elif name is not None:
            body.append(line)
    if name is not None:
        found[name] = ''.join(body)
    return found


def script(job):
    """Return the first literal run block, accepting any valid deeper indent."""
    lines = job.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.lstrip() == 'run: |\n':
            parent_indent = len(line) - len(line.lstrip())
            body = []
            for candidate in lines[index + 1:]:
                if candidate.strip():
                    indent = len(candidate) - len(candidate.lstrip())
                    if indent <= parent_indent:
                        break
                body.append(candidate)
            return textwrap.dedent(''.join(body))
    raise AssertionError('workflow job has no literal shell script')


class WorkflowContract(unittest.TestCase):
    def setUp(self):
        self.jobs = jobs()

    def classify(self, paths, event='pull_request', git_status=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / 'paths'
            fixture.write_bytes(b''.join(path.encode() + b'\0' for path in paths))
            output = root / 'output'
            env = dict(os.environ, EVENT_NAME=event, RUNNER_TEMP=directory,
                       GITHUB_OUTPUT=str(output), DIFF_FIXTURE=str(fixture),
                       GIT_STATUS=str(git_status))
            # Execute the shipped shell, and require the real diff's flags:
            # no-renames exposes both sides of code-to-documentation renames.
            fake_git = '''git() {
              test "$*" = 'diff --name-only -z --no-renames HEAD^1 HEAD' || return 99
              cat "$DIFF_FIXTURE"
              return "$GIT_STATUS"
            }
            '''
            result = subprocess.run(  # noqa: S603 - executes the reviewed workflow
                ['/bin/bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c',
                 fake_git + script(self.jobs['changes'])],
                env=env, capture_output=True, text=True, check=False,
            )
            return result.returncode, output.read_text() if output.exists() else ''

    def docker_scope(self, paths, event='pull_request'):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / 'paths'
            fixture.write_text(''.join(f'{path}\n' for path in paths))
            env = dict(os.environ, EVENT_NAME=event, DIFF_FIXTURE=str(fixture))
            fake_commands = '''git() {
              expected="diff --name-only HEAD^1 HEAD -- . :(exclude)ci/**"
              test "$*" = "$expected" || return 99
              while IFS= read -r path; do
                case "$path" in ci/*) ;; *) printf '%s\\n' "$path" ;; esac
              done < "$DIFF_FIXTURE"
            }
            docker() { printf 'docker-args:%s\\n' "$*"; }
            '''
            return subprocess.run(  # noqa: S603 - executes the reviewed workflow
                ['/bin/bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c',
                 fake_commands + script(self.jobs['docker'])],
                env=env, capture_output=True, text=True, check=False,
            )

    def test_docs_only(self):
        for paths in (['README.md'], ['contrib/postfix/README.md', 'docs/usage.md'],
                      ['docs/file with spaces.md', 'docs/line\nbreak.md']):
            with self.subTest(paths=paths):
                self.assertEqual(self.classify(paths), (0, 'application=false\n'))

    def test_application_negative_control(self):
        for paths in (['internal/scan/scan.go'], ['README.md', 'cmd/strixd/main.go'],
                      ['go.mod'], ['go.sum'], ['docker/Dockerfile'],
                      ['.github/workflows/ci.yml'], ['ci/workflow_contract_test.py'],
                      ['internal/scan/testdata/sample.md'],
                      ['internal/testdata/README.md'],
                      ['unknown'],
                      ['README.MD'], ['README.md.go'],
                      ['internal/deleted.go', 'docs/renamed.md'], []):
            with self.subTest(paths=paths):
                self.assertEqual(self.classify(paths), (0, 'application=true\n'))

    def test_release_and_other_triggers_run_application(self):
        for event in ('workflow_call', 'push', ''):
            with self.subTest(event=event):
                # Even an unavailable diff cannot narrow a release caller.
                self.assertEqual(self.classify(['README.md'], event, 1),
                                 (0, 'application=true\n'))

    def test_diff_failure_does_not_publish_a_skip(self):
        status, output = self.classify(['README.md'], git_status=1)
        self.assertNotEqual(status, 0)
        self.assertEqual(output, '')

    def test_docker_changed_scope(self):
        for paths in (['ci/workflow_contract_test.py'], []):
            with self.subTest(paths=paths):
                result = self.docker_scope(paths)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('changed files: <full suite>', result.stdout)
                self.assertIn('CHANGED_FILES=', result.stdout)
                self.assertNotIn('CHANGED_FILES=--changed --', result.stdout)
        result = self.docker_scope(['internal/scan/scan.go'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('CHANGED_FILES=--changed -- internal/scan/scan.go', result.stdout)
        result = self.docker_scope(['internal/scan/scan.go'], event='workflow_call')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('changed files: <full suite>', result.stdout)

    def test_wiring(self):
        self.assertIn('fetch-depth: 2', self.jobs['changes'])
        self.assertIn('application: ${{ steps.scope.outputs.application }}',
                      self.jobs['changes'])
        self.assertIn('run: python3 -B ci/workflow_contract_test.py',
                      self.jobs['changes'])
        for job in APPLICATION_JOBS:
            self.assertIn('needs: changes\n', self.jobs[job])
            self.assertIn("if: ${{ needs.changes.outputs.application == 'true' }}",
                          self.jobs[job])
        self.assertNotIn('needs: changes', self.jobs['scanners'])
        self.assertNotIn('    if:', self.jobs['scanners'])
        aggregate = self.jobs['ci-ok']
        self.assertIn('if: ${{ always() }}', aggregate)
        self.assertIn('needs: [changes, docker, parity-isolation, lint, scanners]',
                      aggregate)
        for name, job in (('CHANGES', 'changes'), ('SCANNERS', 'scanners'),
                          ('DOCKER', 'docker'), ('PARITY', 'parity-isolation'),
                          ('LINT', 'lint')):
            self.assertIn(f'{name}_RESULT: ${{{{ needs.{job}.result }}}}', aggregate)
        self.assertIn('APPLICATION: ${{ needs.changes.outputs.application }}',
                      aggregate)

    def test_required_check_result_matrix(self):
        states = ('success', 'skipped', 'failure', 'cancelled')
        # Include missing/malformed classifier output, and every result state
        # independently in every required job.
        for application in ('true', 'false', '', 'invalid'):
            for results in itertools.product(states, repeat=5):
                env = dict(os.environ, APPLICATION=application)
                env.update(zip(('CHANGES_RESULT', 'SCANNERS_RESULT', 'DOCKER_RESULT',
                                'PARITY_RESULT', 'LINT_RESULT'), results, strict=True))
                expected = 'success' if application == 'true' else 'skipped'
                accepted = (application in ('true', 'false')
                            and results[:2] == ('success', 'success')
                            and results[2:] == (expected,) * 3)
                result = subprocess.run(  # noqa: S603 - reviewed workflow script
                    ['/bin/bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c',
                     script(self.jobs['ci-ok'])],
                    env=env, capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode == 0, accepted,
                                 (application, results, result.stderr))


if __name__ == '__main__':
    unittest.main()
