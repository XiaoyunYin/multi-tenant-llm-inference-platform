import contextlib
import io
import subprocess
import sys
import unittest
from unittest.mock import patch

from inference_platform.command_diagnostics import TAIL_BYTES, checked_process, stderr_tail
from inference_platform.credential_redaction import redact_values
from inference_platform.kind_rollout import run


class CommandDiagnosticsTests(unittest.TestCase):
    def test_real_failure_keeps_bounded_redacted_tail_in_error_and_log(self):
        output = io.StringIO()
        with (
            contextlib.redirect_stderr(output),
            self.assertRaises(subprocess.CalledProcessError) as caught,
        ):
            checked_process(
                [
                    sys.executable,
                    "-c",
                    "import sys;sys.stderr.write('x'*20000+'\\nBearer hidden-bearer --token=hidden-token private-password\\ncompiler sentinel\\n');sys.exit(7)",
                ],
                capture_output=True,
                secrets=("private-password",),
            )
        self.assertEqual(caught.exception.returncode, 7)
        self.assertIn("compiler sentinel", str(caught.exception))
        self.assertIn("compiler sentinel", output.getvalue())
        self.assertLessEqual(len(caught.exception.stderr.encode()), TAIL_BYTES)
        for secret in ("private-password", "hidden-bearer", "hidden-token"):
            self.assertNotIn(secret, str(caught.exception))
            self.assertNotIn(secret, output.getvalue())

    def test_kind_run_preserves_actual_child_stderr_with_inherited_stdout(self):
        with contextlib.redirect_stderr(io.StringIO()) as output:
            with self.assertRaisesRegex(subprocess.CalledProcessError, "build sentinel"):
                run(
                    sys.executable,
                    "-c",
                    "import sys;sys.stderr.write('build sentinel');sys.exit(1)",
                    capture=False,
                )
        self.assertIn("build sentinel", output.getvalue())

    def test_real_registry_and_kubectl_messages_are_preserved(self):
        for message in (
            "denied: Your authorization token has expired. Reauthenticate and try again.",
            "no basic auth credentials",
            "error: You must be logged in to the server (Unauthorized)",
            "User arn:aws:iam::[account-redacted]:role/operator is not authorized to perform: ecr:InitiateLayerUpload",
        ):
            with self.subTest(message=message):
                self.assertEqual(stderr_tail(message, environment={}), message)
        self.assertEqual(
            stderr_tail(
                "arn:aws:iam::123456789012:role/operator is not authorized to perform: ecr:InitiateLayerUpload",
                environment={},
            ),
            "arn:aws:iam::[account-redacted]:role/operator is not authorized to perform: ecr:InitiateLayerUpload",
        )

    def test_value_redaction_keeps_prose_but_removes_every_credential_form(self):
        text = "\n".join(
            (
                "Authorization: Bearer sensitive-bearer note",
                "Authorization: Basic c2VjcmV0OnBhc3N3b3Jk note",
                "Basic c2VjcmV0OnBhc3N3b3Jk",
                "AKIA0000000000000000 ASIA1111111111111111",
                'aws_secret_access_key="secret-key-value"; aws_session_token=session-value',
                '"aws_access_key_id": "identifier-value"',
                "--token=token-value env-password explicit-password",
            )
        )
        result = redact_values(
            text, secrets=("explicit-password",), environment={"DB_PASSWORD": "env-password"}
        )
        for secret in (
            "sensitive-bearer",
            "c2VjcmV0OnBhc3N3b3Jk",
            "AKIA0000000000000000",
            "ASIA1111111111111111",
            "secret-key-value",
            "session-value",
            "identifier-value",
            "token-value",
            "env-password",
            "explicit-password",
        ):
            self.assertNotIn(secret, result)
        self.assertIn("note", result)
        self.assertIn("aws_secret_access_key=", result)

    def test_non_capturing_success_writes_only_safe_bounded_stderr_to_phase_log(self):
        with contextlib.redirect_stderr(io.StringIO()) as log:
            run(
                sys.executable,
                "-c",
                "import sys;sys.stderr.write('x'*20000+'\\nwarning: no basic auth credentials; Bearer private-value')",
                capture=False,
            )
        self.assertIn("warning: no basic auth credentials", log.getvalue())
        self.assertNotIn("private-value", log.getvalue())
        self.assertLessEqual(len(log.getvalue().encode()), TAIL_BYTES + 1)
        with contextlib.redirect_stderr(io.StringIO()) as log:
            run(
                sys.executable,
                "-c",
                "import sys;sys.stderr.write('captured warning')",
                capture=True,
            )
        self.assertEqual(log.getvalue(), "")

    def test_docker_failure_keeps_stdout_and_stderr_with_secrets_removed(self):
        result = subprocess.CompletedProcess(
            ["docker", "push"],
            1,
            b"x" * 20000 + b"layer status Bearer hidden-output",
            b"no basic auth credentials",
        )
        with (
            patch("inference_platform.command_diagnostics.subprocess.run", return_value=result),
            contextlib.redirect_stderr(io.StringIO()) as log,
        ):
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                checked_process(["docker", "push", "fixture"], capture_output=True)
        self.assertIn("layer status", caught.exception.output)
        self.assertIn("no basic auth credentials", str(caught.exception))
        self.assertIn("layer status", log.getvalue())
        self.assertNotIn("hidden-output", log.getvalue())
        self.assertLessEqual(len(caught.exception.output.encode()), TAIL_BYTES)

    def test_success_and_utf8_boundary(self):
        result = checked_process([sys.executable, "-c", "print('success')"], capture_output=True)
        self.assertEqual(result.stdout.strip(), b"success")
        self.assertLessEqual(len(stderr_tail("a" * 20000).encode()), TAIL_BYTES)
        self.assertNotIn("not-exported", stderr_tail("Bearer not-exported"))


if __name__ == "__main__":
    unittest.main()
