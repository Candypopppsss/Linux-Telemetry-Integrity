import errno
from pathlib import Path
import subprocess
import tempfile
import unittest

from validate import validate


class ValidationTests(unittest.TestCase):
    def test_success(self):
        self.assertEqual(validate("LTI_ENTER 10 10\nLTI_EXEC 10 10\nLTI_RESULT success\n", 0)["completed_execs"], 1)

    def test_failed_exec(self):
        self.assertEqual(validate("LTI_ENTER 10 10\nLTI_EXIT 10 10 -8\nLTI_RESULT errno=8\n", 8)["failed_attempts"], 1)

    def test_missing_duplicate_mismatched_and_wrong_return(self):
        for trace in ["", "LTI_ENTER 10 10\nLTI_ENTER 10 10\nLTI_EXIT 10 10 -8\n",
                      "LTI_ENTER 10 10\nLTI_EXIT 11 11 -8\nLTI_RESULT errno=8\n",
                      "LTI_ENTER 10 10\nLTI_EXIT 10 10 -2\nLTI_RESULT errno=8\n",
                      "LTI_ENTER 10\n"]:
            with self.subTest(trace=trace), self.assertRaises(ValueError):
                validate(trace, 8)

    def test_unprivileged_workload(self):
        source = Path(__file__).resolve().parents[1] / "proof_of_concept/attempt.c"
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "attempt"
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)], check=True)
            invalid = Path(directory) / "invalid"
            invalid.write_text("LTI invalid executable image\n")
            invalid.chmod(0o700)
            for target, error, marker in [(binary, 0, "success"), (invalid, errno.ENOEXEC, "errno=8"),
                                          (Path(directory) / "absent", errno.ENOENT, "errno=2")]:
                result = subprocess.run([str(binary), str(target), str(error)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "LTI_RESULT " + marker)


if __name__ == "__main__":
    unittest.main()
