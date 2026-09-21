import contextlib
import io
import json
import unittest

import acsd
import cli_output


class TestCLIOutputContract(unittest.TestCase):
    def test_exit_code_contract_is_stable_and_reexported(self):
        expected = (0, 1, 2, 3, 4, 5)
        actual = (
            cli_output.EXIT_OK,
            cli_output.EXIT_VERIFY_FAIL,
            cli_output.EXIT_USAGE,
            cli_output.EXIT_STATE_CONFLICT,
            cli_output.EXIT_EXTERNAL,
            cli_output.EXIT_INCOMPLETE,
        )
        self.assertEqual(actual, expected)
        self.assertEqual(acsd.EXIT_OK, cli_output.EXIT_OK)
        self.assertEqual(acsd.EXIT_VERIFY_FAIL, cli_output.EXIT_VERIFY_FAIL)

    def test_json_output_preserves_machine_contract(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli_output.emit_json("verify", 1, "TAMPERED", {"error_code": "X"})
        self.assertEqual(
            json.loads(output.getvalue()),
            {
                "command": "verify",
                "status": "error",
                "exit_code": 1,
                "message": "TAMPERED",
                "data": {"error_code": "X"},
            },
        )

    def test_human_output_preserves_line_format(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli_output.emit_human("inspect", 0, "inspected", {"state": "ready"})
        self.assertEqual(
            output.getvalue(),
            "inspect: inspected (exit 0)\n  state: ready\n",
        )


if __name__ == "__main__":
    unittest.main()
