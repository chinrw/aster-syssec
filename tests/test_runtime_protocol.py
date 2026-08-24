from __future__ import annotations

import json
import unittest

from aster_syssec.runtime import GuestProtocolError, parse_guest_result


class GuestProtocolTests(unittest.TestCase):
    def test_parses_one_marker_delimited_object_amid_boot_noise(self) -> None:
        expected = {
            "case_id": "pipe-partial-efault-read",
            "exit_kind": "normal",
            "return": -1,
            "errno": 14,
            "first_byte": 65,
            "remaining_return": 2,
            "remaining_errno": 0,
            "remaining_byte_0": 65,
            "remaining_byte_1": 66,
        }
        output = (
            b"Booting Asterinas...\r\n"
            b"SYSSEC_RESULT_BEGIN\r\n"
            + json.dumps(expected, separators=(",", ":")).encode("utf-8")
            + b"\r\nSYSSEC_RESULT_END\r\n"
            b"Power down.\r\n"
        )

        result = parse_guest_result(output, max_output_bytes=64 * 1024)

        self.assertEqual(result, expected)

    def test_rejects_output_larger_than_the_configured_limit(self) -> None:
        with self.assertRaises(GuestProtocolError) as raised:
            parse_guest_result(b"123456789", max_output_bytes=8)

        self.assertEqual(raised.exception.code, "output-too-large")

    def test_rejects_non_utf8_output(self) -> None:
        with self.assertRaises(GuestProtocolError) as raised:
            parse_guest_result(b"boot: \xff", max_output_bytes=64 * 1024)

        self.assertEqual(raised.exception.code, "non-utf8")

    def test_rejects_output_without_a_begin_marker(self) -> None:
        output = b'{"case_id":"case","exit_kind":"normal"}\nSYSSEC_RESULT_END\n'

        with self.assertRaises(GuestProtocolError) as raised:
            parse_guest_result(output, max_output_bytes=64 * 1024)

        self.assertEqual(raised.exception.code, "missing-begin-marker")

    def test_rejects_output_without_an_end_marker(self) -> None:
        output = b'SYSSEC_RESULT_BEGIN\n{"case_id":"case","exit_kind":"normal"}\n'

        with self.assertRaises(GuestProtocolError) as raised:
            parse_guest_result(output, max_output_bytes=64 * 1024)

        self.assertEqual(raised.exception.code, "missing-end-marker")

    def test_rejects_duplicate_markers(self) -> None:
        cases = (
            (
                (
                    b"SYSSEC_RESULT_BEGIN\nSYSSEC_RESULT_BEGIN\n"
                    b'{"case_id":"case","exit_kind":"normal"}\n'
                    b"SYSSEC_RESULT_END\n"
                ),
                "duplicate-begin-marker",
            ),
            (
                (
                    b"SYSSEC_RESULT_BEGIN\n"
                    b'{"case_id":"case","exit_kind":"normal"}\n'
                    b"SYSSEC_RESULT_END\nSYSSEC_RESULT_END\n"
                ),
                "duplicate-end-marker",
            ),
        )

        for output, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(GuestProtocolError) as raised:
                    parse_guest_result(output, max_output_bytes=64 * 1024)

                self.assertEqual(raised.exception.code, code)

    def test_rejects_an_end_marker_before_the_begin_marker(self) -> None:
        output = (
            b"SYSSEC_RESULT_END\nSYSSEC_RESULT_BEGIN\n"
            b'{"case_id":"case","exit_kind":"normal"}\n'
        )

        with self.assertRaises(GuestProtocolError) as raised:
            parse_guest_result(output, max_output_bytes=64 * 1024)

        self.assertEqual(raised.exception.code, "invalid-marker-order")

    def test_rejects_truncated_json(self) -> None:
        output = (
            b"SYSSEC_RESULT_BEGIN\n"
            b'{"case_id":"case","exit_kind":"normal"\n'
            b"SYSSEC_RESULT_END\n"
        )

        with self.assertRaises(GuestProtocolError) as raised:
            parse_guest_result(output, max_output_bytes=64 * 1024)

        self.assertEqual(raised.exception.code, "invalid-json")

    def test_rejects_nonstandard_json_numbers(self) -> None:
        output = (
            b"SYSSEC_RESULT_BEGIN\n"
            b'{"case_id":"case","exit_kind":"normal","value":NaN}\n'
            b"SYSSEC_RESULT_END\n"
        )

        with self.assertRaises(GuestProtocolError) as raised:
            parse_guest_result(output, max_output_bytes=64 * 1024)

        self.assertEqual(raised.exception.code, "invalid-json")

    def test_rejects_a_second_json_object_between_the_markers(self) -> None:
        output = (
            b"SYSSEC_RESULT_BEGIN\n"
            b'{"case_id":"case","exit_kind":"normal"}\n'
            b'{"case_id":"second","exit_kind":"normal"}\n'
            b"SYSSEC_RESULT_END\n"
        )

        with self.assertRaises(GuestProtocolError) as raised:
            parse_guest_result(output, max_output_bytes=64 * 1024)

        self.assertEqual(raised.exception.code, "extra-result-content")

    def test_rejects_a_non_object_json_value(self) -> None:
        output = b"SYSSEC_RESULT_BEGIN\n[]\nSYSSEC_RESULT_END\n"

        with self.assertRaises(GuestProtocolError) as raised:
            parse_guest_result(output, max_output_bytes=64 * 1024)

        self.assertEqual(raised.exception.code, "non-object")

    def test_rejects_an_object_that_does_not_match_the_guest_schema(self) -> None:
        output = b'SYSSEC_RESULT_BEGIN\n{"case_id":"case"}\nSYSSEC_RESULT_END\n'

        with self.assertRaises(GuestProtocolError) as raised:
            parse_guest_result(output, max_output_bytes=64 * 1024)

        self.assertEqual(raised.exception.code, "invalid-guest-result")
