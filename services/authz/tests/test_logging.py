import json
import logging
import unittest

from ..telemetry.logging import JsonFormatter


class JsonFormatterIdentityFieldsTests(unittest.TestCase):
    """Every structured log line carries fixed service/environment
    identity fields (see telemetry/logging.py's module docstring) so an
    authorize decision here can be traced alongside bedrock-gateway-app's
    own request logs without already knowing which log group either
    came from."""

    def test_service_and_environment_are_in_every_line(self):
        formatter = JsonFormatter(service="platform-authz-service", environment="dev")
        record = logging.LogRecord(
            name="gateway-dev-authz", level=logging.INFO, pathname="", lineno=0,
            msg="authorize decision", args=(), exc_info=None,
        )

        line = json.loads(formatter.format(record))

        self.assertEqual(line["service"], "platform-authz-service")
        self.assertEqual(line["environment"], "dev")

    def test_defaults_to_empty_string_when_unconfigured(self):
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="gateway-dev-authz", level=logging.INFO, pathname="", lineno=0,
            msg="x", args=(), exc_info=None,
        )

        line = json.loads(formatter.format(record))

        self.assertEqual(line["service"], "")
        self.assertEqual(line["environment"], "")


if __name__ == "__main__":
    unittest.main()
