import logging
import sys

import pytest

from nexus_intelligence import __main__ as cli


def test_bulk_flags_are_unambiguous():
    parser = cli._build_parser()

    with pytest.raises(SystemExit):
        cli._validate_args(parser.parse_args(["example.test", "--file", "targets.txt"]), parser)

    with pytest.raises(SystemExit):
        cli._validate_args(parser.parse_args(["--correlate"]), parser)


@pytest.mark.asyncio
async def test_missing_bulk_file_returns_cli_error(monkeypatch, tmp_path):
    missing = tmp_path / "missing-targets.txt"
    monkeypatch.setattr(sys, "argv", ["nexus-intel", "--file", str(missing)])
    monkeypatch.setattr(cli, "setup_logger", lambda _verbose: logging.getLogger("nexus-cli-test"))

    assert await cli.entrypoint() == 2


def test_main_propagates_async_exit_code(monkeypatch):
    async def fake_entrypoint():
        return 7

    monkeypatch.setattr(cli, "entrypoint", fake_entrypoint)
    assert cli.main() == 7
