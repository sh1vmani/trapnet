import pytest
from trapnet.config import Config


def test_load_default():
    config = Config.load_default()
    assert len(config.services) == 15
    assert all(svc.enabled for svc in config.services.values())


def test_load_missing_file():
    with pytest.raises(ValueError, match="not found"):
        Config.load("this_file_does_not_exist.yml")


def test_port_validation(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("services:\n  ssh:\n    enabled: true\n    port: 99999\n")
    with pytest.raises(ValueError):
        Config.load(str(bad))


def test_dashboard_defaults():
    config = Config.load_default()
    assert config.dashboard.host == "127.0.0.1"
    assert config.dashboard.port == 5000
