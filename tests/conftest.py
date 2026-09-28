
import pytest


@pytest.fixture
def config_home(tmp_path, monkeypatch):
    """Point Locksmith's config folder at a temp dir on any platform."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path))
    return tmp_path


@pytest.fixture
def needs_symlinks(tmp_path):
    """Skip where the user cannot create symlinks (Windows without Developer Mode)."""
    probe = tmp_path / ".symlink-probe"
    try:
        probe.symlink_to(tmp_path)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available to this user")
    probe.unlink()
