from rich.console import Console

from strix.interface import update_check


def test_update_checks_are_disabled() -> None:
    update_check.start_background_check()
    assert update_check.get_available_update() is None
    assert update_check.prompt_update_if_available(Console()) is False
    assert update_check.is_binary_install() is False


def test_self_update_is_disabled() -> None:
    assert update_check.self_update(Console()) is False
    assert update_check.get_upgrade_command() == "git fetch upstream && git merge --ff-only upstream/main"
