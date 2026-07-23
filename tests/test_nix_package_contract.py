from pathlib import Path


ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "nix-packages.yml"


def test_package_build_refuses_implicit_lock_updates() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    build = workflow.split('output="$(nix build \\\n', 1)[1].split(')"', 1)[0]

    assert "--no-update-lock-file" in build


if __name__ == "__main__":
    test_package_build_refuses_implicit_lock_updates()
