"""Integration launcher. Run from repository root: python -m vault_cli.

Modules may be merged separately from four existing personal Git branches.
"""
from importlib import import_module

from . import shared  # Set repository module import paths before loading teammates.
from src.key_management.keystore import KeystoreError

TASKS = {
    "1": ("cristian_keys", "Cristian: Key Management (D6)"),
    "2": ("axel_encryption", "Axel: Encrypt & Share File (D2/D3)"),
    "3": ("esteban_signatures", "Esteban: Sign & Verify (D5)"),
    "4": ("fernanda_security", "Fernanda: Security & Recovery (D3/D5/D6)"),
}


def main() -> None:
    print(f"Workspace: {shared.WORKSPACE}")
    while True:
        print("\n========== SECURE VAULT — CONSOLE ==========")
        for option, (_, label) in TASKS.items():
            print(f"{option}. {label}")
        print("0. Exit")
        try:
            option = input("Select an option: ").strip()
            if option == "0":
                print("Goodbye!")
                break
            if option not in TASKS:
                print("Invalid option")
                continue
            module_name = TASKS[option][0]
            try:
                # Lazy loading keeps the launcher usable while teammates merge PRs.
                module = import_module(f".{module_name}", package=__package__)
                module.run()
            except ModuleNotFoundError as exc:
                if exc.name == f"vault_cli.{module_name}":
                    print("[PENDING] This teammate's module has not been merged yet")
                else:
                    print(f"[ERROR] Missing Python dependency: {exc.name}")
            except (ValueError, OSError, TypeError, KeystoreError) as exc:
                print(f"[REJECTED] {type(exc).__name__}: {exc}")
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break


if __name__ == "__main__":
    main()
