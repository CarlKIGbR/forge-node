"""Entry point of the release zipapp: `python3 -I forge-node.pyz <command> ...` (agent run | privd | privctl ... | opworker ... | probe ... | doctor; `release build|sign` only from a source checkout). One file, one dispatcher: the
units, the transient op/probe units and the owner's shell all start the same artifact, so the version that runs is always the version that is `current`."""
import sys


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        sys.stderr.write("usage: forge-node.pyz agent|privd|privctl|opworker|probe|doctor|release ...\n")
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "agent":
        from .agent.__main__ import main as agent_main
        return agent_main(rest)
    if cmd == "privd":
        from .privd.main import run_privd
        return run_privd()
    if cmd == "privctl":
        from .privd.main import run_privctl
        return run_privctl(rest)
    if cmd == "opworker":
        try:
            from .privd.opworker import main as op_main
        except ImportError:
            sys.stderr.write("this release (profile t0) contains no op worker\n")
            return 2
        return op_main(rest)
    if cmd == "probe":
        from .t0.probe_main import production_main
        return production_main(rest)
    if cmd == "doctor":
        from .doctor import main as doctor_main
        return doctor_main(rest)
    if cmd == "release":
        try:
            from .release.cli import main as release_main
        except ImportError:
            sys.stderr.write("release build/sign run from a source checkout (PYTHONPATH=src python3 -m forge_node.cli release ...), not from an installed artifact\n")
            return 2
        return release_main(rest)
    sys.stderr.write(f"unknown command {cmd!r}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
