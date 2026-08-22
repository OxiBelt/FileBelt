#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Create and operate bounded local FileBelt development deployments."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from development.backend import Backend
    from development.diagnostics import diagnostic_directory, scrub, secret_values, write_failure
    from development.model import (
        ConfigurationError,
        DevelopmentConfiguration,
        ROOT,
        Session,
        development_root,
        load_configuration,
        prepare_root,
        session_directory,
        session_manifest,
        validate_session_name,
    )
    from development.runner import CommandFailure, Runner
else:
    from .backend import Backend
    from .diagnostics import diagnostic_directory, scrub, secret_values, write_failure
    from .model import (
        ConfigurationError,
        DevelopmentConfiguration,
        ROOT,
        Session,
        development_root,
        load_configuration,
        prepare_root,
        session_directory,
        session_manifest,
        validate_session_name,
    )
    from .runner import CommandFailure, Runner


def backend_for(topology: str, work_dir: Path, runner: Runner) -> Backend:
    if topology == "compose":
        if __package__ in {None, ""}:
            from development.compose_backend import ComposeBackend
        else:
            from .compose_backend import ComposeBackend

        return ComposeBackend(ROOT, work_dir, runner)
    if topology == "minikube":
        if __package__ in {None, ""}:
            from development.minikube_backend import MinikubeBackend
        else:
            from .minikube_backend import MinikubeBackend

        return MinikubeBackend(ROOT, work_dir, runner)
    raise ConfigurationError("session topology is unsupported")


def source_revision(runner: Runner) -> str:
    revision = runner.run(("git", "rev-parse", "HEAD")).stdout.decode().strip()
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise ConfigurationError("repository HEAD is not an exact Git revision")
    return revision


def remove_session_directory(root: Path, name: str) -> None:
    sessions = root / "sessions"
    if sessions.is_symlink() or not sessions.is_dir():
        raise ConfigurationError("development sessions directory is unsafe")
    sessions = sessions.resolve()
    target = session_directory(root, name)
    if target.is_symlink() or target.resolve() != sessions / validate_session_name(name):
        raise ConfigurationError("refusing unsafe session cleanup target")
    if target.exists():
        shutil.rmtree(target)


def load_session(root: Path, name: str) -> tuple[Session, Path]:
    validate_session_name(name)
    work_dir = session_directory(root, name)
    if work_dir.is_symlink() or not work_dir.is_dir():
        raise ConfigurationError("development session directory is unavailable or unsafe")
    session = Session.load(session_manifest(root, name))
    if session.name != name:
        raise ConfigurationError("session manifest name does not match its owned directory")
    return session, work_dir


def failure_bytes(error: BaseException) -> bytes:
    if isinstance(error, CommandFailure):
        return error.stdout + b"\n" + error.stderr
    return f"{type(error).__name__}: {error}\n".encode("utf-8", errors="replace")


def retain_failure(
    root: Path,
    session: Session,
    work_dir: Path,
    backend: Backend,
    error: BaseException,
) -> Path:
    destination = diagnostic_directory(root, session.name)
    secrets = secret_values(work_dir)
    write_failure(destination, "failure", failure_bytes(error), secrets)
    try:
        for name, data in backend.diagnose(session).items():
            if not name.replace("-", "").isalnum():
                continue
            write_failure(destination, name, data, secrets)
    except BaseException as diagnostic_error:  # diagnostics must not mask the original failure
        write_failure(destination, "diagnostics-failure", failure_bytes(diagnostic_error), secrets)
    return destination


def command_up(arguments: argparse.Namespace, root: Path, runner: Runner) -> int:
    name = validate_session_name(arguments.name)
    configuration = load_configuration(arguments.config)
    revision = source_revision(runner)
    work_dir = session_directory(root, name)
    if work_dir.exists():
        raise ConfigurationError(f"development session already exists: {name}")
    work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    work_dir.chmod(0o700)
    session = Session.create(name, arguments.topology, revision, configuration)
    manifest = session_manifest(root, name)
    session.save(manifest)
    backend = backend_for(session.topology, work_dir, runner)
    try:
        backend.up(session, configuration)
        if session.phase == "creating":
            session.phase = "running"
        session.save(manifest)
    except BaseException as error:
        session.phase = "failed"
        session.save(manifest)
        diagnostics = retain_failure(root, session, work_dir, backend, error)
        try:
            backend.down(session)
            remove_session_directory(root, name)
        except BaseException as cleanup_error:
            session.phase = "cleanup-failed"
            session.qualification["cleanupError"] = type(cleanup_error).__name__
            session.save(manifest)
            write_failure(diagnostics, "cleanup-failure", failure_bytes(cleanup_error), secret_values(work_dir))
        raise RuntimeError(f"deployment failed; scrubbed diagnostics: {diagnostics}") from error
    result = {
        "accepted": False,
        "name": session.name,
        "phase": session.phase,
        "qualification": session.qualification,
        "sourceRevision": session.source_revision,
        "topology": session.topology,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def command_list(root: Path) -> int:
    rows: list[dict[str, object]] = []
    sessions = root / "sessions"
    if sessions.is_dir() and not sessions.is_symlink():
        for path in sorted(sessions.iterdir()):
            if path.is_symlink() or not path.is_dir():
                continue
            try:
                session = Session.load(path / "session.json")
            except (ConfigurationError, json.JSONDecodeError):
                rows.append({"name": path.name, "phase": "invalid", "accepted": False})
                continue
            rows.append(
                {
                    "accepted": False,
                    "createdAt": session.created_at,
                    "name": session.name,
                    "phase": session.phase,
                    "topology": session.topology,
                }
            )
    print(json.dumps(rows, indent=2, sort_keys=True))
    return 0


def command_status(arguments: argparse.Namespace, root: Path, runner: Runner) -> int:
    session, work_dir = load_session(root, arguments.name)
    backend = backend_for(session.topology, work_dir, runner)
    backend_status = backend.status(session)
    result = {
        "accepted": False,
        "backend": backend_status,
        "createdAt": session.created_at,
        "features": session.qualification.get("features", []),
        "name": session.name,
        "phase": session.phase,
        "sourceRevision": session.source_revision,
        "topology": session.topology,
    }
    if arguments.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{session.name}: {session.phase} ({session.topology}); qualification accepted=false")
        print(json.dumps(backend_status, indent=2, sort_keys=True))
    return 0


def command_logs(arguments: argparse.Namespace, root: Path, runner: Runner) -> int:
    session, work_dir = load_session(root, arguments.name)
    backend = backend_for(session.topology, work_dir, runner)
    data = backend.logs(session, arguments.component, arguments.tail)
    sys.stdout.buffer.write(scrub(data, secret_values(work_dir)))
    if data and not data.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    return 0


def command_restart(arguments: argparse.Namespace, root: Path, runner: Runner) -> int:
    session, work_dir = load_session(root, arguments.name)
    backend_for(session.topology, work_dir, runner).restart(session, arguments.component)
    print(f"restarted {arguments.component} in {session.name}")
    return 0


def command_diagnose(arguments: argparse.Namespace, root: Path, runner: Runner) -> int:
    session, work_dir = load_session(root, arguments.name)
    backend = backend_for(session.topology, work_dir, runner)
    secrets = secret_values(work_dir)
    for name, data in backend.diagnose(session).items():
        print(f"[{name}]")
        sys.stdout.flush()
        sys.stdout.buffer.write(scrub(data, secrets))
        if data and not data.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
    return 0


def command_port_forward(arguments: argparse.Namespace, root: Path, runner: Runner) -> int:
    if not 1024 <= arguments.port <= 65535:
        raise ConfigurationError("port must be between 1024 and 65535")
    session, work_dir = load_session(root, arguments.name)
    if session.topology == "minikube" and session.phase == "quiesced":
        raise ConfigurationError("Minikube helper has no serving endpoint while quiesced")
    print(
        f"preparing https://filebelt.localhost:{arguments.port}/ on IPv4 loopback; "
        "qualification accepted=false"
    )
    sys.stdout.flush()
    return backend_for(session.topology, work_dir, runner).port_forward(session, arguments.port)


def command_down(arguments: argparse.Namespace, root: Path, runner: Runner) -> int:
    session, work_dir = load_session(root, arguments.name)
    backend = backend_for(session.topology, work_dir, runner)
    session.phase = "stopping"
    session.save(session_manifest(root, session.name))
    try:
        backend.down(session)
        remove_session_directory(root, session.name)
    except BaseException as error:
        session.phase = "cleanup-failed"
        session.save(session_manifest(root, session.name))
        diagnostics = retain_failure(root, session, work_dir, backend, error)
        raise RuntimeError(f"cleanup failed; session retained; scrubbed diagnostics: {diagnostics}") from error
    print(f"removed disposable development session {session.name}")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    up = commands.add_parser("up", help="create a named detached development session")
    up.add_argument("--name", required=True)
    up.add_argument("--topology", choices=("compose", "minikube"), required=True)
    up.add_argument("--config", type=Path)
    commands.add_parser("list", help="list local development sessions")
    status = commands.add_parser("status", help="show bounded session status")
    status.add_argument("--name", required=True)
    status.add_argument("--json", action="store_true")
    logs = commands.add_parser("logs", help="show bounded scrubbed component logs")
    logs.add_argument("--name", required=True)
    logs.add_argument("--component", required=True)
    logs.add_argument("--tail", type=int, choices=range(1, 501), default=200, metavar="1..500")
    restart = commands.add_parser("restart", help="restart an allowlisted stateless component")
    restart.add_argument("--name", required=True)
    restart.add_argument("--component", required=True)
    diagnose = commands.add_parser("diagnose", help="print bounded scrubbed diagnostics")
    diagnose.add_argument("--name", required=True)
    forward = commands.add_parser("port-forward", help="open one loopback-only foreground edge forward")
    forward.add_argument("--name", required=True)
    forward.add_argument("--port", type=int, default=8443)
    down = commands.add_parser("down", help="delete an owned disposable session")
    down.add_argument("--name", required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    commands = {
        "up": command_up,
        "list": lambda _arguments, selected_root, _runner: command_list(selected_root),
        "status": command_status,
        "logs": command_logs,
        "restart": command_restart,
        "diagnose": command_diagnose,
        "port-forward": command_port_forward,
        "down": command_down,
    }
    try:
        root = prepare_root(development_root())
        runner = Runner(ROOT)
        return commands[arguments.command](arguments, root, runner)
    except (ConfigurationError, CommandFailure, RuntimeError, OSError, json.JSONDecodeError) as error:
        print(f"local development helper: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
