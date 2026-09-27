#!/usr/bin/env python3
"""Reproduce the expense-agent study in an isolated local Juardrails server.

Requires Go, Python 3, OPENAI_API_KEY and TYPESAFE_API_KEY in the repository
.env file or process environment. No real expense transaction is performed.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

from agent import load_env_file


ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]


def run(argv, env=None, capture=True):
    process = subprocess.run(argv, cwd=REPO, env=env, text=True, capture_output=capture, timeout=180)
    if process.returncode:
        raise RuntimeError(f"{' '.join(str(x) for x in argv[:3])} failed: {process.stderr.strip()[-500:]}")
    return process.stdout


def json_file(path, value):
    path.write_text(json.dumps(value))
    return str(path)


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", default=str(REPO / ".env"))
    parser.add_argument("--artifacts-dir", help="new directory for generated skill ZIP and raw observations")
    args = parser.parse_args()
    load_env_file(args.env_file)
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        parser.error("OPENAI_API_KEY is required")
    server_env = os.environ.copy()
    server_env.pop("OPENAI_API_KEY", None)
    if not server_env.get("TYPESAFE_API_KEY") and Path(args.env_file).exists():
        for raw in Path(args.env_file).read_text().splitlines():
            if raw.strip().startswith("TYPESAFE_API_KEY="):
                server_env["TYPESAFE_API_KEY"] = raw.split("=", 1)[1].strip().strip("'\"")
                break
    if not server_env.get("TYPESAFE_API_KEY"):
        parser.error("TYPESAFE_API_KEY is required")
    with tempfile.TemporaryDirectory(prefix="juardrails-expense-study-") as directory:
        work = Path(directory)
        admin_home, agent_home = work / "admin-home", work / "agent-home"
        admin_home.mkdir(mode=0o700)
        agent_home.mkdir(mode=0o700)
        binary = work / "juardrails"
        run(["go", "build", "-o", str(binary), "./cmd/juardrails"])
        port = available_port()
        url = f"http://127.0.0.1:{port}"
        db, audit = work / "juardrails.sqlite", work / "audit.jsonl"
        admin_env = os.environ.copy()
        admin_env["HOME"] = str(admin_home)
        admin_env.pop("OPENAI_API_KEY", None)
        run([str(binary), "bootstrap", "-db", str(db), "-audit-log", str(audit), "-url", url], admin_env)
        with (work / "server.log").open("w") as log:
            server = subprocess.Popen(
                [str(binary), "-addr", f"127.0.0.1:{port}", "-db", str(db), "-audit-log", str(audit)],
                cwd=REPO, env=server_env, stdout=log, stderr=log,
            )
            try:
                for _ in range(100):
                    if server.poll() is not None:
                        raise RuntimeError("local Juardrails server exited during setup")
                    try:
                        with urllib.request.urlopen(url + "/healthz", timeout=1):
                            break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("local Juardrails server did not become ready")

                def admin(*parts):
                    return run([str(binary), "cli", *parts], admin_env)

                admin("admin", "namespaces", "create", json_file(work / "namespace.json", {"name": "expense-demo"}))
                admin("-namespace", "expense-demo", "apply", str(ROOT / "policy.json"))
                grant = {"name": "expense-agent-access", "rules": [{"namespace": "expense-demo", "actions": ["policies:read", "policies:evaluate", "policies:simulate"]}]}
                admin("admin", "access", "create", json_file(work / "grant.json", grant))
                principal = json.loads(admin("admin", "users", "create", json_file(work / "principal.json", {"name": "expense-agent", "kind": "service"})))
                admin("admin", "users", "bindings", principal["id"], json_file(work / "bindings.json", {"policies": ["expense-agent-access"]}))
                expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)).isoformat().replace("+00:00", "Z")
                token_request = {"principal_id": principal["id"], "name": "case-study-agent", "expires_at": expiry}
                issued = json.loads(admin("admin", "tokens", "create", json_file(work / "token-request.json", token_request)))
                credential_dir = agent_home / ".juardrails"
                credential_dir.mkdir(mode=0o700)
                fd = os.open(credential_dir / "credentials.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as file:
                    json.dump({"url": url, "token": issued["token"]}, file)
                agent_env = os.environ.copy()
                agent_env["HOME"] = str(agent_home)
                agent_env["SKILL_AI_API_KEY"] = key
                for forbidden in (["admin", "users", "list"], ["-namespace", "root", "list"]):
                    probe = subprocess.run([str(binary), "cli", *forbidden], cwd=REPO, env=agent_env, capture_output=True, text=True, timeout=15)
                    if probe.returncode == 0:
                        raise RuntimeError("expense agent service account has more access than intended")
                skill_zip = work / "expense-skill.zip"
                run([str(binary), "cli", "-namespace", "expense-demo", "skill", "expense-approval", str(skill_zip)], agent_env)
                live_path = work / "live-results.json"
                live_output = run(["python3", str(ROOT / "agent.py"), "--skill", str(skill_zip), "--binary", str(binary), "--output", str(live_path)], agent_env)
                simulation_output = run(["python3", str(ROOT / "simulate.py"), "--skill", str(skill_zip), "--binary", str(binary)], agent_env)
                print(live_output.strip())
                print(simulation_output.strip())
                if args.artifacts_dir:
                    destination = Path(args.artifacts_dir)
                    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
                    shutil.copy2(skill_zip, destination / skill_zip.name)
                    shutil.copy2(live_path, destination / live_path.name)
                    print(f"Saved generated skill and raw observations to {destination}")
            finally:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == "__main__":
    main()
