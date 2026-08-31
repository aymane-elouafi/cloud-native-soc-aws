#!/usr/bin/env python3
"""Emit state-change JSON events for risky Docker runtime configurations."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

DOCKER_SOCKET_PATHS = {"/var/run/docker.sock", "/run/docker.sock"}
SENSITIVE_HOST_PATHS = (
    "/etc",
    "/root",
    "/var/lib/docker",
)
DANGEROUS_CAPABILITIES = {
    "DAC_READ_SEARCH",
    "NET_ADMIN",
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_PTRACE",
    "SYS_RAWIO",
}


def finding_key(item: dict[str, Any]) -> str:
    finding = item["finding"]
    return "|".join(
        str(finding.get(field, ""))
        for field in (
            "type",
            "container_id",
            "source",
            "destination",
            "namespace",
            "capability",
        )
    )


def base_finding(
    *,
    finding_type: str,
    container_id: str,
    container_name: str,
    image: str,
    **details: Any,
) -> dict[str, Any]:
    finding = {
        "type": finding_type,
        "container_id": container_id,
        "container_name": container_name,
        "image": image,
        **details,
    }
    return {"integration": "docker_security_scan", "finding": finding}


def is_same_or_descendant(path: str, parent: str) -> bool:
    return path == parent or path.startswith(parent + os.sep)


def normalise_capability(value: object) -> str:
    return str(value).upper().removeprefix("CAP_")


def scan() -> list[dict[str, Any]]:
    import docker

    client = docker.from_env()
    findings: list[dict[str, Any]] = []

    try:
        containers = sorted(client.containers.list(all=True), key=lambda item: item.name)
        for container in containers:
            attrs = container.attrs
            container_id = container.id
            container_name = container.name
            image = str(attrs.get("Config", {}).get("Image", "unknown"))
            host_config = attrs.get("HostConfig", {})

            if bool(host_config.get("Privileged", False)):
                findings.append(
                    base_finding(
                        finding_type="privileged_container",
                        container_id=container_id,
                        container_name=container_name,
                        image=image,
                    )
                )

            if str(host_config.get("NetworkMode", "")).lower() == "host":
                findings.append(
                    base_finding(
                        finding_type="host_network_mode",
                        container_id=container_id,
                        container_name=container_name,
                        image=image,
                        network_mode="host",
                    )
                )

            for namespace, config_key in (("pid", "PidMode"), ("ipc", "IpcMode")):
                if str(host_config.get(config_key, "")).lower() == "host":
                    findings.append(
                        base_finding(
                            finding_type="host_namespace",
                            container_id=container_id,
                            container_name=container_name,
                            image=image,
                            namespace=namespace,
                        )
                    )

            for capability in sorted(
                {
                    normalise_capability(item)
                    for item in host_config.get("CapAdd", []) or []
                }
                & DANGEROUS_CAPABILITIES
            ):
                findings.append(
                    base_finding(
                        finding_type="dangerous_capability",
                        container_id=container_id,
                        container_name=container_name,
                        image=image,
                        capability=capability,
                    )
                )

            for mount in attrs.get("Mounts", []):
                if mount.get("Type") != "bind":
                    continue

                source = os.path.normpath(str(mount.get("Source", "")))
                destination = os.path.normpath(str(mount.get("Destination", "")))
                details = {
                    "source": source,
                    "destination": destination,
                    "rw": bool(mount.get("RW", False)),
                    "mode": str(mount.get("Mode", "")),
                }

                if source in DOCKER_SOCKET_PATHS or destination in DOCKER_SOCKET_PATHS:
                    finding_type = "docker_socket_mount"
                elif source == "/":
                    finding_type = "host_root_mount"
                elif any(is_same_or_descendant(source, item) for item in SENSITIVE_HOST_PATHS):
                    finding_type = "sensitive_host_mount"
                else:
                    continue

                findings.append(
                    base_finding(
                        finding_type=finding_type,
                        container_id=container_id,
                        container_name=container_name,
                        image=image,
                        **details,
                    )
                )
    finally:
        client.close()

    return sorted(findings, key=finding_key)


def load_state(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as handle:
        items = json.load(handle)
    return {finding_key(item): item for item in items}


def save_state(path: Path, items: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(items, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
    os.replace(temporary, path)


def emit(path: Path, items: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/var/log/wazuh-docker-security.json"),
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path("/var/lib/wazuh-docker-risk-scan/state.json"),
    )
    args = parser.parse_args()

    try:
        current_items = scan()
        previous = load_state(args.state_file)
        current = {finding_key(item): item for item in current_items}

        events: list[dict[str, Any]] = []
        for key in sorted(current.keys() - previous.keys()):
            item = current[key]
            item["finding"]["status"] = "active"
            events.append(item)
        for key in sorted(previous.keys() - current.keys()):
            item = previous[key]
            item["finding"]["status"] = "resolved"
            events.append(item)

        if events:
            emit(args.output, events)
        save_state(args.state_file, current_items)
        return 0
    except Exception as exc:
        error = {
            "integration": "docker_security_scan",
            "finding": {
                "type": "scanner_error",
                "status": "active",
                "message": f"{type(exc).__name__}: {exc}",
            },
        }
        emit(args.output, [error])
        print(error["finding"]["message"], file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
