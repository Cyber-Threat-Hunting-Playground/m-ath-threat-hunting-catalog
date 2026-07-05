#!/usr/bin/env python3
"""Unified runner for punycode_idn notebook/script automation.

Supports:
- Papermill execution of punycode_idn.ipynb with runtime parameters
- CLI execution of punycode_idn.py with matching runtime options
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path


def _as_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    norm = str(value).strip().lower()
    if norm in {"true", "1", "yes", "y"}:
        return True
    if norm in {"false", "0", "no", "n"}:
        return False
    raise ValueError(f"Invalid boolean value: {value}")


def _load_json_override(args: argparse.Namespace) -> str:
    raw = str(args.engine_config_overrides_json or "").strip()
    if args.engine_config_overrides_file:
        text = Path(args.engine_config_overrides_file).expanduser().read_text(encoding="utf-8")
        obj = json.loads(text)
        if not isinstance(obj, dict):
            raise ValueError("--engine-config-overrides-file must contain a JSON object.")
        return json.dumps(obj)
    if raw:
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise ValueError("--engine-config-overrides-json must decode to a JSON object.")
        return json.dumps(obj)
    return ""


def _default_output_notebook(scenario_dir: Path) -> Path:
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return scenario_dir / "output" / f"punycode_idn_executed_{ts}.ipynb"


def run_notebook(args: argparse.Namespace, scenario_dir: Path, repo_root: Path) -> int:
    try:
        import papermill as pm
    except ImportError:
        print("papermill is not installed. Install dependencies from install/requirements.txt.")
        return 1

    input_nb = Path(args.target).expanduser().resolve()
    output_nb = Path(args.output_notebook).expanduser().resolve() if args.output_notebook else _default_output_notebook(scenario_dir)
    output_nb.parent.mkdir(parents=True, exist_ok=True)

    overrides_json = _load_json_override(args)
    params: dict[str, object] = {}
    if args.engine_config_file:
        params["PAPERMILL_ENGINE_CONFIG_FILE"] = str(Path(args.engine_config_file).expanduser().resolve())
    if overrides_json:
        params["PAPERMILL_ENGINE_CONFIG_OVERRIDES_JSON"] = overrides_json
    if args.translate_enabled is not None:
        params["PAPERMILL_TRANSLATE_ENABLED"] = _as_bool(args.translate_enabled)
    if args.dns_sibling_enabled is not None:
        params["PAPERMILL_DNS_SIBLING_CHECK_ENABLED"] = _as_bool(args.dns_sibling_enabled)
    if args.vt_workers is not None:
        params["PAPERMILL_VT_MAX_WORKERS"] = int(args.vt_workers)
    if args.vt_sleep is not None:
        params["PAPERMILL_VT_SLEEP_SECONDS"] = float(args.vt_sleep)
    if args.dns_sibling_workers is not None:
        params["PAPERMILL_DNS_SIBLING_MAX_WORKERS"] = int(args.dns_sibling_workers)
    if args.otx_workers is not None:
        params["PAPERMILL_OTX_MAX_WORKERS"] = int(args.otx_workers)
    if args.otx_sleep is not None:
        params["PAPERMILL_OTX_SLEEP_SECONDS"] = float(args.otx_sleep)
    if args.pulsedive_workers is not None:
        params["PAPERMILL_PD_MAX_WORKERS"] = int(args.pulsedive_workers)
    if args.pulsedive_sleep is not None:
        params["PAPERMILL_PD_SLEEP_SECONDS"] = float(args.pulsedive_sleep)

    print(f"Executing notebook via papermill: {input_nb}")
    print(f"Output notebook: {output_nb}")
    pm.execute_notebook(
        input_path=str(input_nb),
        output_path=str(output_nb),
        parameters=params,
        cwd=str(repo_root),
    )
    return 0


def run_script(args: argparse.Namespace) -> int:
    script_path = Path(args.target).expanduser().resolve()
    cmd = [sys.executable, str(script_path)]

    if args.engine_config_file:
        cmd += ["--engine-config-file", str(Path(args.engine_config_file).expanduser().resolve())]
    overrides_json = _load_json_override(args)
    if overrides_json:
        cmd += ["--engine-config-overrides-json", overrides_json]

    if args.vt_workers is not None:
        cmd += ["--vt-workers", str(int(args.vt_workers))]
    if args.vt_sleep is not None:
        cmd += ["--vt-sleep", str(float(args.vt_sleep))]
    if args.dns_sibling_workers is not None:
        cmd += ["--dns-sibling-workers", str(int(args.dns_sibling_workers))]
    if args.otx_workers is not None:
        cmd += ["--otx-workers", str(int(args.otx_workers))]
    if args.otx_sleep is not None:
        cmd += ["--otx-sleep", str(float(args.otx_sleep))]
    if args.pulsedive_workers is not None:
        cmd += ["--pulsedive-workers", str(int(args.pulsedive_workers))]
    if args.pulsedive_sleep is not None:
        cmd += ["--pulsedive-sleep", str(float(args.pulsedive_sleep))]

    translate_enabled = _as_bool(args.translate_enabled) if args.translate_enabled is not None else None
    if translate_enabled is False:
        cmd.append("--no-translate")
    dns_sibling_enabled = _as_bool(args.dns_sibling_enabled) if args.dns_sibling_enabled is not None else None
    if dns_sibling_enabled is False:
        cmd.append("--no-dns-sibling")

    if args.log_level:
        cmd += ["--log-level", args.log_level]

    print("Executing script:", " ".join(cmd))
    proc = subprocess.run(cmd, check=False)
    return int(proc.returncode)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run punycode_idn via Papermill notebook execution or Python script mode.",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "notebook", "script"],
        default="auto",
        help="Execution mode. auto selects by target extension.",
    )
    parser.add_argument(
        "--target",
        default="",
        help="Path to punycode_idn.ipynb or punycode_idn.py. Defaults to notebook in scenario folder.",
    )
    parser.add_argument(
        "--output-notebook",
        default="",
        help="Notebook output path when running in notebook mode.",
    )
    parser.add_argument("--engine-config-file", default="", help="Alternate engine weights file path.")
    parser.add_argument("--engine-config-overrides-json", default="", help="JSON object merged over engine config.")
    parser.add_argument("--engine-config-overrides-file", default="", help="Path to JSON file merged over engine config.")

    parser.add_argument("--translate-enabled", choices=["true", "false"], default=None)
    parser.add_argument("--dns-sibling-enabled", choices=["true", "false"], default=None)
    parser.add_argument("--vt-workers", type=int, default=None)
    parser.add_argument("--vt-sleep", type=float, default=None)
    parser.add_argument("--dns-sibling-workers", type=int, default=None)
    parser.add_argument("--otx-workers", type=int, default=None)
    parser.add_argument("--otx-sleep", type=float, default=None)
    parser.add_argument("--pulsedive-workers", type=int, default=None)
    parser.add_argument("--pulsedive-sleep", type=float, default=None)
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    scenario_dir = Path(__file__).resolve().parent
    repo_root = scenario_dir.parent.parent
    default_target = scenario_dir / "punycode_idn.ipynb"
    target = Path(args.target).expanduser().resolve() if args.target else default_target.resolve()
    args.target = str(target)

    mode = args.mode
    if mode == "auto":
        suffix = target.suffix.lower()
        if suffix == ".ipynb":
            mode = "notebook"
        elif suffix == ".py":
            mode = "script"
        else:
            raise ValueError(f"Cannot infer mode from target extension: {target}")

    if mode == "notebook":
        return run_notebook(args, scenario_dir=scenario_dir, repo_root=repo_root)
    return run_script(args)


if __name__ == "__main__":
    sys.exit(main())
