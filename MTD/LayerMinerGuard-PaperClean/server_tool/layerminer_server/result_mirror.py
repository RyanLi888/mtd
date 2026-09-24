"""Mirror runtime result files into a local results directory."""

import json
import os


def result_dir(config: dict) -> str:
    """Return the configured local result mirror directory."""
    output_cfg = config.get("output", {})
    return output_cfg.get("result_dir", "results")


def result_path(config: dict, *parts: str) -> str:
    """Build a path inside the local result mirror directory."""
    return os.path.join(result_dir(config), *parts)


def ensure_result_dir(config: dict, *parts: str) -> str:
    """Create and return a directory inside the local result mirror."""
    path = result_path(config, *parts)
    os.makedirs(path, exist_ok=True)
    return path


def append_jsonl(config: dict, filename: str, record: dict) -> str:
    """Append one JSON record to a mirrored JSONL file."""
    ensure_result_dir(config)
    path = result_path(config, filename)
    with open(path, "a") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path


def write_json(config: dict, filename: str, data: dict) -> str:
    """Write one mirrored JSON file."""
    ensure_result_dir(config)
    path = result_path(config, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return path


def append_line(config: dict, filename: str, line: str) -> str:
    """Append one text line to a mirrored log file."""
    ensure_result_dir(config)
    path = result_path(config, filename)
    with open(path, "a") as f:
        f.write(line + "\n")
    return path


def write_observation(config: dict, filename: str, record: dict) -> str:
    """Write one mirrored observation JSON file."""
    obs_dir = ensure_result_dir(config, "observations")
    path = os.path.join(obs_dir, filename)
    with open(path, "w") as f:
        json.dump(record, f, indent=2, ensure_ascii=False)
    return path


def clear_file(config: dict, filename: str) -> int:
    """Truncate a mirrored result file and return its non-empty line count."""
    path = result_path(config, filename)
    if not os.path.exists(path):
        return 0
    with open(path) as f:
        count = sum(1 for line in f if line.strip())
    with open(path, "w") as f:
        pass
    return count


def clear_json_file(config: dict, filename: str) -> int:
    """Replace a mirrored JSON file with an empty object."""
    path = result_path(config, filename)
    if not os.path.exists(path):
        return 0
    try:
        with open(path) as f:
            data = json.load(f)
        count = len(data) if isinstance(data, dict) else 1
    except json.JSONDecodeError:
        count = 0
    with open(path, "w") as f:
        json.dump({}, f)
    return count


def clear_observations(config: dict) -> int:
    """Remove mirrored observation JSON files."""
    obs_dir = result_path(config, "observations")
    if not os.path.isdir(obs_dir):
        return 0
    total = 0
    for fname in os.listdir(obs_dir):
        if fname.endswith(".json") and not fname.startswith("."):
            os.remove(os.path.join(obs_dir, fname))
            total += 1
    return total


def clear_json_dir(config: dict, dirname: str) -> int:
    """Remove JSON files from a mirrored result subdirectory."""
    directory = result_path(config, dirname)
    if not os.path.isdir(directory):
        return 0
    total = 0
    for fname in os.listdir(directory):
        if fname.endswith(".json") and not fname.startswith("."):
            os.remove(os.path.join(directory, fname))
            total += 1
    return total
