from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


PYVUL_METADATA_URL = (
    "https://raw.githubusercontent.com/billquan/PyVul/master/"
    "benchmark_curation/data_collection/github_adv_src_links.json"
)
PYVUL_README_URL = "https://raw.githubusercontent.com/billquan/PyVul/master/README.md"


try:
    from tqdm import tqdm  # type: ignore
except ImportError:
    tqdm = None


@dataclass
class Sample:
    sample_index: int
    project_name: str
    cwe: str
    advisory_id: str | None
    cve: str | None
    ghsa: str | None
    repo_url: str
    fix_commit: str
    before_commit: str
    source_link: str
    repo_name: str
    owner: str
    raw_report: dict[str, Any]


@dataclass
class Filters:
    require_cve: bool
    require_ghsa: bool
    cwe: str | None
    repo_contains: str | None


class Progress:
    def __init__(self, total: int, desc: str) -> None:
        self.total = total
        self.desc = desc
        self.count = 0
        self._tqdm = tqdm(total=total, desc=desc, unit="case") if tqdm else None
        self._last_len = 0

    def update(self, message: str | None = None) -> None:
        self.count += 1
        if self._tqdm:
            if message:
                self._tqdm.set_postfix_str(message[:80])
            self._tqdm.update(1)
            return

        width = 30
        filled = width if self.total == 0 else int(width * self.count / self.total)
        bar = "#" * filled + "-" * (width - filled)
        percent = 100 if self.total == 0 else int(100 * self.count / self.total)
        msg = f"\r{self.desc}: [{bar}] {self.count}/{self.total} {percent:3d}%"
        if message:
            msg += f" {message[:80]}"
        padding = " " * max(0, self._last_len - len(msg))
        self._last_len = len(msg)
        print(msg + padding, end="", flush=True)

    def close(self) -> None:
        if self._tqdm:
            self._tqdm.close()
        else:
            print()


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip()
        command = " ".join(args)
        message = f"Command failed ({result.returncode}): {command}"
        if details:
            message += f"\n{details}"
        raise RuntimeError(message)
    return result


def git_repo_run(
    repo_dir: Path,
    args: list[str],
    *,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    safe_dir = repo_dir.resolve().as_posix()
    return run(
        ["git", "-c", f"safe.directory={safe_dir}", *args],
        cwd=repo_dir,
        check=check,
        capture=capture,
    )


def require_command(command: str) -> None:
    if shutil.which(command):
        return
    raise SystemExit(f"Required command not found in PATH: {command}")


def download_text(url: str, *, retries: int = 3, timeout: int = 60) -> str:
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "pyvul-dataset-extractor/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.read().decode("utf-8")
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(2 * attempt)
    raise RuntimeError(f"Failed to download {url}: {last_error}")


def load_metadata(cache_dir: Path, force_refresh: bool) -> dict[str, Any]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / "github_adv_src_links.json"
    if force_refresh or not path.exists():
        text = download_text(PYVUL_METADATA_URL)
        path.write_text(text, encoding="utf-8")
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_repo_url(repo_url: str) -> str:
    if repo_url.endswith(".git"):
        return repo_url
    return f"{repo_url}.git"


def parse_source_link(source_link: str) -> tuple[str, str]:
    marker = "/commit/"
    if marker not in source_link:
        raise ValueError(f"Unsupported source link (missing /commit/): {source_link}")
    repo_url, commit = source_link.split(marker, 1)
    commit = commit.strip().split("/")[0]
    repo_url = repo_url.rstrip("/")
    if not repo_url.startswith("https://github.com/"):
        raise ValueError(f"Unsupported repository host: {repo_url}")
    return repo_url, commit


def extract_aliases(report: dict[str, Any]) -> tuple[str | None, str | None]:
    advisories = []
    for key in ("aliases", "identifiers", "vuln_aliases"):
        value = report.get(key)
        if isinstance(value, list):
            advisories.extend(value)
    advisory_id = report.get("id")
    if isinstance(advisory_id, str):
        advisories.append(advisory_id)

    cve = next((x for x in advisories if isinstance(x, str) and x.startswith("CVE-")), None)
    ghsa = next((x for x in advisories if isinstance(x, str) and x.startswith("GHSA-")), None)
    return cve, ghsa


def iter_reports(metadata: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for cwe, reports in metadata.items():
        if not isinstance(reports, list):
            continue
        for report in reports:
            if isinstance(report, dict):
                yield str(cwe), report


def owner_and_repo(repo_url: str) -> tuple[str, str]:
    parts = repo_url.rstrip("/").split("/")
    if len(parts) < 2:
        raise ValueError(f"Invalid GitHub repo url: {repo_url}")
    return parts[-2], parts[-1]


def build_samples(metadata: dict[str, Any], *, filters: Filters) -> list[Sample]:
    samples: list[Sample] = []

    for cwe, report in iter_reports(metadata):
        src_links = report.get("src_links") or []
        if not isinstance(src_links, list) or not src_links:
            continue

        source_link = src_links[0]
        if not isinstance(source_link, str):
            continue
        if "/commit/" not in source_link:
            continue

        try:
            repo_url, fix_commit = parse_source_link(source_link)
            owner, repo_name = owner_and_repo(repo_url)
        except ValueError:
            continue

        advisory_id = report.get("id") if isinstance(report.get("id"), str) else None
        cve, ghsa = extract_aliases(report)
        if filters.require_cve and not cve:
            continue
        if filters.require_ghsa and not ghsa:
            continue
        if filters.cwe and str(cwe).lower() != filters.cwe.lower():
            continue
        if filters.repo_contains:
            repo_text = f"{owner}/{repo_name}".lower()
            if filters.repo_contains.lower() not in repo_text:
                continue
        sample_index = len(samples) + 1
        project_name = make_project_name(
            sample_index=sample_index,
            cwe=cwe,
            owner=owner,
            repo_name=repo_name,
            advisory_id=advisory_id,
            fix_commit=fix_commit,
        )

        samples.append(
            Sample(
                sample_index=sample_index,
                project_name=project_name,
                cwe=cwe,
                advisory_id=advisory_id,
                cve=cve,
                ghsa=ghsa,
                repo_url=repo_url,
                fix_commit=fix_commit,
                before_commit=f"{fix_commit}^",
                source_link=source_link,
                repo_name=repo_name,
                owner=owner,
                raw_report=report,
            )
        )

    return samples


def sanitize_name(text: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text.strip())
    text = re.sub(r"_+", "_", text).strip("._-")
    return text or "unknown"


def make_project_name(
    *,
    sample_index: int,
    cwe: str,
    owner: str,
    repo_name: str,
    advisory_id: str | None,
    fix_commit: str,
) -> str:
    advisory_or_commit = advisory_id or fix_commit[:12]
    parts = [
        sanitize_name(cwe),
        f"{sample_index:04d}",
        sanitize_name(owner),
        sanitize_name(repo_name),
        sanitize_name(advisory_or_commit),
    ]
    return "_".join(parts)[:150]


def select_range(samples: list[Sample], *, start: int, end: int | None, limit: int | None) -> list[Sample]:
    if start < 1:
        raise SystemExit("--start must be >= 1")
    if end is not None and end < start:
        raise SystemExit("--end must be >= --start")
    if limit is not None and limit < 1:
        raise SystemExit("--limit must be >= 1")
    if end is not None and limit is not None:
        raise SystemExit("--end and --limit cannot be used together")

    start_offset = start - 1
    if end is not None:
        return samples[start_offset:end]
    if limit is not None:
        return samples[start_offset : start_offset + limit]
    return samples[start_offset:]


def ensure_repo_mirror(cache_repos_dir: Path, sample: Sample) -> Path:
    repo_dir = cache_repos_dir / f"{sanitize_name(sample.owner)}__{sanitize_name(sample.repo_name)}"
    if repo_dir.exists():
        if commit_exists(repo_dir, sample.fix_commit) and commit_exists(repo_dir, sample.before_commit):
            return repo_dir
        git_repo_run(repo_dir, ["fetch", "--all", "--tags", "--prune"])
        return repo_dir
    cache_repos_dir.mkdir(parents=True, exist_ok=True)
    run(["git", "clone", "--no-checkout", normalize_repo_url(sample.repo_url), str(repo_dir)])
    return repo_dir


def verify_commit_exists(repo_dir: Path, commitish: str) -> None:
    git_repo_run(repo_dir, ["rev-parse", "--verify", commitish])


def commit_exists(repo_dir: Path, commitish: str) -> bool:
    result = git_repo_run(
        repo_dir,
        ["rev-parse", "--verify", commitish],
        check=False,
    )
    return result.returncode == 0


def make_writable_and_retry(func: Any, path: str, exc_info: Any) -> None:
    try:
        os.chmod(path, stat.S_IRWXU)
        func(path)
    except Exception:
        raise exc_info[1]


def remove_tree(path: Path, *, ignore_errors: bool = False) -> None:
    if path.exists():
        try:
            shutil.rmtree(path, onerror=make_writable_and_retry)
        except Exception:
            if not ignore_errors:
                raise


def safe_tar_members(tar: tarfile.TarFile, output_dir: Path) -> list[tarfile.TarInfo]:
    root = output_dir.resolve()
    safe_members: list[tarfile.TarInfo] = []
    for member in tar.getmembers():
        target = (output_dir / member.name).resolve()
        if target != root and root not in target.parents:
            raise RuntimeError(f"unsafe archive path: {member.name}")

        member.uid = member.gid = 0
        member.uname = member.gname = ""
        if member.isdir():
            member.mode = 0o755
        elif member.isfile():
            member.mode = 0o644
        else:
            member.mode = 0o755 if member.isdir() else 0o644
        safe_members.append(member)
    return safe_members


def make_tree_writable(path: Path) -> None:
    for root, dirs, files in os.walk(path):
        for dirname in dirs:
            dir_path = Path(root) / dirname
            if dir_path.is_symlink():
                continue
            os.chmod(dir_path, stat.S_IRWXU)
        for filename in files:
            file_path = Path(root) / filename
            if file_path.is_symlink():
                continue
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)


def export_commit_tree(repo_dir: Path, commitish: str, output_dir: Path) -> None:
    remove_tree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
        tar_path = Path(tmp.name)

    try:
        git_repo_run(repo_dir, ["archive", "--format=tar", "-o", str(tar_path), commitish])
        with tarfile.open(tar_path) as tar:
            members = safe_tar_members(tar, output_dir)
            try:
                tar.extractall(output_dir, members=members, filter="data")
            except TypeError:
                tar.extractall(output_dir, members=members)
        make_tree_writable(output_dir)
    finally:
        tar_path.unlink(missing_ok=True)


def safe_write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_meta(case_dir: Path, sample: Sample, status: str, error: str | None = None) -> None:
    meta = {
        "sample_index": sample.sample_index,
        "project_name": sample.project_name,
        "status": status,
        "cwe": sample.cwe,
        "advisory_id": sample.advisory_id,
        "cve": sample.cve,
        "ghsa": sample.ghsa,
        "repo_url": sample.repo_url,
        "repo_name": sample.repo_name,
        "repo_owner": sample.owner,
        "source_link": sample.source_link,
        "fix_commit": sample.fix_commit,
        "before_commit": sample.before_commit,
        "error": error,
        "raw_report": sample.raw_report,
    }
    safe_write_json(case_dir / "meta.json", meta)


def process_sample(sample: Sample, output_dir: Path, cache_repos_dir: Path) -> tuple[bool, str]:
    case_dir = output_dir / sample.project_name
    before_dir = case_dir / "Alpha"
    after_dir = case_dir / "Beta"

    case_dir.mkdir(parents=True, exist_ok=True)

    try:
        repo_dir = ensure_repo_mirror(cache_repos_dir, sample)
        verify_commit_exists(repo_dir, sample.fix_commit)
        verify_commit_exists(repo_dir, sample.before_commit)
        export_commit_tree(repo_dir, sample.before_commit, before_dir)
        export_commit_tree(repo_dir, sample.fix_commit, after_dir)
        write_meta(case_dir, sample, status="ok")
        return True, sample.repo_name
    except Exception as exc:
        if before_dir.exists():
            remove_tree(before_dir, ignore_errors=True)
        if after_dir.exists():
            remove_tree(after_dir, ignore_errors=True)
        write_meta(case_dir, sample, status="error", error=str(exc))
        return False, f"{sample.repo_name}: {exc}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract PyVul commit-level samples into Alpha/Beta project directories."
    )
    parser.add_argument(
        "--output-dir",
        default="dataset",
        help="Output directory to create under the current working directory. Default: dataset",
    )
    parser.add_argument(
        "--cache-dir",
        default=".pyvul_cache",
        help="Directory for cached PyVul metadata and cloned repos. Default: .pyvul_cache",
    )
    parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="1-based index of the first sample to extract. Default: 1",
    )
    parser.add_argument(
        "--end",
        type=int,
        default=None,
        help="1-based index of the last sample to extract, inclusive.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Extract at most N samples from --start. Cannot be combined with --end.",
    )
    parser.add_argument(
        "--force-refresh-metadata",
        action="store_true",
        help="Redownload PyVul metadata even if a cached copy exists.",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip project directories that already contain Alpha/, Beta/, and meta.json.",
    )
    parser.add_argument(
        "--max-failures",
        type=int,
        default=None,
        help="Stop early after N failed samples.",
    )
    parser.add_argument(
        "--count-only",
        action="store_true",
        help="Only print how many valid samples can be extracted, then exit.",
    )
    parser.add_argument(
        "--require-cve",
        action="store_true",
        help="Only include samples that have a CVE identifier.",
    )
    parser.add_argument(
        "--require-ghsa",
        action="store_true",
        help="Only include samples that have a GHSA identifier.",
    )
    parser.add_argument(
        "--cwe",
        default=None,
        help="Only include one CWE value, for example CWE-79.",
    )
    parser.add_argument(
        "--repo-contains",
        default=None,
        help="Only include repos whose owner/name contains this substring.",
    )
    parser.add_argument(
        "--write-index",
        action="store_true",
        help="Write cases_index.jsonl in the output directory before extraction.",
    )
    return parser.parse_args()


def is_complete_case(case_dir: Path) -> bool:
    return (
        (case_dir / "Alpha").is_dir()
        and (case_dir / "Beta").is_dir()
        and (case_dir / "meta.json").is_file()
    )


def write_index(samples: list[Sample], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    index_path = output_dir / "cases_index.jsonl"
    with index_path.open("w", encoding="utf-8") as f:
        for sample in samples:
            row = {
                "sample_index": sample.sample_index,
                "project_name": sample.project_name,
                "cwe": sample.cwe,
                "advisory_id": sample.advisory_id,
                "cve": sample.cve,
                "ghsa": sample.ghsa,
                "repo_url": sample.repo_url,
                "repo_name": sample.repo_name,
                "repo_owner": sample.owner,
                "fix_commit": sample.fix_commit,
                "before_commit": sample.before_commit,
                "source_link": sample.source_link,
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return index_path


def main() -> int:
    require_command("git")

    args = parse_args()
    cwd = Path.cwd()
    output_dir = (cwd / args.output_dir).resolve()
    cache_dir = (cwd / args.cache_dir).resolve()
    cache_repos_dir = cache_dir / "repos"

    print(f"[info] working directory: {cwd}")
    print(f"[info] output directory: {output_dir}")
    print(f"[info] cache directory: {cache_dir}")
    print(f"[info] PyVul metadata: {PYVUL_METADATA_URL}")

    metadata = load_metadata(cache_dir, args.force_refresh_metadata)
    filters = Filters(
        require_cve=args.require_cve,
        require_ghsa=args.require_ghsa,
        cwe=args.cwe,
        repo_contains=args.repo_contains,
    )
    all_samples = build_samples(metadata, filters=filters)

    if not all_samples:
        print("[error] no valid samples found in PyVul metadata")
        return 1

    samples = select_range(all_samples, start=args.start, end=args.end, limit=args.limit)

    print(f"[info] total extractable candidate samples: {len(all_samples)}")
    print(f"[info] selected samples: {len(samples)}")
    if samples:
        print(
            f"[info] selected index range: "
            f"{samples[0].sample_index}..{samples[-1].sample_index}"
        )
    if args.write_index:
        index_path = write_index(samples, output_dir)
        print(f"[info] wrote index: {index_path}")
    if args.count_only:
        return 0

    if not samples:
        print("[error] selected range is empty")
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)

    progress = Progress(len(samples), desc="Extracting")
    success_count = 0
    failure_count = 0

    for sample in samples:
        case_dir = output_dir / sample.project_name
        if args.skip_existing and is_complete_case(case_dir):
            success_count += 1
            progress.update(f"{sample.project_name} skipped")
            continue

        ok, message = process_sample(sample, output_dir, cache_repos_dir)
        if ok:
            success_count += 1
            progress.update(f"{sample.project_name} {message}")
        else:
            failure_count += 1
            progress.update(f"{sample.project_name} failed")
            print(f"[warn] {message}", file=sys.stderr)
            if args.max_failures is not None and failure_count >= args.max_failures:
                print(f"[warn] stopping after {failure_count} failures")
                break

    progress.close()
    print(f"[done] success={success_count} failure={failure_count} output={output_dir}")
    if failure_count > 0:
        print("[done] failed cases still contain meta.json with the error reason")
    return 0 if success_count > 0 else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
