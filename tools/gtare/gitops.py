import subprocess


class GitError(Exception):
    pass


def run(repo, *args, check=True):
    try:
        p = subprocess.run(["git"] + list(args), cwd=repo, capture_output=True, text=True, encoding="utf-8")
    except OSError:
        raise GitError("git is not installed or not on PATH.")
    if check and p.returncode != 0:
        raise GitError("git %s failed:\n%s" % (" ".join(args), (p.stderr or p.stdout).strip()))
    return p.stdout.rstrip()


def is_repo(repo):
    try:
        return run(repo, "rev-parse", "--is-inside-work-tree") == "true"
    except GitError:
        return False


def current_branch(repo):
    return run(repo, "rev-parse", "--abbrev-ref", "HEAD")


def changed_files(repo, base):
    out = run(repo, "diff", "--name-only", "--diff-filter=ACMRD", "%s...HEAD" % base)
    return [l for l in out.splitlines() if l]


def show(repo, ref, path):
    p = subprocess.run(["git", "show", "%s:%s" % (ref, path)], cwd=repo, capture_output=True)
    return p.stdout.decode("utf-8", "replace") if p.returncode == 0 else None
