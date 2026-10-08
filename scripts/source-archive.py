#!/usr/bin/env python3
"""Explicit source allowlist. No git-ignore heuristic, runtime data, or publishing."""
import argparse
import os
from pathlib import Path, PurePosixPath
import stat
import zipfile

ROOT_FILES = {
    'README.md', 'LICENSE', 'SECURITY.md', '.gitignore', 'package.json',
    'package-lock.json', 'tsconfig.json', 'vite.config.ts', 'playwright.config.ts',
    'index.html', 'icon.svg',
}
RUST_FILES = {'src-tauri/Cargo.toml', 'src-tauri/Cargo.lock', 'src-tauri/build.rs'}
FORBIDDEN = {'.local', '.git', 'keys', 'secrets', 'target', 'node_modules',
             'dist', 'work', 'outputs', 'test-results', 'playwright-report'}

def allowed(relative):
    p = PurePosixPath(relative)
    parts = p.parts
    if any(x in FORBIDDEN or x.startswith('.env') for x in parts):
        return False
    if relative in ROOT_FILES or relative in RUST_FILES:
        return True
    if len(parts) == 2 and parts[0] == 'src-tauri':
        return p.name == 'tauri.conf.json' or (p.name.startswith('tauri.') and p.name.endswith('.conf.json'))
    rules = [
        (('src',), {'.ts', '.tsx', '.css', '.svg'}),
        (('src-tauri', 'src'), {'.rs'}),
        (('src-tauri', 'tests'), {'.rs'}),
        (('src-tauri', 'examples'), {'.rs'}),
        (('src-tauri', 'permissions'), {'.toml'}),
        (('src-tauri', 'capabilities'), {'.json'}),
        (('src-tauri', 'icons'), {'.png', '.ico', '.icns'}),
        (('tests',), {'.ts'}),
        (('scripts',), {'.py', '.mjs', '.sh', '.ps1'}),
        (('.github', 'workflows'), {'.yml', '.yaml'}),
        (('docs', 'product'), {'.md'}),
        (('docs', 'mtg'), {'.md'}),
    ]
    if len(parts) == 2 and parts[0] == 'docs' and p.suffix == '.md':
        return True
    return any(parts[:len(prefix)] == prefix and len(parts) > len(prefix) and p.suffix in suffixes
               for prefix, suffixes in rules)

def source_members(root):
    root = Path(root).absolute()
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Source root must be a real directory')
    selected = []
    total_bytes = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        # Fail closed for linked directories inside source roots; never traverse a link.
        for d in list(dirs):
            path = Path(directory) / d
            relative = path.relative_to(root).as_posix()
            if d in FORBIDDEN or d.startswith('.env') or relative == 'docs/evidence':
                dirs.remove(d)
                continue
            if path.is_symlink():
                dirs.remove(d)
                if relative.split('/')[0] in {'src', 'src-tauri', 'scripts', 'tests', 'docs', '.github'}:
                    raise ValueError('Linked source directory refused')
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if not allowed(relative):
                continue
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError('Linked or nonregular source file refused')
            total_bytes += before.st_size
            if before.st_size > 8 * 1024 * 1024 or total_bytes > 64 * 1024 * 1024:
                raise ValueError('Source archive size limit exceeded')
            flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
            fd = os.open(path, flags)
            with os.fdopen(fd, 'rb') as stream:
                held = os.fstat(stream.fileno())
                if (held.st_dev, held.st_ino) != (before.st_dev, before.st_ino):
                    raise ValueError('Source changed before read')
                data = stream.read(8 * 1024 * 1024 + 1)
                after = os.fstat(stream.fileno())
            current = path.lstat()
            identity = lambda m: (m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns)
            if len(data) != before.st_size or identity(before) != identity(after) or identity(before) != identity(current):
                raise ValueError('Source changed during read')
            selected.append((relative, data))
    return sorted(selected)

def archive(root, destination):
    members = source_members(root)
    if not members:
        raise ValueError('No allowed source files')
    destination = Path(destination)
    created = False
    try:
        with zipfile.ZipFile(destination, 'x', compression=zipfile.ZIP_DEFLATED) as output:
            created = True
            for relative, data in members:
                info = zipfile.ZipInfo(relative, date_time=(2020, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                output.writestr(info, data)
        with zipfile.ZipFile(destination) as output:
            if output.namelist() != [name for name, _ in members] or output.testzip():
                raise ValueError('Archive verification failed')
    except Exception:
        if created:
            destination.unlink(missing_ok=True)
        raise
    return [name for name, _ in members]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    names = archive(args.root, args.destination)
    print(f'Verified {len(names)} allowlisted source files. No publication performed.')
