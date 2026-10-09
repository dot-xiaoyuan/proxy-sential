#!/usr/bin/env python3
"""Retain the last different frontend graph under the application upgrade lock."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import uuid


def controlled(root, target):
    resolved = Path(target).resolve(strict=True)
    if resolved.parent != root/'releases' or not resolved.is_dir():
        raise ValueError('frontend release outside controlled releases')
    directory = resolved/'frontend/dist'
    if directory.resolve(strict=True) != directory or not directory.is_dir():
        raise ValueError('frontend directory contains redirected paths')
    return resolved


def pointer(root, name, optional=False):
    path = root/name
    if optional and not path.exists() and not path.is_symlink():
        return None
    if not path.is_symlink():
        raise ValueError('frontend release pointer must be a symlink')
    return controlled(root, path)


def graph(release):
    root = release/'frontend/dist'
    digest = hashlib.sha256()
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('frontend graph contains unsafe entries')
        if path.is_file():
            digest.update(str(path.relative_to(root)).encode()+b'\0')
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    if not (root/'index.html').is_file():
        raise ValueError('frontend shell missing')
    return digest.hexdigest()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish(root, target):
    path = root/'frontend-previous'
    if target is None:
        if path.is_symlink():
            path.unlink()
        elif path.exists():
            raise ValueError('frontend pointer replaced by regular file')
    else:
        temporary = root/('.frontend-previous-'+uuid.uuid4().hex)
        try:
            temporary.symlink_to(target)
            os.replace(temporary, path)
        finally:
            if temporary.is_symlink():
                temporary.unlink()
    sync_directory(root)


def prepare(root, candidate, state_path):
    root = root.resolve(strict=True)
    old = pointer(root, 'current')
    previous = pointer(root, 'previous')
    retained = pointer(root, 'frontend-previous', True)
    candidate = controlled(root, candidate)
    old_graph = graph(old)
    if graph(candidate) != old_graph:
        target = old
    elif retained is not None:
        target = retained
    elif graph(previous) != old_graph:
        target = previous
    else:
        target = None
    if state_path.parent != root/'config' or state_path.is_symlink():
        raise ValueError('invalid frontend rollback state path')
    state = {'schema_version':1, 'root':str(root), 'original':str(retained) if retained else None, 'published':str(target) if target else None}
    fd = os.open(state_path, os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW)
    with os.fdopen(fd, 'w') as output:
        json.dump(state, output); output.flush(); os.fsync(output.fileno())
    sync_directory(state_path.parent)
    publish(root, target)
    return state


def restore(root, state_path):
    root = root.resolve(strict=True)
    if state_path.parent != root/'config' or state_path.is_symlink():
        raise ValueError('invalid frontend rollback state path')
    state = json.loads(state_path.read_text())
    if state.get('schema_version') != 1 or state.get('root') != str(root):
        raise ValueError('invalid frontend rollback state')
    original = controlled(root, state['original']) if state['original'] else None
    published = controlled(root, state['published']) if state['published'] else None
    current = pointer(root, 'frontend-previous', True)
    if current not in (original, published):
        raise ValueError('frontend pointer changed after preparation')
    publish(root, original)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['prepare','restore'])
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.mode == 'prepare':
            if args.candidate is None:
                raise ValueError('candidate required')
            print(json.dumps(prepare(args.root,args.candidate,args.state)))
        else:
            restore(args.root,args.state)
    except (OSError,ValueError,KeyError) as error:
        raise SystemExit(str(error))
