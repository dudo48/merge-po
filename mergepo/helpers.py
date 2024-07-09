import pickle
from pathlib import Path


def load_persistent_data(path: Path):
    return pickle.loads(path.read_bytes()) if path.is_file() else None


def save_persistent_data(path: Path, data: object):
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.write_bytes(pickle.dumps(data))
