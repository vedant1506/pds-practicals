import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def resolve_input_file(filename: str) -> str:
    if os.path.isabs(filename) and os.path.exists(filename):
        return filename

    candidates = [
        filename,
        os.path.join(BASE_DIR, filename),
        os.path.join(BASE_DIR, "data", "raw", os.path.basename(filename)),
        os.path.join(BASE_DIR, "data", "processed", os.path.basename(filename)),
        os.path.join(BASE_DIR, "data", "split", os.path.basename(filename)),
        os.path.join(BASE_DIR, "logs", os.path.basename(filename)),
        os.path.join("data", "raw", os.path.basename(filename)),
        os.path.join("data", "processed", os.path.basename(filename)),
        os.path.join("data", "split", os.path.basename(filename)),
    ]

    for cand in candidates:
        if os.path.exists(cand):
            return os.path.abspath(cand)

    return os.path.abspath(filename)


def resolve_export_file(filename: str, default_folder: str = "data/processed") -> str:
    if os.path.isabs(filename):
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        return filename

    target_path = os.path.join(BASE_DIR, default_folder, os.path.basename(filename))
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    return target_path
