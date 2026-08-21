import os
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class ArtifactInventory:
    total_files: int = 0
    total_bytes: int = 0
    python_files: int = 0
    dependency_manifests: int = 0
    lockfiles: int = 0
    models: int = 0
    extensions: Dict[str, int] = None

    def __post_init__(self):
        if self.extensions is None:
            self.extensions = {}

def inventory_directory(directory: str) -> ArtifactInventory:
    """
    Recursively scans the directory and computes the ArtifactInventory.
    """
    inv = ArtifactInventory()
    
    manifest_names = {'requirements.txt', 'requirements-dev.txt', 'pyproject.toml'}
    lockfile_names = {'Pipfile.lock', 'poetry.lock', 'uv.lock', 'pylock.toml'}
    model_extensions = {'.h5', '.pb', '.pt', '.pth', '.onnx', '.tflite', '.bin', '.safetensors'}
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                size = os.path.getsize(file_path)
            except OSError:
                continue
                
            inv.total_files += 1
            inv.total_bytes += size
            
            _, ext = os.path.splitext(file)
            ext = ext.lower()
            
            inv.extensions[ext] = inv.extensions.get(ext, 0) + 1
            
            if ext == '.py':
                inv.python_files += 1
            elif ext in model_extensions:
                inv.models += 1
                
            if file in manifest_names:
                inv.dependency_manifests += 1
            elif file in lockfile_names:
                inv.lockfiles += 1

    return inv
