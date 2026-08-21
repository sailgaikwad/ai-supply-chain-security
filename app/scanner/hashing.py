import hashlib

def calculate_sha256(file_path: str, chunk_size: int = 8192) -> str:
    """
    Calculates the SHA-256 hash of a file using streaming reads.
    This ensures that large files are not loaded entirely into memory.
    
    Args:
        file_path: The path to the file on the local file system.
        chunk_size: The size of the chunks to read.
        
    Returns:
        The SHA-256 hex digest of the file.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()
