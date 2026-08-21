import os
import tarfile
import zipfile

def is_safe_path(base_dir: str, target_path: str) -> bool:
    """
    Check if the target_path resolves to a path inside the base_dir.
    Used to prevent Zip-Slip / Path Traversal vulnerabilities.
    """
    base_dir = os.path.abspath(base_dir)
    target_path = os.path.abspath(target_path)
    return target_path.startswith(base_dir + os.sep) or target_path == base_dir

def safe_extract(archive_path: str, extract_to: str) -> bool:
    """
    Safely extract a ZIP or TAR archive to the extract_to directory.
    Returns True if extraction was successful, False otherwise.
    """
    if not os.path.exists(archive_path):
        return False
        
    os.makedirs(extract_to, exist_ok=True)
    
    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path, 'r') as zf:
                for member in zf.infolist():
                    target_path = os.path.join(extract_to, member.filename)
                    if not is_safe_path(extract_to, target_path):
                        continue
                    zf.extract(member, extract_to)
            return True
            
        elif tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, 'r') as tf:
                for member in tf.getmembers():
                    target_path = os.path.join(extract_to, member.name)
                    if not is_safe_path(extract_to, target_path):
                        continue
                    # In python 3.12+, tarfile has a filter='data' which prevents some of this, 
                    # but manual check provides backward compatibility
                    tf.extract(member, extract_to)
            return True
            
    except Exception:
        pass
        
    return False
