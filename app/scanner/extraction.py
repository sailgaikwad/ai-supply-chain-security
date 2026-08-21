import os
import tarfile
import zipfile
import shutil
from dataclasses import dataclass

@dataclass
class ExtractionLimits:
    max_extracted_size: int = 500 * 1024 * 1024  # 500 MB
    max_compressed_size: int = 100 * 1024 * 1024 # 100 MB
    max_files: int = 10000
    max_single_file_size: int = 100 * 1024 * 1024 # 100 MB
    max_compression_ratio: int = 100

@dataclass
class ExtractionResult:
    success: bool
    path: str
    reason: str = ""

def is_safe_path(base_dir: str, target_path: str) -> bool:
    """
    Check if the target_path resolves to a path inside the base_dir.
    Used to prevent Zip-Slip / Path Traversal vulnerabilities.
    """
    base_dir = os.path.abspath(base_dir)
    target_path = os.path.abspath(target_path)
    return target_path.startswith(base_dir + os.sep) or target_path == base_dir

def safe_extract(archive_path: str, extract_to: str, limits: ExtractionLimits = None) -> ExtractionResult:
    """
    Safely extract a ZIP or TAR archive to the extract_to directory.
    Enforces decompression bomb limits, path traversal prevention, etc.
    """
    if limits is None:
        limits = ExtractionLimits()
        
    if not os.path.exists(archive_path):
        return ExtractionResult(False, extract_to, "Archive does not exist")
        
    archive_size = os.path.getsize(archive_path)
    if archive_size > limits.max_compressed_size:
        return ExtractionResult(False, extract_to, f"Archive exceeds maximum compressed size: {archive_size} > {limits.max_compressed_size}")
        
    # Attempt extraction
    os.makedirs(extract_to, exist_ok=True)
    
    total_extracted_size = 0
    extracted_files = 0
    
    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path, 'r') as zf:
                # Pre-extraction check
                infolist = zf.infolist()
                if len(infolist) > limits.max_files:
                    return _fail_extraction(extract_to, f"Archive contains too many files: {len(infolist)} > {limits.max_files}")
                
                total_declared_size = sum(info.file_size for info in infolist)
                if total_declared_size > limits.max_extracted_size:
                    return _fail_extraction(extract_to, f"Archive declared size exceeds limit: {total_declared_size} > {limits.max_extracted_size}")
                if archive_size > 0 and (total_declared_size / archive_size) > limits.max_compression_ratio:
                    return _fail_extraction(extract_to, f"Archive exceeds maximum compression ratio: > {limits.max_compression_ratio}x")

                for member in infolist:
                    if member.is_dir():
                        continue
                    
                    if member.file_size > limits.max_single_file_size:
                        return _fail_extraction(extract_to, f"File {member.filename} exceeds single file size limit.")
                        
                    target_path = os.path.join(extract_to, member.filename)
                    if not is_safe_path(extract_to, target_path):
                        return _fail_extraction(extract_to, f"Path traversal attempt detected: {member.filename}")
                        
                    # Create directories
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    
                    # Streaming extraction
                    with zf.open(member, 'r') as source, open(target_path, 'wb') as target:
                        copied_bytes = 0
                        while True:
                            chunk = source.read(8192)
                            if not chunk:
                                break
                            target.write(chunk)
                            copied_bytes += len(chunk)
                            total_extracted_size += len(chunk)
                            
                            if copied_bytes > limits.max_single_file_size:
                                return _fail_extraction(extract_to, f"File {member.filename} exceeded single file limit during extraction.")
                            if total_extracted_size > limits.max_extracted_size:
                                return _fail_extraction(extract_to, "Total extracted size exceeded limit during extraction.")
                                
                    extracted_files += 1

            return ExtractionResult(True, extract_to)
            
        elif tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, 'r') as tf:
                members = tf.getmembers()
                if len(members) > limits.max_files:
                    return _fail_extraction(extract_to, f"Archive contains too many files: {len(members)} > {limits.max_files}")
                    
                total_declared_size = sum(m.size for m in members)
                if total_declared_size > limits.max_extracted_size:
                    return _fail_extraction(extract_to, f"Archive declared size exceeds limit: {total_declared_size} > {limits.max_extracted_size}")
                if archive_size > 0 and (total_declared_size / archive_size) > limits.max_compression_ratio:
                    return _fail_extraction(extract_to, f"Archive exceeds maximum compression ratio: > {limits.max_compression_ratio}x")

                for member in members:
                    if not member.isfile():
                        continue
                        
                    if member.size > limits.max_single_file_size:
                        return _fail_extraction(extract_to, f"File {member.name} exceeds single file size limit.")
                        
                    target_path = os.path.join(extract_to, member.name)
                    if not is_safe_path(extract_to, target_path):
                        return _fail_extraction(extract_to, f"Path traversal attempt detected: {member.name}")
                        
                    # Create directories
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    
                    # Streaming extraction
                    f = tf.extractfile(member)
                    if f:
                        with open(target_path, 'wb') as target:
                            copied_bytes = 0
                            while True:
                                chunk = f.read(8192)
                                if not chunk:
                                    break
                                target.write(chunk)
                                copied_bytes += len(chunk)
                                total_extracted_size += len(chunk)
                                
                                if copied_bytes > limits.max_single_file_size:
                                    return _fail_extraction(extract_to, f"File {member.name} exceeded single file limit during extraction.")
                                if total_extracted_size > limits.max_extracted_size:
                                    return _fail_extraction(extract_to, "Total extracted size exceeded limit during extraction.")
                    extracted_files += 1
                    
            return ExtractionResult(True, extract_to)
            
    except Exception as e:
        return _fail_extraction(extract_to, f"Extraction error: {str(e)}")
        
    return ExtractionResult(False, extract_to, "Unsupported archive format")

def _fail_extraction(extract_to: str, reason: str) -> ExtractionResult:
    """Helper to clean up the directory on failure and return the reason."""
    try:
        shutil.rmtree(extract_to, ignore_errors=True)
    except Exception:
        pass
    return ExtractionResult(False, extract_to, reason)
