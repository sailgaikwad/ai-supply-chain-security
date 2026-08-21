import os
import tempfile
import zipfile
import pytest
from app.scanner.extraction import safe_extract, ExtractionLimits

def create_synthetic_zip(path: str, contents: dict):
    with zipfile.ZipFile(path, 'w') as zf:
        for name, data in contents.items():
            zf.writestr(name, data)

def test_safe_extract_normal():
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "normal.zip")
        extract_dir = os.path.join(temp_dir, "extract")
        create_synthetic_zip(zip_path, {"test.py": b"print('hello')"})
        
        result = safe_extract(zip_path, extract_dir)
        assert result.success is True
        assert os.path.exists(os.path.join(extract_dir, "test.py"))

def test_safe_extract_path_traversal():
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "traversal.zip")
        extract_dir = os.path.join(temp_dir, "extract")
        create_synthetic_zip(zip_path, {"../evil.py": b"print('evil')"})
        
        result = safe_extract(zip_path, extract_dir)
        assert result.success is False
        assert "Path traversal attempt detected" in result.reason
        assert not os.path.exists(os.path.join(temp_dir, "evil.py"))

def test_safe_extract_absolute_path():
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "absolute.zip")
        extract_dir = os.path.join(temp_dir, "extract")
        create_synthetic_zip(zip_path, {"/etc/passwd": b"root:x:0:0:"})
        
        result = safe_extract(zip_path, extract_dir)
        assert result.success is False
        assert "Path traversal attempt detected" in result.reason

def test_safe_extract_excessive_entries():
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "many.zip")
        extract_dir = os.path.join(temp_dir, "extract")
        
        # Create a zip with 15 entries
        contents = {f"file{i}.txt": b"data" for i in range(15)}
        create_synthetic_zip(zip_path, contents)
        
        limits = ExtractionLimits(max_files=10)
        result = safe_extract(zip_path, extract_dir, limits)
        
        assert result.success is False
        assert "Archive contains too many files" in result.reason

def test_safe_extract_excessive_declared_size():
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "huge.zip")
        extract_dir = os.path.join(temp_dir, "extract")
        
        # Actually write a 10MB file which will be highly compressed
        payload = b'\0' * (10 * 1024 * 1024) # 10MB
        with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('big.txt', payload)
            
        limits = ExtractionLimits(max_extracted_size=5 * 1024 * 1024) # 5MB limit
        result = safe_extract(zip_path, extract_dir, limits)
        
        assert result.success is False
        assert "Archive declared size exceeds limit" in result.reason

def test_safe_extract_compression_ratio():
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "ratio.zip")
        extract_dir = os.path.join(temp_dir, "extract")
        
        # Create a highly compressible payload
        payload = b'\0' * (5 * 1024 * 1024) # 5MB
        with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('ratio.txt', payload)
            
        # The 5MB payload of zeros will compress to ~5KB, making ratio ~1000x
        limits = ExtractionLimits(max_compression_ratio=10) # limit to 10x
        result = safe_extract(zip_path, extract_dir, limits)
        
        assert result.success is False
        assert "Archive exceeds maximum compression ratio" in result.reason

def test_safe_extract_malformed_archive():
    with tempfile.TemporaryDirectory() as temp_dir:
        malformed_path = os.path.join(temp_dir, "bad.zip")
        extract_dir = os.path.join(temp_dir, "extract")
        
        with open(malformed_path, 'wb') as f:
            f.write(b"NOT A ZIP FILE")
            
        result = safe_extract(malformed_path, extract_dir)
        assert result.success is False
        assert "Unsupported archive format" in result.reason
