import hashlib
import json
from pathlib import Path
import zipfile

def inspect_archive(path):
    with zipfile.ZipFile(path) as archive:
        names=[item.filename for item in archive.infolist()]
        manifest=json.loads(archive.read("manifest.json"))
        return [{"name":name,"size":info.file_size,"sha256":hashlib.sha256(archive.read(info)).hexdigest()} for name in names if name!="manifest.json" for info in archive.infolist() if info.filename==name],manifest
