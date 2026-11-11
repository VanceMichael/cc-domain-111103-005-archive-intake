from pathlib import Path
from app.archive import inspect_archive
print(inspect_archive("fixtures/package.zip")[0])
