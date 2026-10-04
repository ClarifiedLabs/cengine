"""Repo-owned, deterministic pure-Python wheels; importing never installs/runs them."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import zipfile

IMAGE = "mirror.gcr.io/library/python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0"
MAX_WHEEL = 32 * 1024
VERSIONS = ("1.0", "2.0")


def wheel(version):
    if type(version) is not str or version not in VERSIONS:
        raise ValueError("only fixture versions 1.0 and 2.0 are allowed")
    dist = f"volume_workflow-{version}.dist-info"
    files = {
        "volume_workflow/__init__.py": b"",
        "volume_workflow/cli.py": (
            "from importlib.resources import files\n"
            "def main():\n"
            f"    print('volume-workflow {version}: ' + files('volume_workflow').joinpath('message.txt').read_text().strip())\n"
        ).encode(),
        "volume_workflow/message.txt": ("first resource\n" if version == "1.0" else "upgraded resource\n").encode(),
        f"{dist}/METADATA": f"Metadata-Version: 2.1\nName: volume-workflow\nVersion: {version}\n".encode(),
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nGenerator: cengine-stdlib-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{dist}/entry_points.txt": b"[console_scripts]\nvolume-workflow = volume_workflow.cli:main\n",
    }
    files[f"volume_workflow/{'v1_only' if version == '1.0' else 'v2_only'}.txt"] = version.encode()
    records = io.StringIO(newline="")
    writer = csv.writer(records, lineterminator="\n")
    for name, content in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        writer.writerow([name, "sha256=" + digest, str(len(content))])
    writer.writerow([f"{dist}/RECORD", "", ""])
    files[f"{dist}/RECORD"] = records.getvalue().encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    data = output.getvalue()
    if len(data) > MAX_WHEEL:
        raise ValueError("wheel exceeds fixture bound")
    return f"volume_workflow-{version}-py3-none-any.whl", data
