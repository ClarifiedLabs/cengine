"""VOL-023: real offline pip upgrade + nonroot multi-file backup/restore campaign."""
from types import ModuleType
from pathlib import Path

import pytest

_SOURCE = Path(__file__).parent / "fixtures/volume-workflows/campaign.py"
_campaign = ModuleType("volume_workflows_campaign")
_campaign.__file__ = str(_SOURCE)
exec(compile(_SOURCE.read_bytes(), str(_SOURCE), "exec"), _campaign.__dict__)


@pytest.mark.compat("VOL-023")
def test_offline_package_nonroot_multifile_backup_restore(daemon):
    # One ledger ID, no parameterized duplicate IDs. Both backend modes run serially.
    _campaign.run(daemon)
