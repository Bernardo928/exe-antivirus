import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

# Dados de teste isolados (nunca mexe na quarentena/configuração real do usuário)
_DATA = tempfile.mkdtemp(prefix="exeav-test-data-")
os.environ["EXEAV_DATA_DIR"] = _DATA
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def engine():
    from exeav import config
    from exeav.engine.engine import Engine
    return Engine(config.Settings())


@pytest.fixture()
def tmpdir_path(tmp_path):
    return tmp_path
