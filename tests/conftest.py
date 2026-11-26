import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from labscout.config import Config
from labscout.models import Host, HttpInfo, Port, ProxmoxGuest


@pytest.fixture
def cfg(tmp_path):
    c = Config()
    c.state_dir = str(tmp_path / "state")
    c.networks = ["10.0.3.0/24"]
    c.domain = "home.example.org"
    return c


@pytest.fixture
def grafana_host():
    return Host(ip="10.0.3.116", hostname="grafana.lan", ports=[Port(3000, service="http"), Port(22)],
                http=[HttpInfo(port=3000, status=302, title="Grafana", location="/login")],
                proxmox=ProxmoxGuest(endpoint="home", node="node05", vmid=118, type="lxc",
                                     name="grafana", tags=["community-script", "monitoring"]))


@pytest.fixture
def mystery_host():
    return Host(ip="10.0.3.99", ports=[Port(8085, service="http"), Port(22)],
                http=[HttpInfo(port=8085, status=200, title="Kitchen Owl")],
                proxmox=ProxmoxGuest(endpoint="home", node="node06", vmid=170, type="lxc",
                                     name="recipes", tags=["community-script"]))


class FakeOllama:
    """Stands in for OllamaClient.chat_json and records the prompts."""

    def __init__(self, answer: dict):
        self.answer = answer
        self.calls = []

    def chat_json(self, system, user, schema):
        self.calls.append(user)
        return dict(self.answer)
