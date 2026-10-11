"""wlib.views agent-access helpers: decoding a Linux capability mask and deciding whether an agent's uid/gids
could read a file from its owner:group:mode stat. Pure functions, fully offline."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wlib import views  # noqa: E402


def test_caps_full_root():
    names, full = views._caps("000001ffffffffff")
    assert full is True
    assert "sys_admin" in names and "net_raw" in names


def test_caps_single_bit():
    names, full = views._caps("0000000000000400")   # bit 10 = cap_net_bind_service
    assert full is False and names == ["net_bind_service"]


def test_caps_net_admin():
    names, full = views._caps("%x" % (1 << 12))      # bit 12 = cap_net_admin
    assert names == ["net_admin"] and full is False


def test_caps_garbage_is_empty():
    assert views._caps("not-hex") == ([], False)
    assert views._caps(None) == ([], False)


def test_can_read_root_reads_anything():
    assert views._can_read(0, 0, "", "1000:1000:600") is True


def test_can_read_owner_bit():
    # owner 1000, mode 600 → owner can read, nobody else
    assert views._can_read(1000, 1000, "", "1000:1000:600") is True
    assert views._can_read(1001, 1001, "", "1000:1000:600") is False


def test_can_read_group_bit():
    # group 50, mode 640 → a member of group 50 can read
    assert views._can_read(1001, 50, "", "1000:50:640") is True
    assert views._can_read(1001, 99, "7 50 8", "1000:50:640") is True   # 50 among supplementary gids
    assert views._can_read(1001, 99, "7 8", "1000:50:640") is False


def test_can_read_other_bit():
    assert views._can_read(1001, 1001, "", "1000:1000:644") is True     # world-readable
    assert views._can_read(1001, 1001, "", "1000:1000:640") is False    # no other-read


def test_can_read_unknown_stat_is_none():
    assert views._can_read(1000, 1000, "", "garbage") is None
