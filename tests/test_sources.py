import time

from helpers import ethernet, ipv4_tcp, pcap

from netmon.sources import PcapSource


def test_pcap_file(tmp_path):
    f = tmp_path / "t.pcap"
    f.write_bytes(pcap([ethernet(ipv4_tcp("192.168.1.2", "1.2.3.4", 50000, 443)) for _ in range(3)]))
    got = []
    src = PcapSource(str(f), realtime=False)
    src.start(got.append)
    deadline = time.monotonic() + 5
    while not src.finished and time.monotonic() < deadline:
        time.sleep(0.01)
    assert src.error is None
    assert len(got) == 3 and got[0].dport == 443
