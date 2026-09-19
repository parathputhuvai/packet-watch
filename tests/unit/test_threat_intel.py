from packet_watch.threat_intel.ja3 import calculate_ja3


def test_ja3_calculation_filters_grease():
    class E:
        def __init__(self): self.type = 10; self.groups = [29, 0x0A0A]; self.ecpl = [0]
    class H:
        version = 771
        ciphers = [0x1301, 0x0A0A, 0x1302]
        ext = [E()]
    value, md5 = calculate_ja3(H())
    assert value == "771,4865-4866,10,29,0"
    assert len(md5) == 32
