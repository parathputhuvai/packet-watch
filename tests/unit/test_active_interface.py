from packet_watch.capture.active_interface import find_active_interface, map_guid_to_npcap


WIFI_GUID = "{2AB61363-7FF7-412E-8ED4-D432E4C2B0EC}"


def test_map_guid_to_npcap_matches_guid_inside_npf_name():
    interfaces = [
        r"\\Device\\NPF_{11111111-1111-1111-1111-111111111111}",
        rf"\\Device\\NPF_{WIFI_GUID}",
    ]

    assert map_guid_to_npcap(WIFI_GUID, interfaces) == rf"\\Device\\NPF_{WIFI_GUID}"


def test_map_guid_to_npcap_returns_none_when_guid_is_missing():
    assert map_guid_to_npcap(WIFI_GUID, ["Npcap Loopback Adapter"]) is None


def test_find_active_interface_maps_first_resolvable_adapter():
    adapters = [
        {
            "FriendlyName": "Disconnected Ethernet",
            "Status": "Up",
            "InterfaceGuid": "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
            "IPv4Address": "10.0.0.2",
            "Gateway": "10.0.0.1",
        },
        {
            "FriendlyName": "Wi-Fi",
            "Status": "Up",
            "InterfaceGuid": WIFI_GUID,
            "IPv4Address": "192.168.100.5",
            "Gateway": "192.168.100.1",
        },
    ]
    npcap = [rf"\\Device\\NPF_{WIFI_GUID}"]

    result = find_active_interface(lambda: adapters, lambda: npcap)

    assert result.friendly_name == "Wi-Fi"
    assert result.ipv4_address == "192.168.100.5"
    assert result.gateway == "192.168.100.1"
    assert result.npcap_interface == rf"\\Device\\NPF_{WIFI_GUID}"


def test_monitor_auto_reuses_existing_monitor_method():
    from packet_watch.capture.active_interface import ActiveInterfaceInfo
    from packet_watch.cli.app import PacketWatchApp

    info = ActiveInterfaceInfo(
        friendly_name="Wi-Fi",
        status="Up",
        ipv4_address="192.168.100.5",
        gateway="192.168.100.1",
        interface_guid=WIFI_GUID,
        npcap_interface=rf"\\Device\\NPF_{WIFI_GUID}",
    )

    class DummyConsole:
        def print(self, *args, **kwargs):
            return None

    app = object.__new__(PacketWatchApp)
    app.console = DummyConsole()
    app.get_active_interface = lambda: info
    calls = []
    app.monitor = lambda interface: calls.append(interface)

    result = app.monitor_auto()

    assert result is None
    assert calls == [info.npcap_interface]
