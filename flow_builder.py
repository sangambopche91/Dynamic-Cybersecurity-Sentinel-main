from collections import defaultdict
from datetime import datetime


class FlowBuilder:
    """
    Converts individual network packets into aggregated network flows.

    A flow is identified using:
        source IP
        destination IP
        source port
        destination port
        protocol
    """

    def __init__(self):
        self.flows = defaultdict(self._new_flow)

    @staticmethod
    def _new_flow():
        return {
            "start_time": None,
            "last_time": None,

            "src_ip": None,
            "dst_ip": None,
            "src_port": 0,
            "dst_port": 0,
            "proto": "other",

            "spkts": 0,
            "dpkts": 0,
            "sbytes": 0,
            "dbytes": 0,

            "packet_sizes_src": [],
            "packet_sizes_dst": [],

            "ttl_src": [],
            "ttl_dst": [],

            "syn_count": 0,
            "synack_count": 0,
            "ack_count": 0,

            "src_windows": [],
            "dst_windows": [],

            "last_src_time": None,
            "last_dst_time": None,

            "src_intervals": [],
            "dst_intervals": []
        }

    @staticmethod
    def _get_timestamp(packet):
        """
        Get packet timestamp.
        """

        try:
            return float(packet.time)
        except Exception:
            return datetime.now().timestamp()

    @staticmethod
    def _get_protocol(packet):
        """
        Detect TCP/UDP/other protocol.
        """

        from scapy.all import TCP, UDP

        if TCP in packet:
            return "tcp"

        if UDP in packet:
            return "udp"

        return "other"

    @staticmethod
    def _get_ports(packet):
        """
        Extract source and destination ports.
        """

        from scapy.all import TCP, UDP

        if TCP in packet:
            return packet[TCP].sport, packet[TCP].dport

        if UDP in packet:
            return packet[UDP].sport, packet[UDP].dport

        return 0, 0

    def add_packet(self, packet):
        """
        Add one captured packet to its corresponding flow.

        Returns the current flow dictionary.
        """

        from scapy.all import IP, TCP

        if IP not in packet:
            return None

        timestamp = self._get_timestamp(packet)

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        src_port, dst_port = self._get_ports(packet)

        proto = self._get_protocol(packet)

        # Use a bidirectional key so that both directions
        # of the same connection belong to one flow.
        endpoint_a = (src_ip, src_port)
        endpoint_b = (dst_ip, dst_port)

        if endpoint_a <= endpoint_b:
            flow_key = (
                endpoint_a,
                endpoint_b,
                proto
            )
        else:
            flow_key = (
                endpoint_b,
                endpoint_a,
                proto
            )

        flow = self.flows[flow_key]

        # Initialize flow
        if flow["start_time"] is None:

            flow["start_time"] = timestamp

            flow["src_ip"] = src_ip
            flow["dst_ip"] = dst_ip

            flow["src_port"] = src_port
            flow["dst_port"] = dst_port

            flow["proto"] = proto

        flow["last_time"] = timestamp

        packet_size = len(packet)

        # Determine whether this packet belongs to
        # the original source direction.
        original_direction = (
            src_ip == flow["src_ip"]
            and dst_ip == flow["dst_ip"]
            and src_port == flow["src_port"]
            and dst_port == flow["dst_port"]
        )

        if original_direction:

            flow["spkts"] += 1
            flow["sbytes"] += packet_size

            if TCP in packet:
                flow["src_windows"].append(packet[TCP].window)

            flow["packet_sizes_src"].append(packet_size)

            if hasattr(packet[IP], "ttl"):
                flow["ttl_src"].append(packet[IP].ttl)

            if flow["last_src_time"] is not None:
                interval = timestamp - flow["last_src_time"]
                flow["src_intervals"].append(interval)

            flow["last_src_time"] = timestamp

        else:

            flow["dpkts"] += 1
            flow["dbytes"] += packet_size

            if TCP in packet:
                flow["dst_windows"].append(packet[TCP].window)

            flow["packet_sizes_dst"].append(packet_size)

            if hasattr(packet[IP], "ttl"):
                flow["ttl_dst"].append(packet[IP].ttl)

            if flow["last_dst_time"] is not None:
                interval = timestamp - flow["last_dst_time"]
                flow["dst_intervals"].append(interval)

            flow["last_dst_time"] = timestamp

        # TCP flags
        if TCP in packet:

            flags = str(packet[TCP].flags)

            if "S" in flags and "A" not in flags:
                flow["syn_count"] += 1

            if "S" in flags and "A" in flags:
                flow["synack_count"] += 1

            if "A" in flags:
                flow["ack_count"] += 1

        return flow

    @staticmethod
    def _mean(values, default=0.0):
        if not values:
            return default

        return sum(values) / len(values)

    def get_flow_features(self, flow):
        """
        Convert an aggregated flow into the 42-feature
        NetworkFlow-compatible dictionary.

        Some UNSW-NB15 features cannot be reconstructed
        exactly from raw packets alone. Those fields are
        represented using conservative flow-derived values.
        """

        duration = max(
            flow["last_time"] - flow["start_time"],
            0.000001
        )

        total_packets = flow["spkts"] + flow["dpkts"]

        total_bytes = flow["sbytes"] + flow["dbytes"]

        rate = total_packets / duration

        sload = (flow["sbytes"] * 8) / duration
        dload = (flow["dbytes"] * 8) / duration

        sinpkt = self._mean(flow["src_intervals"])
        dinpkt = self._mean(flow["dst_intervals"])

        smean = self._mean(flow["packet_sizes_src"])
        dmean = self._mean(flow["packet_sizes_dst"])

        sttl = self._mean(flow["ttl_src"], 64)
        dttl = self._mean(flow["ttl_dst"], 64)

        swin = self._mean(flow["src_windows"])
        dwin = self._mean(flow["dst_windows"])

        synack = (
            1.0
            if flow["synack_count"] > 0
            else 0.0
        )

        ackdat = (
            1.0
            if flow["ack_count"] > 0
            else 0.0
        )

        # Port/service inference
        destination_port = flow["dst_port"]

        if destination_port == 80:
            service = "http"

        elif destination_port == 443:
            service = "https"

        elif destination_port == 53:
            service = "dns"

        elif destination_port == 21:
            service = "ftp"

        else:
            service = "-"

        # TCP connection state approximation
        if flow["proto"] == "tcp":

            if flow["syn_count"] > 0 and flow["synack_count"] > 0:
                state = "CON"

            elif flow["syn_count"] > 0:
                state = "REQ"

            else:
                state = "FIN"

        else:
            state = "INT"

        return {
            "dur": duration,
            "proto": flow["proto"],
            "service": service,
            "state": state,

            "spkts": flow["spkts"],
            "dpkts": flow["dpkts"],

            "sbytes": flow["sbytes"],
            "dbytes": flow["dbytes"],

            "rate": rate,

            "sttl": sttl,
            "dttl": dttl,

            "sload": sload,
            "dload": dload,

            "sloss": 0.0,
            "dloss": 0.0,

            "sinpkt": sinpkt,
            "dinpkt": dinpkt,

            "sjit": 0.0,
            "djit": 0.0,

            "swin": swin,
            "stcpb": 0.0,

            "dtcpb": 0.0,
            "dwin": dwin,

            "tcprtt": 0.0,
            "synack": synack,
            "ackdat": ackdat,

            "smean": smean,
            "dmean": dmean,

            "trans_depth": 0.0,
            "response_body_len": 0.0,

            "ct_srv_src": 1.0,
            "ct_state_ttl": 1.0,
            "ct_dst_ltm": 1.0,
            "ct_src_dport_ltm": 1.0,
            "ct_dst_sport_ltm": 1.0,
            "ct_dst_src_ltm": 1.0,

            "is_ftp_login": 0.0,
            "ct_ftp_cmd": 0.0,
            "ct_flw_http_mthd": 0.0,

            "ct_src_ltm": 1.0,
            "ct_srv_dst": 1.0,

            "is_sm_ips_ports": (
                1.0
                if (
                    flow["src_ip"] == flow["dst_ip"]
                    and flow["src_port"] == flow["dst_port"]
                )
                else 0.0
            )
        }