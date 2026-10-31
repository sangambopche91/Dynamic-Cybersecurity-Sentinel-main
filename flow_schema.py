from dataclasses import dataclass, asdict
from typing import Any, Dict


@dataclass
class NetworkFlow:
    """
    Standard internal network-flow representation
    used by Dynamic Cybersecurity Sentinel V2.
    """

    dur: float
    proto: str
    service: str
    state: str

    spkts: float
    dpkts: float
    sbytes: float
    dbytes: float
    rate: float

    sttl: float
    dttl: float
    sload: float
    dload: float

    sloss: float
    dloss: float
    sinpkt: float
    dinpkt: float
    sjit: float
    djit: float

    swin: float
    stcpb: float
    dtcpb: float
    dwin: float

    tcprtt: float
    synack: float
    ackdat: float

    smean: float
    dmean: float
    trans_depth: float
    response_body_len: float

    ct_srv_src: float
    ct_state_ttl: float
    ct_dst_ltm: float
    ct_src_dport_ltm: float
    ct_dst_sport_ltm: float
    ct_dst_src_ltm: float

    is_ftp_login: float
    ct_ftp_cmd: float
    ct_flw_http_mthd: float
    ct_src_ltm: float
    ct_srv_dst: float
    is_sm_ips_ports: float

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the NetworkFlow object into a dictionary.
        """
        return asdict(self)