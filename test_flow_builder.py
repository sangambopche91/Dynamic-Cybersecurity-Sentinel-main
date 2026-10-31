from pathlib import Path
import sys

BASE_DIR = Path(__file__).resolve().parent.parent.parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
from scapy.all import sniff

from services.v2.flow_builder import FlowBuilder


print("=" * 70)
print("DYNAMIC CYBERSECURITY SENTINEL")
print("V2 FLOW BUILDER TEST")
print("=" * 70)

builder = FlowBuilder()

print("\nCapturing real network packets...")
print("Please generate some network activity for about 10 seconds.")
print("For example: open a website or refresh a webpage.")
print("Press CTRL+C after the test if required.\n")


def process_packet(packet):
    flow = builder.add_packet(packet)

    if flow is None:
        return

    features = builder.get_flow_features(flow)

    print("-" * 70)
    print("LIVE FLOW DETECTED")
    print("-" * 70)

    print("Protocol :", features["proto"])
    print("Duration :", round(features["dur"], 4))
    print("Packets  :", features["spkts"] + features["dpkts"])
    print("Bytes    :", features["sbytes"] + features["dbytes"])
    print("Rate     :", round(features["rate"], 2))

    print("\n42 ML FEATURES:")

    print("dur =", features["dur"])
    print("proto =", features["proto"])
    print("service =", features["service"])
    print("state =", features["state"])
    print("spkts =", features["spkts"])
    print("dpkts =", features["dpkts"])
    print("sbytes =", features["sbytes"])
    print("dbytes =", features["dbytes"])
    print("rate =", features["rate"])
    print("sttl =", features["sttl"])
    print("dttl =", features["dttl"])
    print("sload =", features["sload"])
    print("dload =", features["dload"])
    print("sloss =", features["sloss"])
    print("dloss =", features["dloss"])
    print("sinpkt =", features["sinpkt"])
    print("dinpkt =", features["dinpkt"])
    print("sjit =", features["sjit"])
    print("djit =", features["djit"])
    print("swin =", features["swin"])
    print("stcpb =", features["stcpb"])
    print("dtcpb =", features["dtcpb"])
    print("dwin =", features["dwin"])
    print("tcprtt =", features["tcprtt"])
    print("synack =", features["synack"])
    print("ackdat =", features["ackdat"])
    print("smean =", features["smean"])
    print("dmean =", features["dmean"])
    print("trans_depth =", features["trans_depth"])
    print("response_body_len =", features["response_body_len"])
    print("ct_srv_src =", features["ct_srv_src"])
    print("ct_state_ttl =", features["ct_state_ttl"])
    print("ct_dst_ltm =", features["ct_dst_ltm"])
    print("ct_src_dport_ltm =", features["ct_src_dport_ltm"])
    print("ct_dst_sport_ltm =", features["ct_dst_sport_ltm"])
    print("ct_dst_src_ltm =", features["ct_dst_src_ltm"])
    print("is_ftp_login =", features["is_ftp_login"])
    print("ct_ftp_cmd =", features["ct_ftp_cmd"])
    print("ct_flw_http_mthd =", features["ct_flw_http_mthd"])
    print("ct_src_ltm =", features["ct_src_ltm"])
    print("ct_srv_dst =", features["ct_srv_dst"])
    print("is_sm_ips_ports =", features["is_sm_ips_ports"])

    print("-" * 70)


try:
    sniff(
        prn=process_packet,
        store=False,
        timeout=10
    )

except KeyboardInterrupt:
    print("\nCapture stopped by user.")

print("\n" + "=" * 70)
print("FLOW BUILDER TEST COMPLETED")
print("Total flows:", len(builder.flows))
print("=" * 70)