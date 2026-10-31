import random
import time

from services.v2.flow_schema import NetworkFlow


def generate_flow():
    """
    Generate one simulated network flow.
    """

    protocols = ["tcp", "udp"]
    services = ["http", "https", "dns", "-"]
    states = ["FIN", "CON", "INT", "REQ"]

    flow = NetworkFlow(
        dur=round(random.uniform(0.1, 5.0), 3),

        proto=random.choice(protocols),
        service=random.choice(services),
        state=random.choice(states),

        spkts=random.randint(1, 50),
        dpkts=random.randint(1, 50),

        sbytes=random.randint(40, 5000),
        dbytes=random.randint(40, 5000),

        rate=round(random.uniform(1, 1000), 3),

        sttl=random.randint(32, 128),
        dttl=random.randint(32, 128),

        sload=round(random.uniform(10, 10000), 3),
        dload=round(random.uniform(10, 10000), 3),

        sloss=random.randint(0, 5),
        dloss=random.randint(0, 5),

        sinpkt=round(random.uniform(0.01, 2.0), 3),
        dinpkt=round(random.uniform(0.01, 2.0), 3),

        sjit=round(random.uniform(0, 1), 3),
        djit=round(random.uniform(0, 1), 3),

        swin=random.randint(0, 65535),
        stcpb=random.randint(0, 100000),
        dtcpb=random.randint(0, 100000),
        dwin=random.randint(0, 65535),

        tcprtt=round(random.uniform(0, 1), 3),
        synack=round(random.uniform(0, 1), 3),
        ackdat=round(random.uniform(0, 1), 3),

        smean=random.randint(40, 1500),
        dmean=random.randint(40, 1500),

        trans_depth=random.randint(0, 5),
        response_body_len=random.randint(0, 5000),

        ct_srv_src=random.randint(1, 10),
        ct_state_ttl=random.randint(1, 10),
        ct_dst_ltm=random.randint(1, 10),
        ct_src_dport_ltm=random.randint(1, 10),
        ct_dst_sport_ltm=random.randint(1, 10),
        ct_dst_src_ltm=random.randint(1, 10),

        is_ftp_login=random.randint(0, 1),
        ct_ftp_cmd=random.randint(0, 5),
        ct_flw_http_mthd=random.randint(0, 5),

        ct_src_ltm=random.randint(1, 10),
        ct_srv_dst=random.randint(1, 10),

        is_sm_ips_ports=random.randint(0, 1)
    )

    return flow


def start_fake_stream(interval=2):
    """
    Continuously generate network flows.
    """

    print("Starting simulated live network stream...")
    print("Press CTRL+C to stop.")
    print()

    counter = 1

    try:
        while True:

            flow = generate_flow()

            print(f"Flow #{counter}")
            print(flow.to_dict())
            print("-" * 80)

            counter += 1

            time.sleep(interval)

    except KeyboardInterrupt:
        print()
        print("Simulated live stream stopped.")


if __name__ == "__main__":
    start_fake_stream()