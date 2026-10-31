from flow_schema import NetworkFlow


flow = NetworkFlow(
    dur=1.5,
    proto="tcp",
    service="http",
    state="FIN",

    spkts=10,
    dpkts=8,
    sbytes=1200,
    dbytes=900,
    rate=50,

    sttl=64,
    dttl=64,
    sload=1000,
    dload=800,

    sloss=0,
    dloss=0,
    sinpkt=0.15,
    dinpkt=0.12,
    sjit=0.01,
    djit=0.01,

    swin=255,
    stcpb=1000,
    dtcpb=2000,
    dwin=255,

    tcprtt=0.05,
    synack=0.02,
    ackdat=0.03,

    smean=120,
    dmean=112,
    trans_depth=1,
    response_body_len=500,

    ct_srv_src=2,
    ct_state_ttl=1,
    ct_dst_ltm=2,
    ct_src_dport_ltm=1,
    ct_dst_sport_ltm=1,
    ct_dst_src_ltm=1,

    is_ftp_login=0,
    ct_ftp_cmd=0,
    ct_flw_http_mthd=1,
    ct_src_ltm=2,
    ct_srv_dst=2,
    is_sm_ips_ports=0
)


print("NetworkFlow created successfully!")
print()
print("Flow data:")
print(flow.to_dict())