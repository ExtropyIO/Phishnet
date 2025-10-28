import os
from uagents_core.utils.registration import (
    register_chat_agent,
    RegistrationRequestCredentials,
)

register_chat_agent(
    "Intake",
    "http://TeeAge-Alb16-asYi7vJYnLGj-755747286.eu-west-1.elb.amazonaws.com/intake/",
    active=True,
    credentials=RegistrationRequestCredentials(
        agentverse_api_key="eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3NjE2NDU5NzksImlhdCI6MTc2MTY0MjM3OSwiaXNzIjoiZmV0Y2guYWkiLCJqdGkiOiI4NDdiZTMyMDliYTQ0MTBmMTNkOTFiY2UiLCJzY29wZSI6IiIsInN1YiI6IjE2ZGVlNDVlNGE3MGU1MmRiYTc1ZThlZDZkMjkyYjhmZWVjODNlMDk2MmYyYWNjZCJ9.dH16eE2_cVo6tLkoXjOkSRHwBKG-XYYG80_0PbiWMHOLw8MgS1L6e-8MkYnvHyc_fLskRGjx_3eWUZaNSR6JcGVhZmfoz71GephSbl8dENjn5ut5GgUzgh95Bz2cngxa1hxKsK79mtRsdA9aFC-w8LssRfOuBwtFH3_87iqoerVkh3sFSx2T5HDqNxuSlvqjvCGhatL_q-sluEex-nzRpUZUhcaCyVgmu0sx6Kp46uto__OivAq_tbUWtEeEB-nFesbigEveMJiG0mn_jrBJotKizhRIzU7DN8vykya8JGkCIv2FogpcKVAQas-dNXOjS_f19of6teIAOmRXUdgCfQ",
        agent_seed_phrase="intake-agent-seed",
    ),
)