import os
from uagents_core.utils.registration import (
    register_chat_agent,
    RegistrationRequestCredentials,
)

register_chat_agent(
    "Analyzer ",
    "http://TeeAge-Alb16-asYi7vJYnLGj-755747286.eu-west-1.elb.amazonaws.com/analyzer/",
    active=True,
    credentials=RegistrationRequestCredentials(
        agentverse_api_key="eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3NjE1NzkzODIsImlhdCI6MTc2MTU3NTc4MiwiaXNzIjoiZmV0Y2guYWkiLCJqdGkiOiI4NDdiZTMyMDliYTQ0MTBmMTNkOTFiY2UiLCJzY29wZSI6IiIsInN1YiI6IjE2ZGVlNDVlNGE3MGU1MmRiYTc1ZThlZDZkMjkyYjhmZWVjODNlMDk2MmYyYWNjZCJ9.glcHWn7dpObTi87BKKX2k8Ag7_tWEymLB_Zw7nDJB1a1d96NvaAIpItwW8cG583QyQr6X9CTQ-Q4hq6AaxWLPpBhQ-PBTXcFnBow4Gt07LOAzp1CQJ2C4t_97UPxjy4r-wvbY57B5B0mkadZ1BxwLO_I8pGwYqKI3xgXv0gaqAo95-ru0VPzYpam9IoYrATD-HauGxQxo1yEJi4oDJY85hv_I2S6Q9-4sHiUPjTFRkMwgR7bkIcgrcYlIde9Ve6kkZs2ceqg1Tn5oCD0uZIgSqWJTlEjp0D9Unao1UXk3AaTQosZxznrpz78kF7RtRNez1xcpx96QBbM6fSoB30KOA",
        agent_seed_phrase="analyzer-agent-seed",
    ),
)