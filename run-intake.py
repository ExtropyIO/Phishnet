import os
from uagents_core.utils.registration import (
    register_chat_agent,
    RegistrationRequestCredentials,
)

register_chat_agent(
    "Intake Agent",
    "http://TeeAge-Alb16-asYi7vJYnLGj-755747286.eu-west-1.elb.amazonaws.com/intake/",
    active=True,
    credentials=RegistrationRequestCredentials(
        agentverse_api_key="eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3NjE1NzAyMjgsImlhdCI6MTc2MTU2NjYyOCwiaXNzIjoiZmV0Y2guYWkiLCJqdGkiOiIxMzdhM2U1YmZlYWM5ZmM1Njk5NzlhM2QiLCJzY29wZSI6IiIsInN1YiI6IjE2ZGVlNDVlNGE3MGU1MmRiYTc1ZThlZDZkMjkyYjhmZWVjODNlMDk2MmYyYWNjZCJ9.HcN_FGHGcrYrtY7H4sXxT5W5zfK49RJ4DwSxYgEt--kbDNtIgQ6AmfnoYh9e81nGO2TXJzTmT36dsxN82Exg47759FG0XAU2sOdkD0JE68xtvG1HI1YydWlylgw4N48ZGyxl2wuey1zz1l8saV-kM5whc_VPYjM8SBy4IW5yj-_xNB_duBSv4_FrVbtciuiANK_3TsvMuA1wniyBZgRGGpa6tPnzRaY7FCNKaXXbipvz0rC9JINWSLl46XkzrHI9v6NIHWp9Fsj8rKxMgEH_3kcegz81WaYsVCwd7RNxevOSsmP-I8nbp9WyJTPbuqBIrGsC3S_VgslFNeygxwcSjg",
        agent_seed_phrase="intake-agent-seed",
    ),
)