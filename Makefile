.PHONY: ecr-login build push deploy bounce health analyze all

ecr-login:
	bash scripts/ecr_login.sh

build push:
	bash scripts/build_push.sh

deploy:
	bash scripts/roll_services.sh

bounce:
	bash scripts/bounce_services.sh

health:
	bash scripts/test_health.sh

analyze:
	bash scripts/test_analyze.sh

all:
	bash scripts/redeploy.sh
