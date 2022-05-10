# import config.
# Default config can be changed with `make cnf="config_special.env" command`
cnf ?= configs/dev/config.env
include $(cnf)
export $(shell sed 's/=.*//' $(cnf))

# Create allconfig.env to create a single config file out of multiple files, so we can pass to docker
allcnf ?= configs/dev/allconfig.env
$(shell cat $(cnf) > $(allcnf))

# import local config.
# Local config can be changed with `make localcnf="local_special.env" command`
localcnf ?= configs/dev/local.env
ifneq ("$(wildcard $(localcnf))","")
	include $(localcnf)
	export $(shell sed 's/=.*//' $(localcnf))
    $(shell cat $(localcnf) >> $(allcnf))
endif

# import deploy config
# Default config can be changed with `make dpl="deploy_special.env" command`
dpl ?= configs/dev/deploy.env
include $(dpl)
export $(shell sed 's/=.*//' $(dpl))

# import token config
# Default config can be changed with `make tkn="deploy_special.env" command`
tkn ?= configs/dev/token.env
ifneq ("$(wildcard $(tkn))","")
	include $(tkn)
	export $(shell sed 's/=.*//' $(tkn))
	export CI_READ_COMMON=$(GITHUB_TOKEN)
endif

includePath = vendor/github.com/descope/common/pkg/common/proto/include
ifeq ($(REPO_NAME), common)
	includePath = pkg/$(REPO_NAME)/proto/include
endif

# HELP
# This will output the help for each task
.PHONY: help build run

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

proto:
	protoc -Ipkg/$(REPO_NAME)/proto/v1 -I$(includePath) --go_out=:. --go-grpc_out=:. --grpc-gateway_out=:. --openapiv2_out=:pkg/$(REPO_NAME)/proto/v1/doc --openapiv2_opt logtostderr=true --openapiv2_opt use_go_templates=true pkg/$(REPO_NAME)/proto/v1/*.proto; \
	docker run --platform linux/amd64 --rm -v $(CURDIR)/pkg/$(REPO_NAME)/proto/v1/doc:/out -v $(CURDIR)/pkg/$(REPO_NAME)/proto/v1:/protos -v $(CURDIR)/$(includePath):/include pseudomuto/protoc-gen-doc -Iinclude; \

build: ## Build the container
	DOCKER_BUILDKIT=1 docker build -f $(DOCKER_FILE) --target base --secret id=github_token,env=CI_READ_COMMON --build-arg build_dir=$(BUILD_DIR) --build-arg port=$(CONTAINER_PORT) --build-arg repo_name=$(REPO_NAME) -t $(IMAGE_NAME) .

build-prod: ## Build the container for prod
	DOCKER_BUILDKIT=1 docker build -f $(DOCKER_FILE) --secret id=github_token,env=CI_READ_COMMON --build-arg build_dir=$(BUILD_DIR) --build-arg port=$(CONTAINER_PORT) --build-arg repo_name=$(REPO_NAME) -t $(IMAGE_NAME) .

run: ## Run container
	docker run -i --rm --env-file=$(allcnf) -p=$(CONTAINER_PORT):$(GRPC_PORT) -p=$(CONTAINER_HTTP_PORT):$(HTTP_PORT) --name="$(CONTAINER_NAME)" $(IMAGE_NAME) $(ENTRY_NAME)

up: build run ## Run container on port configured in `config.env` (Alias to run)

stop: ## Stop and remove a running container
	docker stop $(CONTAINER_NAME)

port: ## Get the configured container port
	@echo $(CONTAINER_PORT)

start-db: ## Start database (postgresql)
	docker run -d --name postgresql-container -p 5432:5432 -e POSTGRES_PASSWORD=passwordless postgres

clean-db: ## Clean database (postgresql)
	docker rm -f postgresql-container

start-rabbitmq: ## Start queue (rabbitmq)
	docker run -d --hostname my-rabbit --name rabbit-container -p 5672:5672 -p 15672:15672 rabbitmq:3-management-alpine

clean-rabbitmq: ## Clean queue (rabbitmq)
	docker rm -f rabbit-container

start-cache: ## Start cache (redis)
	docker run -d --name redis-container -p 6379:6379 redis

clean-cache: ## Clean cache (redis)
	docker rm -f redis-container

dev-env: start-db start-rabbitmq start-cache ## Start dev env 3rd party services

clean-dev-env: clean-db clean-rabbitmq clean-cache ## Clean dev env 3rd party services

compose: ## Run docker compose
	docker-compose --env-file=$(allcnf) -f $(COMPOSE_FILE) -f $(COMPOSE_OVERRIDE_FILE) $(filter-out $@,$(MAKECMDGOALS))
