DOCKER ?= docker

.PHONY: help build run

help: ## Show this help
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: Dockerfile compose.yaml ## Build the Docker container(s)
	@$(DOCKER) compose build

run: ## Run the Docker container(s)
	@$(DOCKER) compose run --rm gaps-runner "/entrypoint.sh"

