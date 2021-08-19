SHELL := /usr/bin/env bash
IMAGEDIRS = $(shell ls -d containers/* | cut -d '/' -f 2)
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef


.PHONY: all
all: build
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-35s$(RESET)%s\n", $$1, $$2}'
	@for job in $(shell egrep "\w+:$$" workflows/*.yml | grep -v 'with:\|jobs:\|steps:' | cut -d ' ' -f 3 | cut -d ':' -f 1); do \
		printf "$(BOLD)$(CYAN)%-35s$(RESET)Run %s action with act\n" $$job $$job; \
	done

.PHONY: run
run: ## Run all Github Action steps as defined in the workflows directory
	@for job in $(shell egrep "\w+:$$" workflows/*.yml | grep -v 'with:\|jobs:\|steps:' | cut -d ' ' -f 3 | cut -d ':' -f 1); do \
		printf "$(BOLD)$(CYAN)Running Step: %-35s$(RESET)\n" $$job; \
    	./act -v -W workflows -j $$job > tests/functional/output/$$job.output 2>&1; \
        echo $$? >> tests/functional/output/$$job.output; \
    done

.PHONY: check
check: bootstrap run ## Run all Github Action steps and then verify them with tests
	python3 -m venv venv
	venv/bin/pip install pytest
	venv/bin/pytest tests/functional

.PHONY: boostrap
bootstrap: ## Download and install all go dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Boostrapping dependencies)
	@pwd
	# Install `act` to run the actions
	curl https://raw.githubusercontent.com/nektos/act/master/install.sh |  sh -s -- -b . v0.2.17
	# prep temp dirs
	mkdir -p tests/functional/output

.PHONY: run-docker-registry
run-docker-registry: bootstrap
	# start a local registry
	docker run -d -p 5000:5000 --name registry registry:2 | echo

.PHONY: test
test: run-docker-registry bootstrap
	npm run build
	./act -v -P ubuntu-latest=ghcr.io/catthehacker/ubuntu:js-latest -j test

.PHONY: wipe-docker
wipe-docker:
	docker kill $(shell docker ps -a -q) | echo
	docker image prune -af
	docker container prune -f
	docker volume prune -f

%: ## do a local build
	scripts/local.sh "$*"
