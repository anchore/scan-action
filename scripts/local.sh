#!/usr/bin/env bash

# This script is only meant to run from Makefile in the parent directory of this repository

SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

if [ $# -eq 0 ]
  then
    echo "No arguments supplied, this command requires a Github Action step tag to run, like:"
    for job in $(egrep "\w+:$$" workflows/*.yml | grep -v 'with:\|jobs:\|steps:' | cut -d ' ' -f 3 | cut -d ':' -f 1); do \
	echo "- $job"
    done
    exit 1
fi

JOB=$1

# ensure this is at the root
cd "$SCRIPTPATH/.."

# hardcoded path (workflows)
act -v -W workflows -j $JOB > tests/functional/output/$JOB.output 2>&1
echo $? >> tests/functional/output/$JOB.output
