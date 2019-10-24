#!/usr/bin/env bash

LAST_VERSION=$(git describe --tags --abbrev=0)

REGEX='v([0-9]+).([0-9]).([0-9]+)'
if [[ "${LAST_VERSION}" =~ $REGEX ]]; then
    MAJOR_VERSION=${BASH_REMATCH[1]}
    MINOR_VERSION=${BASH_REMATCH[2]}
    PATCH_VERSION=${BASH_REMATCH[3]}
fi

COMMIT_MESSAGE=$(git show -s --format=%b%s)

case ${COMMIT_MESSAGE} in
    *"BUMP MAJOR"*)
    ((MAJOR_VERSION++))
    MINOR_VERSION=0
    PATCH_VERSION=0
    ;;
    *"BUMP MINOR"*)
    ((MINOR_VERSION++))
    PATCH_VERSION=0
    ;;
    *)
    ((PATCH_VERSION++))
esac

echo v${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}
