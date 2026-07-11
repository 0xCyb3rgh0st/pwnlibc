#!/usr/bin/env sh
# Thin wrapper so day-to-day usage is `./pwnlibc.sh <args>` with no Go
# toolchain and no docker-compose boilerplate to remember.
#
# Commands that shell out to a nested `docker run` (`build`, `run`) need the
# build-src profile instead, since only that service has the Docker socket
# mounted:
#   docker compose --profile build-src run --rm build-src build 2.31 amd64
set -eu
cd "$(dirname "$0")"
mkdir -p libs workdir

service=cli
profile_args=""
case "${1:-}" in
  build|run)
    service=build-src
    profile_args="--profile build-src"
    ;;
esac

# shellcheck disable=SC2086
exec docker compose $profile_args run --rm "$service" "$@"
