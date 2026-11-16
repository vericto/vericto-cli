#!/bin/sh
# SPDX-FileCopyrightText: 2026 Vericto S.A.S.
# SPDX-License-Identifier: AGPL-3.0-only
#
# A stand-in for vericto-proxy 5.2.0's `mcp credential set|test|delete`
# contract (one JSON object on stdout, a sentence on stderr, exit codes 0 ok,
# 1 usage, 2 no such entry, 3 the role can write with --require-read-only,
# 4 unreachable), for tests/guard_hard.rs. It keeps entries as files in
# $STUB_DIR/store and logs its argv to $STUB_DIR/argv.log, so the tests can
# check the URL only ever arrives on stdin. The URL's host picks the answer:
# `rw…` can write, `unv…` unverified, `down…` unreachable, anything else
# read-only.
printf '%s\n' "$*" >> "$STUB_DIR/argv.log"
if [ "$1" = "--version" ]; then
  echo "vericto-proxy ${STUB_VERSION:-5.2.0}"
  exit 0
fi
if [ "$1" != mcp ] || [ "$2" != credential ]; then
  echo "unexpected arguments" >&2
  exit 1
fi
act=$3
name=$4
f="$STUB_DIR/store/$name"
case $act in
  set)
    if [ -n "$5" ]; then echo "the URL is read from stdin" >&2; exit 1; fi
    mkdir -p "$STUB_DIR/store"
    url=$(cat)
    [ -n "$url" ] || { echo "no URL on stdin" >&2; exit 1; }
    replaced=false
    [ -f "$f" ] && replaced=true
    printf '%s' "$url" > "$f"
    case $url in postgres*) d=postgres ;; mariadb*) d=mysql ;; *) d=mysql ;; esac
    echo "Stored vericto-proxy/$name in the stub store." >&2
    echo "{\"ok\":true,\"action\":\"set\",\"entry\":\"vericto-proxy/$name\",\"backend\":\"stub store\",\"replaced\":$replaced,\"dialect\":\"$d\",\"engine\":\"$d\",\"database\":\"shop\",\"tls\":\"VerifyFull\"}"
    ;;
  test)
    if [ ! -f "$f" ]; then
      echo "No entry vericto-proxy/$name." >&2
      echo "{\"ok\":false,\"action\":\"test\",\"entry\":\"vericto-proxy/$name\",\"error\":\"not_found\"}"
      exit 2
    fi
    url=$(cat "$f")
    case $url in
      *@down*)
        echo "could not connect (connect: connection refused)" >&2
        echo '{"ok":false,"action":"test","error":"unavailable","step":"connect","message":"connection refused"}'
        exit 4 ;;
      *@rw*)
        echo "Connected: the role CAN WRITE (superuser)" >&2
        echo '{"ok":true,"action":"test","dialect":"postgres","engine":"postgres","database_role":{"read_only":false,"verified":true,"user":"app","reasons":["superuser"],"notes":[]}}'
        [ "$5" = --require-read-only ] && exit 3
        exit 0 ;;
      *@unv*)
        echo "Connected: not verified" >&2
        echo '{"ok":true,"action":"test","dialect":"mysql","engine":"mysql","database_role":{"read_only":null,"verified":false,"user":"app","reasons":["privileges granted through a role"],"notes":[]}}'
        [ "$5" = --require-read-only ] && exit 3
        exit 0 ;;
      *)
        echo "Connected: the role is read-only" >&2
        echo '{"ok":true,"action":"test","dialect":"postgres","engine":"postgres","database_role":{"read_only":true,"verified":true,"user":"ro","reasons":[],"notes":[]}}'
        ;;
    esac
    ;;
  delete)
    if [ ! -f "$f" ]; then
      echo '{"ok":false,"action":"delete","deleted":false}'
      exit 2
    fi
    rm "$f"
    echo "{\"ok\":true,\"action\":\"delete\",\"entry\":\"vericto-proxy/$name\",\"deleted\":true}"
    ;;
  *) exit 1 ;;
esac
exit 0
