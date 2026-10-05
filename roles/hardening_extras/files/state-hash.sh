#!/bin/sh
# One hash over what an integrity baseline cares about: the content of /etc and /usr/local,
# the installed package versions, and the set of setuid/setgid files with their modes.
# The hardening run records it at the start and compares at the end, so the AIDE database is
# rebuilt only when something really changed (several tasks rewrite files with identical
# content, so modification times are not a usable signal).
{
  find /etc /usr/local -xdev -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum 2>/dev/null
  dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null
  find /usr -xdev -type f -perm /6000 -printf '%m %p\n' 2>/dev/null | sort
} | sha256sum | cut -d' ' -f1
