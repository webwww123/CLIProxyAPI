#!/usr/bin/env bash
# Deploy an existing release artifact without recreating the container or changing its configuration.
set -euo pipefail
umask 077

if (( $# < 8 || $# > 9 )); then
  echo "Usage: $0 CONTAINER CONTAINER_ID ARTIFACT NEW_SHA256 OLD_SHA256 CONFIG_SHA256 HEALTH_URL BACKUP_DIR [--apply]" >&2
  exit 2
fi
container="$1"
container_id="$2"
artifact="$3"
new_sha="$4"
old_sha="$5"
config_sha="$6"
health_url="$7"
backup_dir="$8"
mode="${9:---dry-run}"
binary_path="/CLIProxyAPI/CLIProxyAPI"
config_path="/CLIProxyAPI/config.yaml"

[[ "$container" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]+$ ]]
for digest in "$container_id" "$new_sha" "$old_sha" "$config_sha"; do
  [[ "$digest" =~ ^[a-f0-9]{64}$ ]] || { echo "Invalid expected identity" >&2; exit 2; }
done
[[ "$artifact" == /* && -f "$artifact" && "$backup_dir" == /* ]]
[[ "$health_url" == http://127.0.0.1:*/* ]] || { echo "Health probe must use loopback" >&2; exit 2; }
[[ "$mode" == --dry-run || "$mode" == --apply ]]
exec 9>"/run/lock/cpa-binary-upgrade-${container}.lock"
flock -n 9 || { echo "Another upgrade holds the lock" >&2; exit 1; }
restart_help="$(docker restart --help)"
if [[ "$restart_help" == *"--time int"* ]]; then
  restart_wait_flag=--time
elif [[ "$restart_help" == *"--timeout"* ]]; then
  restart_wait_flag=--timeout
else
  echo "Docker has no supported restart wait option" >&2
  exit 2
fi
restart_container() { docker restart "$restart_wait_flag" 45 "$container" >/dev/null; }

container_sha() { docker exec "$container" sha256sum "$1" | awk '{print $1}'; }
check_identity() {
  [[ "$(docker inspect --format '{{.Id}}' "$container")" == "$container_id" ]]
  [[ "$(docker inspect --format '{{.State.Running}}' "$container")" == true ]]
  [[ "$(container_sha "$binary_path")" == "$old_sha" ]]
  [[ "$(container_sha /proc/1/exe)" == "$old_sha" ]]
  [[ "$(container_sha "$config_path")" == "$config_sha" ]]
}
check_health() { curl --silent --show-error --fail --max-time 3 "$health_url" >/dev/null; }
wait_health() {
  for ((attempt=0; attempt<60; attempt++)); do
    if check_health 2>/dev/null; then return 0; fi
    sleep 1
  done
  return 1
}
[[ "$(sha256sum "$artifact" | awk '{print $1}')" == "$new_sha" ]]
check_identity
check_health
echo "Preflight passed: exact container, binary, configuration, artifact and health verified."
if [[ "$mode" == --dry-run ]]; then
  echo "Dry run complete; no production binary or configuration was changed."
  exit 0
fi
[[ "${CONFIRM_CPA_BINARY_SHA256:-}" == "$new_sha" ]] || { echo "Exact artifact confirmation is required" >&2; exit 2; }
[[ ! -e "$backup_dir" ]] || { echo "Backup directory already exists" >&2; exit 1; }
install -d -m 700 "$backup_dir"
docker cp "$container:$binary_path" "$backup_dir/previous-binary"
docker cp "$container:$config_path" "$backup_dir/config.snapshot.yaml"
chmod 600 "$backup_dir/previous-binary" "$backup_dir/config.snapshot.yaml"
[[ "$(sha256sum "$backup_dir/previous-binary" | awk '{print $1}')" == "$old_sha" ]]
[[ "$(sha256sum "$backup_dir/config.snapshot.yaml" | awk '{print $1}')" == "$config_sha" ]]
printf '%s\n' "container=$container" "container_id=$container_id" "previous_sha256=$old_sha" "candidate_sha256=$new_sha" "config_sha256=$config_sha" > "$backup_dir/upgrade-record.txt"

replaced=false
on_failure() {
  result=$?
  trap - EXIT
  if [[ "$replaced" == true && "$result" != 0 ]]; then
    echo "Upgrade verification failed; restoring the exact previous binary." >&2
    if docker cp "$backup_dir/previous-binary" "$container:${binary_path}.rollback-pending" &&
       docker exec "$container" sh -c 'chmod 755 "$1" && mv "$1" "$2"' sh "${binary_path}.rollback-pending" "$binary_path" &&
       { [[ "$(container_sha /proc/1/exe)" == "$old_sha" ]] || restart_container; } &&
       wait_health && [[ "$(container_sha "$binary_path")" == "$old_sha" ]]; then
      echo "Rollback verified; configuration was preserved." >&2
    else
      echo "Rollback requires operator attention." >&2
    fi
  fi
  exit "$result"
}
trap on_failure EXIT
docker cp "$artifact" "$container:${binary_path}.upgrade-pending"
[[ "$(container_sha "${binary_path}.upgrade-pending")" == "$new_sha" ]]
check_identity
replaced=true
docker exec "$container" sh -c 'chmod 755 "$1" && mv "$1" "$2"' sh "${binary_path}.upgrade-pending" "$binary_path"
restart_container
wait_health
[[ "$(container_sha "$binary_path")" == "$new_sha" ]]
[[ "$(container_sha /proc/1/exe)" == "$new_sha" ]]
[[ "$(container_sha "$config_path")" == "$config_sha" ]]
[[ "$(docker inspect --format '{{.Id}}' "$container")" == "$container_id" ]]
echo "Upgrade verified; exact binary is live, health is good, container and configuration are unchanged."
