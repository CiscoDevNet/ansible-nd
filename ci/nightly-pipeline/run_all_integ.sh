#!/usr/bin/env bash
# =============================================================================
# run_all_integ.sh -- run the FULL standalone integration suite for EVERY module.
#
# Same coverage the Jenkins nightly gets, but on demand from this terminal. For
# each module it drives the real integration target
#   tests/integration/targets/<module>/tasks/main.yaml
# via run_integration_module.yaml, which discovers tests/standalone/*.yaml with
# testcase='*' -> the full state lifecycle:
#     merged, replaced, overridden, deleted, gathered, sanity
# NOT just the merged+gathered+deleted of the nd_pipeline/playbooks/*.yaml smoke
# playbooks.
#
# Each module runs as its OWN ansible-playbook invocation, so every module gets
# its own PLAY RECAP + log + duration; one failing module never hides another.
#
# USAGE
#   ./run_all_integ.sh                                 # all modules, full suite
#   ./run_all_integ.sh nd_manage_networks              # one module
#   ./run_all_integ.sh nd_manage_vrfs nd_manage_networks
#   ./run_all_integ.sh nd_manage_networks -e testcase=merged   # single case
#   ./run_all_integ.sh -e nd_prerequisite_enable=true          # passthrough -e
#   DRY_RUN=1 ./run_all_integ.sh                       # print the plan, run nothing
#   ./run_all_integ.sh nd_vpc_pair                     # standalone vPC-pair target (needs peer-link)
#
# PIPELINE PARITY (why this is safe to run instead of the nightly)
#   Every module is invoked with the SAME extra-vars the Jenkins nightly passes to
#   run_integration_module.yaml, so a local run behaves like the CI run:
#     * inventory host-vars (incl. creds) promoted to -e via `ansible-inventory
#       --host` written to a 0600 temp file, removed on exit (mirrors the
#       pipeline's INVENTORY_VARS_FILE)
#     * -e fabric_name / nd_test_fabric2_name
#     * -e nd_prerequisite_enable/apply/only/mode/run_id
#     * per-module topology vars (networks fabric, switches mgmt IPs, l3out IDs)
#   The handpicked cleanups the pipeline runs AROUND the tests are preserved too:
#     * switch-membership pre-flight (before) + post-restore (after) via
#       nd_ensure_switches.yaml -- pre-flight is an ENFORCED gate (add +
#       recalculate & deploy + confirm the full 4+2 topology; aborts on failure),
#       post-restore is best-effort; both auto-skip locally when the playbook or
#       integration_config.yml roster is absent (Consul-only files)
#     * a per-module switch guard runs the SAME confirm+add before EVERY module
#       (add missing + recalculate & deploy + confirm 4+2), bounded by
#       ND_SWITCH_GUARD_TIMEOUT; non-fatal to the loop but a heal failure marks
#       the run failed -- so no module runs on a fabric missing a switch
#     * reset_fabric.yaml (after the suite) -- opt-in (ND_RESET_FABRIC=true),
#       matching the nightly's between-version reset
#     * the runner's own SETUP pre-clean + always post-clean run automatically
#
# ENV OVERRIDES
#   ND_COLLECTION_ROOT      path to the cisco.nd collection (default below)
#   ND_INVENTORY            inventory file name/path (default inventory.yaml)
#   ND_PASSWORD / ND_USER   override inventory creds without editing the file
#   MODULE_TIMEOUT          per-module wall-clock cap in seconds (default: uncapped)
#   SWITCHES_MODULE_TIMEOUT cap for nd_manage_switches only (default 5400)
#   FABRIC_NAME             primary fabric   (default VXLAN_EVPN_Fabric)
#   SECONDARY_FABRIC_NAME   l3out ext fabric (default External_Connectivity_Fabric)
#   NETWORK_FABRIC_NAME     networks fabric  (default VXLAN_EVPN_Fabric_eBGP)
#   ND_PREREQUISITE_ENABLE/APPLY/ONLY  prereq wrapper flags (default false = nightly)
#   RUN_MARKER              nd_prerequisite_run_id prefix (default manual-<ts>)
#   VERBOSITY               ansible-playbook verbosity (default -vvvv; "" to quiet)
#   ND_SWITCH_PREFLIGHT     switch pre-flight before suite      (default true)
#   ND_SWITCH_POSTRESTORE   switch post-restore after suite     (default true)
#   ND_SWITCH_AUTO_ONBOARD  pre-flight enforces add+deploy+confirm (default true)
#   ND_SWITCH_SYNC_TIMEOUT  per-onboard wall-clock cap seconds  (default 3600)
#   ND_SWITCH_GUARD_TIMEOUT per-module switch-guard cap seconds  (default 900)
#   ND_RESET_FABRIC         run reset_fabric.yaml after suite   (default false)
#   ND_VPC_PAIR_ENABLE      add standalone nd_vpc_pair to the default set (default false)
#   VPC_PAIR_SWITCH1_SERIAL / VPC_PAIR_SWITCH2_SERIAL / VPC_PAIR_FABRIC_TYPE
#                           vPC pair members + type (default SERIAL00001/SERIAL00002/vxlanIbgp)
#
# ND auth defaults to the collection inventory.yaml. No secret is stored here.
# =============================================================================
set -uo pipefail

COLLECTION_ROOT="${ND_COLLECTION_ROOT:-/Users/sivakasi/ansible/collections/ansible_collections/cisco/nd}"
RUNNER="run_integration_module.yaml"
INVENTORY="${ND_INVENTORY:-inventory.yaml}"

# --- pipeline-parity config (env-overridable; defaults match the nightly) -----
FABRIC_NAME="${FABRIC_NAME:-VXLAN_EVPN_Fabric}"                                 # -> -e fabric_name
SECONDARY_FABRIC_NAME="${SECONDARY_FABRIC_NAME:-External_Connectivity_Fabric}"  # -> -e nd_test_fabric2_name
NETWORK_FABRIC_NAME="${NETWORK_FABRIC_NAME:-VXLAN_EVPN_Fabric_eBGP}"            # networks standalone fabric
ND_PREREQUISITE_ENABLE="${ND_PREREQUISITE_ENABLE:-false}"                       # prereq wrapper off = nightly default
ND_PREREQUISITE_APPLY="${ND_PREREQUISITE_APPLY:-false}"
ND_PREREQUISITE_ONLY="${ND_PREREQUISITE_ONLY:-false}"
RUN_MARKER="${RUN_MARKER:-manual-$(date +%Y%m%d%H%M%S)}"                        # nd_prerequisite_run_id prefix
VERBOSITY="${VERBOSITY:--vvvv}"                                                 # nightly uses -vvvv
INVENTORY_HOST="${INVENTORY_HOST:-nd_controller}"                               # host whose vars we promote
# cleanup / membership parity toggles
ND_SWITCH_PREFLIGHT="${ND_SWITCH_PREFLIGHT:-true}"
ND_SWITCH_POSTRESTORE="${ND_SWITCH_POSTRESTORE:-true}"
ND_RESET_FABRIC="${ND_RESET_FABRIC:-false}"
SWITCH_PLAYBOOK="${SWITCH_PLAYBOOK:-nd_ensure_switches.yaml}"
SWITCH_ROSTER="${SWITCH_ROSTER:-integration_config.yml}"
RESET_PLAYBOOK="${RESET_PLAYBOOK:-reset_fabric.yaml}"

# Default module set = the nightly's INTEGRATION_MODULES, in topology-impact order
# (role-neutral config first; fabric/membership-changing modules LAST). Comment a
# line to drop it. vpc_pair is opt-in via ND_VPC_PAIR_ENABLE (below); interface_vpc_*
# stay off (all three need a vPC peer-link substrate the lab lacks today).
DEFAULT_MODULES=(
  nd_manage_policy
  nd_manage_policy_group
  nd_manage_route_map
  nd_manage_prefix_list
  nd_manage_acl
  nd_manage_l3out
  nd_manage_vrfs
  nd_manage_networks
  nd_manage_fabric
  nd_manage_switches
  nd_resource_manager
  # nd_vpc_pair is standalone (not a role) -> opt-in via ND_VPC_PAIR_ENABLE=true (below)
  # nd_interface_vpc_access     # needs a vPC pair in SETUP
  # nd_interface_vpc_trunk_host # needs a vPC pair in SETUP
)

# nd_manage_links (ND 4.2) is opt-in: its numbered test assumes a dedicated fabric
# (nd_test_fabric_numbered, default "ansible-fab-numbered") with switches n9k-z17-62/63
# and interfaces Ethernet1/30-32. Enable with ND_LINKS_ENABLE=true after provisioning
# that substrate, or pass overrides as passthru, e.g.:
#   ND_LINKS_ENABLE=true ./run_all_integ.sh -e nd_test_fabric_numbered=VXLAN_EVPN_Fabric \
#     -e nd_test_switch_a=<switchA> -e nd_test_switch_b=<switchB>
# You can also always run it explicitly regardless of the toggle: ./run_all_integ.sh nd_manage_links
ND_LINKS_ENABLE="${ND_LINKS_ENABLE:-false}"
if [ "${ND_LINKS_ENABLE}" = "true" ]; then
  DEFAULT_MODULES+=(nd_manage_links)
fi

# nd_vpc_pair is a STANDALONE playbook target (hosts: nd), not a role, so it runs its
# own tests/integration/targets/nd_vpc_pair/tasks/main.yaml directly (NOT via
# run_integration_module.yaml). It needs a physical vPC peer-link substrate
# (leaf_1<->leaf_2 or edge_1<->edge_2) the standing lab does not have today -> OFF by
# default. Enable with ND_VPC_PAIR_ENABLE=true once cabled, or run it explicitly:
#   ./run_all_integ.sh nd_vpc_pair
# Override the pair via VPC_PAIR_SWITCH1_SERIAL / VPC_PAIR_SWITCH2_SERIAL / VPC_PAIR_FABRIC_TYPE.
ND_VPC_PAIR_ENABLE="${ND_VPC_PAIR_ENABLE:-false}"
if [ "${ND_VPC_PAIR_ENABLE}" = "true" ]; then
  DEFAULT_MODULES+=(nd_vpc_pair)
fi
VPC_PAIR_SWITCH1_SERIAL="${VPC_PAIR_SWITCH1_SERIAL:-SERIAL00001}"   # vxlan_leaf_1
VPC_PAIR_SWITCH2_SERIAL="${VPC_PAIR_SWITCH2_SERIAL:-SERIAL00002}"   # vxlan_leaf_2
VPC_PAIR_FABRIC_TYPE="${VPC_PAIR_FABRIC_TYPE:-vxlanIbgp}"

# Parse args: leading nd_* tokens select modules; everything else is passed
# through to ansible-playbook (e.g. -e key=val, --tags, -vvvv).
MODULES=()
PASSTHRU=()
for arg in "$@"; do
  if [ ${#PASSTHRU[@]} -eq 0 ] && [ "${arg#nd_}" != "$arg" ]; then
    MODULES+=("$arg")
  else
    PASSTHRU+=("$arg")
  fi
done
[ ${#MODULES[@]} -gt 0 ] || MODULES=("${DEFAULT_MODULES[@]}")

# Runtime env: macOS fork-safety, writable persistent-conn dir, timeouts.
: "${TMPDIR:=/tmp}"
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
export ANSIBLE_PERSISTENT_CONTROL_PATH_DIR="$TMPDIR/ansible_pc"; mkdir -p "$ANSIBLE_PERSISTENT_CONTROL_PATH_DIR"
rm -f "$ANSIBLE_PERSISTENT_CONTROL_PATH_DIR"/* 2>/dev/null || true
export ANSIBLE_PERSISTENT_COMMAND_TIMEOUT="${ANSIBLE_PERSISTENT_COMMAND_TIMEOUT:-300}"
export ND_TIMEOUT="${ND_TIMEOUT:-300}"

# Force the collection's ansible.cfg (roles_path -> integration targets) regardless of cwd.
[ -f "$COLLECTION_ROOT/ansible.cfg" ] && export ANSIBLE_CONFIG="$COLLECTION_ROOT/ansible.cfg"
export ANSIBLE_ROLES_PATH="$COLLECTION_ROOT/tests/integration/targets"

cd "$COLLECTION_ROOT" || { echo "ERROR: collection root not found: $COLLECTION_ROOT" >&2; exit 2; }
[ -f "$RUNNER" ]    || { echo "ERROR: runner missing: $COLLECTION_ROOT/$RUNNER" >&2; exit 2; }
[ -f "$INVENTORY" ] || { echo "ERROR: inventory missing: $COLLECTION_ROOT/$INVENTORY" >&2; exit 2; }

# Optional credential override (never stored; taken from env only).
PW_ARGS=()
[ -n "${ND_PASSWORD:-}" ] && PW_ARGS+=(-e "ansible_password=${ND_PASSWORD}")
[ -n "${ND_USER:-}" ]     && PW_ARGS+=(-e "ansible_user=${ND_USER}")

# Optional per-module wall-clock cap. nd_manage_switches greenfield re-onboard is slow.
MODULE_TIMEOUT="${MODULE_TIMEOUT:-}"
SWITCHES_MODULE_TIMEOUT="${SWITCHES_MODULE_TIMEOUT:-5400}"
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || command -v gtimeout 2>/dev/null || true)"

TS="$(date +%Y%m%d_%H%M%S)"
LOGDIR="$COLLECTION_ROOT/integ_logs/$TS"
mkdir -p "$LOGDIR"

# Promote inventory host-vars (incl. creds) to extra-var precedence, exactly like the
# nightly's INVENTORY_VARS_FILE. mktemp already creates 0600; belt-and-suspenders umask.
_old_umask="$(umask)"; umask 077
VARS_JSON="$(mktemp "${TMPDIR%/}/nd_runtime_vars.XXXXXX")"
umask "$_old_umask"
cleanup_vars() { [ -n "${VARS_JSON:-}" ] && rm -f "$VARS_JSON" 2>/dev/null || true; }
trap cleanup_vars EXIT INT TERM
EXTRA_VARS_FILE_ARGS=()
if ansible-inventory -i "$INVENTORY" --host "$INVENTORY_HOST" >"$VARS_JSON" 2>/dev/null && [ -s "$VARS_JSON" ]; then
  chmod 600 "$VARS_JSON" 2>/dev/null || true
  EXTRA_VARS_FILE_ARGS=(-e "@$VARS_JSON")
else
  echo "WARN: could not resolve host-vars for '$INVENTORY_HOST'; using -i inventory only."
  rm -f "$VARS_JSON" 2>/dev/null || true; VARS_JSON=""
fi
if [ -n "${VARS_JSON:-}" ]; then HOSTVARS_STATE="promoted (-e @file)"; else HOSTVARS_STATE="inline (-i only)"; fi

# Per-module extra vars, matching the nightly's NETWORK_EXTRA_VARS / MODULE_TOPOLOGY_VARS.
module_extra_vars() {
  case "$1" in
    nd_manage_networks)
      printf '%s' "-e ansible_it_fabric=${NETWORK_FABRIC_NAME} -e nd_network_standalone_fabric=${NETWORK_FABRIC_NAME}" ;;
    nd_manage_switches)
      printf '%s' "-e ansible_switch1=192.0.2.195 -e ansible_switch2=192.0.2.194 -e ansible_switch3=192.0.2.88" ;;
    nd_manage_l3out)
      # switch1 = vxlan_leaf_1 (SERIAL00001 / .195): only VXLAN-side switch physically cabled
      # to external_edge_1 (leaf_1 Eth1/1 <-> edge_1 Eth1/1) for the ext_l3_dci_link. switch2 = edge_1 (.89).
      printf '%s' "-e nd_test_switch1_id=SERIAL00001 -e nd_test_switch1_mgmt_ip=192.0.2.195 -e nd_test_switch2_id=SERIAL00005 -e nd_test_switch2_mgmt_ip=192.0.2.89" ;;
    *) printf '%s' "" ;;
  esac
}

# Switch-membership sync (pre/post) -> nd_ensure_switches.yaml (nightly runSwitchMembershipSync).
# pre = ENFORCED gate: add + recalculate & deploy + confirm the full 4+2 topology; a failure
# aborts the suite (exit 1) so it never starts on a broken topology. post = best-effort restore
# (never aborts). Both auto-skip when the playbook/roster are absent locally (Consul-only).
run_switch_sync() {
  local phase="$1" apply to rc
  if [ "$phase" = "post" ]; then apply="true"; else apply="${ND_SWITCH_AUTO_ONBOARD:-true}"; fi
  if [ "$ND_PREREQUISITE_ONLY" = "true" ]; then echo "SKIP switch ${phase}-sync: prerequisite-only run."; return 0; fi
  if [ ! -f "$COLLECTION_ROOT/$SWITCH_PLAYBOOK" ] || [ ! -f "$COLLECTION_ROOT/$SWITCH_ROSTER" ]; then
    echo "SKIP switch ${phase}-sync: $SWITCH_PLAYBOOK / $SWITCH_ROSTER not present locally (Consul-only)."; return 0
  fi
  # Bound the onboard. A switch mid-reload/rediscovery can need ~30-40 min to become
  # manageable; 1200s (20 min) cut that off (build #17 exit 124). 3600s gives it room
  # while still failing well before the module's ~175 min internal wait ceiling.
  to="${ND_SWITCH_SYNC_TIMEOUT:-3600}"; [ -n "$TIMEOUT_BIN" ] && to="$TIMEOUT_BIN $to" || to=""
  echo "SWITCH ${phase}-sync (apply=${apply}) -> $SWITCH_PLAYBOOK"
  if [ -n "${DRY_RUN:-}" ]; then
    echo "DRY_RUN: ${to} ansible-playbook -i $INVENTORY $SWITCH_PLAYBOOK -e nd_switch_roster_file=$COLLECTION_ROOT/$SWITCH_ROSTER -e nd_switch_apply=${apply} -e nd_switch_deploy=true -e nd_switch_require_full_roster=true -e nd_switch_fail_on_missing=false"; return 0
  fi
  $to ansible-playbook -i "$INVENTORY" "$COLLECTION_ROOT/$SWITCH_PLAYBOOK" \
      -e "nd_switch_roster_file=$COLLECTION_ROOT/$SWITCH_ROSTER" \
      -e "nd_switch_apply=${apply}" \
      -e "nd_switch_deploy=true" \
      -e "nd_switch_require_full_roster=true" \
      -e "nd_switch_fail_on_missing=false" 2>&1 | tee "$LOGDIR/switch_${phase}.log"
  rc=${PIPESTATUS[0]}
  if [ "$rc" -ne 0 ]; then
    if [ "$phase" = "post" ]; then
      echo "WARN: switch post-sync did not complete cleanly (best-effort, continuing)."
    else
      echo "ERROR: switch pre-flight did not confirm the full 4+2 topology (rc=$rc)." >&2
      echo "ERROR: refusing to start the suite on a broken topology; check the switch(es) and grep the log for NDP_SWITCH_PREFLIGHT_MISSING / NDP_SWITCH_CONFIRM_FAIL." >&2
      exit 1
    fi
  fi
}

# Per-module switch-availability guard (mirrors the nightly's ensure_switches_ready).
# Confirm the canonical 4+2 switches before EVERY module and re-add any a prior
# destructive module (e.g. nd_manage_switches) removed, then recalculate & deploy,
# so a module never runs on a fabric missing a switch. Enforced add (apply=true)
# except in a prerequisite-only run. Bounded by ND_SWITCH_GUARD_TIMEOUT (default
# 900s) so one truly-down switch can't hang the whole suite -- the pre-flight
# already gates the start and the post-restore re-confirms at the end. Non-fatal to
# the loop (the module still runs) but a heal failure marks the run failed.
ensure_switches_ready() {
  local _label="$1" _apply="" _gt="" _rc=0
  [ "$ND_SWITCH_PREFLIGHT" = "true" ] || return 0
  if [ ! -f "$COLLECTION_ROOT/$SWITCH_PLAYBOOK" ] || [ ! -f "$COLLECTION_ROOT/$SWITCH_ROSTER" ]; then
    return 0
  fi
  if [ "$ND_PREREQUISITE_ONLY" = "true" ]; then _apply="false"; else _apply="${ND_SWITCH_AUTO_ONBOARD:-true}"; fi
  _gt="${ND_SWITCH_GUARD_TIMEOUT:-900}"; [ -n "$TIMEOUT_BIN" ] && _gt="$TIMEOUT_BIN -k 30 $_gt" || _gt=""
  echo "🔎 [switch-guard] Confirming canonical 4+2 switches before ${_label} (apply=${_apply}, timeout=${ND_SWITCH_GUARD_TIMEOUT:-900}s)"
  if [ -n "${DRY_RUN:-}" ]; then
    echo "DRY_RUN: ${_gt} ansible-playbook -i $INVENTORY $SWITCH_PLAYBOOK -e nd_switch_roster_file=$COLLECTION_ROOT/$SWITCH_ROSTER -e nd_switch_apply=${_apply} -e nd_switch_deploy=true -e nd_switch_require_full_roster=true -e nd_switch_fail_on_missing=false"
    return 0
  fi
  $_gt ansible-playbook -i "$INVENTORY" "$COLLECTION_ROOT/$SWITCH_PLAYBOOK" \
      -e "nd_switch_roster_file=$COLLECTION_ROOT/$SWITCH_ROSTER" \
      -e "nd_switch_apply=${_apply}" \
      -e "nd_switch_deploy=true" \
      -e "nd_switch_require_full_roster=true" \
      -e "nd_switch_fail_on_missing=false" 2>&1 | tee "$LOGDIR/switch_guard_${_label}.log"
  _rc=${PIPESTATUS[0]}
  if [ "$_rc" -ne 0 ]; then
    echo "❌ [switch-guard] Could not confirm/restore the full canonical topology before ${_label} (rc=$_rc); the module will still run but the run is marked FAILED. Grep NDP_SWITCH_PREFLIGHT_MISSING / NDP_SWITCH_CONFIRM_FAIL." >&2
    overall=1
  else
    echo "✅ [switch-guard] Canonical switches confirmed before ${_label}"
  fi
}

# Between-suite fabric reset -> reset_fabric.yaml (nightly resetFabricBetweenVersions; self-contained, no -e).
# Destructive: opt-in only. Skipped for prerequisite-only runs (matches nightly).
run_reset_fabric() {
  if [ "$ND_RESET_FABRIC" != "true" ]; then echo "SKIP reset_fabric: ND_RESET_FABRIC!=true (opt-in)."; return 0; fi
  if [ "$ND_PREREQUISITE_ONLY" = "true" ]; then echo "SKIP reset_fabric: prerequisite-only run."; return 0; fi
  if [ ! -f "$COLLECTION_ROOT/$RESET_PLAYBOOK" ]; then echo "SKIP reset_fabric: $RESET_PLAYBOOK absent."; return 0; fi
  echo "RESET fabric -> $RESET_PLAYBOOK"
  if [ -n "${DRY_RUN:-}" ]; then echo "DRY_RUN: ansible-playbook -i $INVENTORY $RESET_PLAYBOOK"; return 0; fi
  ansible-playbook -i "$INVENTORY" "$COLLECTION_ROOT/$RESET_PLAYBOOK" 2>&1 | tee "$LOGDIR/reset_fabric.log" \
    || echo "WARN: reset_fabric did not complete cleanly (best-effort, continuing)."
}

echo "-----------------------------------------------------------------"
echo "cisco.nd integration -> $COLLECTION_ROOT"
echo "runner      -> $RUNNER"
echo "inventory   -> $INVENTORY   host-vars: $HOSTVARS_STATE"
echo "modules     -> ${MODULES[*]}"
echo "fabric      -> $FABRIC_NAME   secondary -> $SECONDARY_FABRIC_NAME   networks -> $NETWORK_FABRIC_NAME"
echo "prereq      -> enable=$ND_PREREQUISITE_ENABLE apply=$ND_PREREQUISITE_APPLY only=$ND_PREREQUISITE_ONLY mode=live run_id=${RUN_MARKER}_<module>"
echo "cleanups    -> switch_preflight=$ND_SWITCH_PREFLIGHT switch_postrestore=$ND_SWITCH_POSTRESTORE reset_fabric=$ND_RESET_FABRIC"
[ ${#PASSTHRU[@]} -gt 0 ] && echo "extra args  -> ${PASSTHRU[*]}"
echo "verbosity   -> ${VERBOSITY:-(quiet)}"
echo "logs        -> $LOGDIR"
echo "-----------------------------------------------------------------"

# BEFORE the suite: switch-membership pre-flight (best-effort; nightly runSwitchPreflight).
[ "$ND_SWITCH_PREFLIGHT" = "true" ] && run_switch_sync pre

RESULTS=()
overall=0
for m in "${MODULES[@]}"; do
  # nd_manage_switches' runner pre_task include_vars integration_config.yml (switch
  # device creds). Without it the play errors -> skip cleanly instead of failing.
  if [ "$m" = "nd_manage_switches" ] && [ ! -f "$COLLECTION_ROOT/integration_config.yml" ]; then
    echo "SKIP  $m -- integration_config.yml (switch device creds) not present."
    RESULTS+=("SKIP    $m  (no integration_config.yml)")
    continue
  fi

  # Per-module switch guard: confirm/re-add the canonical 4+2 before this module.
  ensure_switches_ready "$m"

  cap=""
  if [ -n "$MODULE_TIMEOUT" ] && [ -n "$TIMEOUT_BIN" ]; then
    if [ "$m" = "nd_manage_switches" ]; then
      cap="$TIMEOUT_BIN -k 60 $SWITCHES_MODULE_TIMEOUT"
    else
      cap="$TIMEOUT_BIN -k 60 $MODULE_TIMEOUT"
    fi
  fi

  log="$LOGDIR/${m}.log"
  echo
  echo "==================================================================="
  echo "RUN ${m}  (full standalone suite: merged/replaced/overridden/deleted/gathered/sanity)"
  echo "  log -> $log"
  echo "==================================================================="

  MOD_XTRA="$(module_extra_vars "$m")"

  # Select the playbook + its module-specific -e args. nd_vpc_pair is a STANDALONE
  # playbook (hosts: nd), not a role, so it runs its own target main.yaml directly
  # with the vPC serial/fabric_type contract (mirrors the nightly standalone path);
  # every other module goes through run_integration_module.yaml with the prereq vars.
  if [ "$m" = "nd_vpc_pair" ]; then
    RUN_PLAYBOOK="$COLLECTION_ROOT/tests/integration/targets/nd_vpc_pair/tasks/main.yaml"
    if [ ! -f "$RUN_PLAYBOOK" ]; then
      echo "SKIP  $m -- target playbook not present: $RUN_PLAYBOOK"
      RESULTS+=("SKIP    $m  (target playbook absent)")
      continue
    fi
    RUN_E_ARGS=(-e "fabric_name=${FABRIC_NAME}"
                -e "switch1_serial=${VPC_PAIR_SWITCH1_SERIAL}"
                -e "switch2_serial=${VPC_PAIR_SWITCH2_SERIAL}"
                -e "fabric_type=${VPC_PAIR_FABRIC_TYPE}")
  else
    RUN_PLAYBOOK="$RUNNER"
    RUN_E_ARGS=(-e "test_module=${m}"
                -e "fabric_name=${FABRIC_NAME}"
                -e "nd_test_fabric2_name=${SECONDARY_FABRIC_NAME}"
                -e "nd_prerequisite_enable=${ND_PREREQUISITE_ENABLE}"
                -e "nd_prerequisite_apply=${ND_PREREQUISITE_APPLY}"
                -e "nd_prerequisite_only=${ND_PREREQUISITE_ONLY}"
                -e "nd_prerequisite_mode=live"
                -e "nd_prerequisite_run_id=${RUN_MARKER}_${m}")
  fi

  if [ -n "${DRY_RUN:-}" ]; then
    echo "DRY_RUN would run:"
    echo "  ${cap:+$cap }ansible-playbook ${VERBOSITY} -i $INVENTORY $RUN_PLAYBOOK"
    [ -n "${VARS_JSON:-}" ] && echo "    -e @$VARS_JSON"
    echo "    ${RUN_E_ARGS[*]}"
    [ -n "$MOD_XTRA" ] && echo "    $MOD_XTRA"
    [ ${#PW_ARGS[@]} -gt 0 ] && echo "    ${PW_ARGS[*]}"
    [ ${#PASSTHRU[@]} -gt 0 ] && echo "    ${PASSTHRU[*]}"
    RESULTS+=("DRYRUN  $m")
    continue
  fi

  start=$(date +%s)
  # $cap, $VERBOSITY and $MOD_XTRA are intentionally left unquoted (word-split into args).
  $cap ansible-playbook ${VERBOSITY} -i "$INVENTORY" "$RUN_PLAYBOOK" \
      ${EXTRA_VARS_FILE_ARGS[@]+"${EXTRA_VARS_FILE_ARGS[@]}"} \
      "${RUN_E_ARGS[@]}" \
      ${MOD_XTRA} \
      ${PW_ARGS[@]+"${PW_ARGS[@]}"} \
      ${PASSTHRU[@]+"${PASSTHRU[@]}"} 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  dur=$(( $(date +%s) - start ))

  if [ "$rc" -eq 0 ]; then
    echo "PASS  ${m} (${dur}s)"
    RESULTS+=("PASS    ${m}  ${dur}s")
  elif [ "$rc" -eq 124 ]; then
    echo "TIMEOUT ${m} (${dur}s, rc=124)"
    RESULTS+=("TIMEOUT ${m}  ${dur}s")
    overall=1
  else
    echo "FAIL  ${m} (rc=${rc}, ${dur}s)"
    RESULTS+=("FAIL    ${m}  rc=${rc}  ${dur}s")
    overall=1
  fi
done

# AFTER the suite: switch post-restore (best-effort), then optional fabric reset.
[ "$ND_SWITCH_POSTRESTORE" = "true" ] && run_switch_sync post
run_reset_fabric

echo
echo "===================== SUMMARY ${TS} ====================="
if [ ${#RESULTS[@]} -gt 0 ]; then
  for r in "${RESULTS[@]}"; do echo "  $r"; done
fi
echo "Logs: $LOGDIR"
echo "========================================================="
exit "$overall"
