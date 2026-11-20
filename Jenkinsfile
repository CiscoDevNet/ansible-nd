import groovy.transform.Field

// ============================================================================
// COMBINED DRAFT FOR REVIEW 
//
// Baseline retained from Pipeline1:
//   * staged integration-module list and smoke gap-fillers
//   * one ansible-playbook invocation per target
//   * fabric reset, ansible-lint summary, and Webex presentation
//
// SOURCE ATTRIBUTION -- TAKEN FROM MY CODE
// Source: nd-pipeline-review/Jenkinsfile (plus the newer nd_pipeline.groovy
// draft where it contains the ND 4.2 environment corrections).
//
// The following behaviors can be taken from, my code:
//   1. Workspace-local runtime:
//        BASE_DIRECTORY=$WORKSPACE/.jenkins-runtime
//        COLLECTIONS_DIRECTORY=$WORKSPACE/nd
//   2. Jenkins safety and retention options:
//        skipDefaultCheckout, disableConcurrentBuilds, pipeline timeout,
//        timestamps, and build/artifact retention.
//   3. Validated Consul downloads using curl --fail, connection/request
//        timeouts, a temporary file, and an atomic move.
//   4. An ND precheck before any integration or smoke target is executed.
//   5. One independently tracked execution per target, with its own output,
//        timeout, duration, result parsing, and archived Jenkins artifact.
//   6. Capturing the real ansible-playbook return code through tee by using
//        PIPESTATUS[0], so tee cannot hide an Ansible failure.
//   7. Continuing with later targets while accumulating all earlier failures;
//        a later success never resets an earlier failure.
//   8. Strict PLAY RECAP parsing and accumulation of ok/failed/skipped counts.
//   9. Recording a visible synthetic failure when execution stops before an
//        Ansible PLAY RECAP is produced.
//  10. Running nd_cleanup_verify.yaml after each integration target and
//        excluding its separate PLAY RECAP from the target's test totals.
//  11. Creating a protected temporary inventory, setting mode 0600, and
//        deleting it from post/always processing.
//  12. Direct Webex API delivery with a masked bearer token, rather than
//        downloading and executing webex-notification-jenkins.py from Consul.
//  13. Building detailed per-target Webex lines containing fabric, ND version,
//        passed, failed, skipped, and duration values.
//
// EXTENSIONS MADE WHILE COMBINING :
//   * unreachable counts and explicit PASSED/FAILED/UNREACHABLE/ERROR/
//     CLEANUP_FAILED statuses
//   * cleanup failures separated from normal failed-task counts
//   * compact failure reasons in the Webex notification
//   * configurable smoke execution, lint gating, and final fabric reset
//   * separate Consul prefixes for Pipeline1 assets and newer safety assets
//   * JSON inventory generation to avoid interpolating credentials in Groovy
//
// ============================================================================

@Field
def PLAYBOOK_FILES = [
    // Smoke gap-fillers not duplicated by INTEGRATION_MODULES.
    'nd_manage_fabric_external.yaml',
    'nd_manage_fabric_ebgp_vxlan.yaml',
    'nd_manage_fabric_ibgp_vxlan.yaml',
    'nd_manage_fabric_ai_ebgp_vxlan.yaml',
    'nd_manage_fabric_ai_ibgp_vxlan.yaml',
    'nd_manage_prefix_list.yaml'
]

@Field
def INTEGRATION_MODULES = [
    // Pipeline1's currently staged first batch.
    'nd_manage_policy',
    'nd_manage_policy_group',
    'nd_manage_networks',
    'nd_manage_vrfs',
    'nd_vpc_pair'

    // Deferred until their testbed variables and cleanup verification are ready:
    // 'nd_manage_route_map',
    // 'nd_manage_acl',
    // 'nd_manage_l3out',
    // 'nd_interface_vpc_access',
    // 'nd_interface_vpc_trunk_host',
    // 'nd_manage_switches',
    // 'nd_manage_fabric',
    // 'nd_resource_manager'
]

@Field
def PIPELINE1_CONFIG_FILES = [
    'requirements.txt',
    'requirements.yaml',
    'ansible.cfg',
    'reset_fabric.yaml'
]

@Field
def SAFETY_CONFIG_FILES = [
    'nd_precheck.yaml',
    'nd_cleanup_verify.yaml'
]

@Field
def INTEGRATION_TIMEOUT_MINUTES = 120

@Field
def SMOKE_TIMEOUT_MINUTES = 45

@Field
def RUN_INTEGRATION_MODULE_YAML = '''---
- name: "cisco.nd integration suite for {{ test_module }}"
  hosts: nd
  gather_facts: false
  connection: ansible.netcommon.httpapi
  vars:
    testcase: "*"
  tasks:
    - name: "[{{ test_module }}] Discover optional cleanup.yaml"
      ansible.builtin.stat:
        path: "{{ playbook_dir }}/tests/integration/targets/{{ test_module }}/tasks/cleanup.yaml"
      register: cleanup_file
      delegate_to: localhost

    - name: "[{{ test_module }}] Pre-clean stale objects when supported"
      ansible.builtin.include_role:
        name: "{{ test_module }}"
        tasks_from: cleanup.yaml
      when: cleanup_file.stat.exists
      ignore_errors: true

    - name: "[{{ test_module }}] Run the full integration suite"
      block:
        - name: "[{{ test_module }}] Include the collection integration target"
          ansible.builtin.include_role:
            name: "{{ test_module }}"
          vars:
            testcase: "*"
      always:
        - name: "[{{ test_module }}] Post-clean when supported"
          ansible.builtin.include_role:
            name: "{{ test_module }}"
            tasks_from: cleanup.yaml
          when: cleanup_file.stat.exists
          ignore_errors: true
'''

pipeline {
    agent {
        docker {
            image 'ansible_nd_setup'
            args '--user root'
        }
    }

    parameters {
        booleanParam(
            name: 'DEBUG',
            defaultValue: false,
            description: 'Reserved for additional non-sensitive diagnostics'
        )
        booleanParam(
            name: 'RUN_SMOKE',
            defaultValue: true,
            description: 'Run Pipeline1 smoke gap-fillers after integration modules'
        )
        booleanParam(
            name: 'LINT_GATES_BUILD',
            defaultValue: false,
            description: 'Fail the build when ansible-lint reports violations'
        )
        booleanParam(
            name: 'RESET_FABRIC_AFTER_RUN',
            defaultValue: false,
            description: 'Run reset_fabric.yaml after all test targets finish'
        )
    }

    environment {
        // FROM MY CODE: Jenkins credential binding and direct Webex API
        // credentials. Pipeline1's ND 4.2 host/fabric values are retained.
        WEBEX_TOKEN = credentials('ANSIBLE_WEBEX_TOKEN')
        WEBEX_ROOM_ID = '61f7d4c0-9566-11f0-b070-451eba08616c'

        ND_USER = credentials('ANSIBLE_NDFC_USERNAME')
        ND_PASSWORD = credentials('ANSIBLE_NDFC_41_117_PASSWORD')
        ANSIBLE_HOST = '10.122.84.112'

        ND_SWITCH_IP_1 = '10.122.84.71'
        ND_SWITCH_IP_2 = '10.122.84.63'
        ND_SWITCH_SERIAL_1 = '99WMIU1JLQ3'
        ND_SWITCH_SERIAL_2 = '9484O9IOVJK'
        ND_SWITCH_SERIAL_3 = '9484O9IOVJK'

        // FROM MY CODE: keep the clone and Python runtime inside this build's
        // workspace rather than under the persistent $HOME/ansible directory.
        BASE_DIRECTORY = "$WORKSPACE/.jenkins-runtime"
        COLLECTIONS_DIRECTORY = "$WORKSPACE/nd"
        COLL_DIR = "$WORKSPACE"
        CONSUL_URL = 'http://10.78.210.155:8500'
        // Pipeline1 and the newer safety assets currently use different KV paths.
        CONSUL_PREFIX_PIPELINE1 = 'ansible-nd'
        CONSUL_PREFIX_SAFETY = 'ansible/nd4x-nightly'
        ND_GIT_BRANCH = 'develop'
        FABRIC_NAME = 'VXLAN_Fabric'
        REQUIRED_PYTHON_SERIES = '3.12'

        PIPELINE_FAILED = 'false'
        TEST_RESULT_SUMMARY = ''
        BUILD_FAILURE_REASON = ''
        TOTAL_PASSED_COUNT = '0'
        TOTAL_FAILED_COUNT = '0'
        TOTAL_SKIPPED_COUNT = '0'
        TOTAL_UNREACHABLE_COUNT = '0'
        TOTAL_ERROR_COUNT = '0'
        CURRENT_ND_INVENTORY = ''
        LINT_STATUS = 'NOT_RUN'
    }

    triggers {
        cron('TZ=Asia/Kolkata\n0 2 * * *')
    }

    options {
        // FROM MY CODE: workspace checkout control, concurrency protection,
        // timestamps, timeout, and build/artifact retention.
        skipDefaultCheckout(true)
        disableConcurrentBuilds()
        timeout(time: 10, unit: 'HOURS')
        timestamps()
        buildDiscarder(
            logRotator(
                daysToKeepStr: '30',
                numToKeepStr: '30',
                artifactNumToKeepStr: '30'
            )
        )
    }

    stages {
        stage('Environment Setup') {
            steps {
                sh '''#!/bin/bash
set -euo pipefail

mkdir -p "${BASE_DIRECTORY}"
cd "${BASE_DIRECTORY}"

if [ -d "${BASE_DIRECTORY}/venv" ]; then
    VENV_PYTHON=$("${BASE_DIRECTORY}/venv/bin/python" --version 2>&1 | awk '{print $2}')
    if [[ "${VENV_PYTHON}" != "${REQUIRED_PYTHON_SERIES}".* ]]; then
        echo "Python version mismatch; recreating the Jenkins virtual environment"
        rm -rf -- "${BASE_DIRECTORY}/venv"
        python3.12 -m venv "${BASE_DIRECTORY}/venv"
    fi
else
    python3.12 -m venv "${BASE_DIRECTORY}/venv"
fi

source "${BASE_DIRECTORY}/venv/bin/activate"
echo "Python: $(python --version)"
'''
            }
        }

        stage('Clone Repository') {
            steps {
                sh '''#!/bin/bash
set -euo pipefail
cd "${COLL_DIR}"

if [ -d "nd/.git" ]; then
    LOCAL_COMMIT=$(git -C nd rev-parse HEAD)
    REMOTE_COMMIT=$(git ls-remote \
        https://github.com/CiscoDevNet/ansible-nd.git \
        "refs/heads/${ND_GIT_BRANCH}" | awk '{print $1}')

    if [ "${LOCAL_COMMIT}" = "${REMOTE_COMMIT}" ]; then
        echo "Repository is up-to-date at ${LOCAL_COMMIT}"
        exit 0
    fi

    rm -rf -- nd
elif [ -e nd ]; then
    echo "${COLL_DIR}/nd exists but is not a Git repository"
    exit 1
fi

git clone \
    --branch "${ND_GIT_BRANCH}" \
    --single-branch \
    https://github.com/CiscoDevNet/ansible-nd.git \
    nd

git -C nd rev-parse HEAD
'''
            }
        }

        stage('Download and Materialize Test Assets') {
            steps {
                script {
                    // Downloaded files are written by shell commands inside the
                    // root Docker container.
                    dir(env.COLLECTIONS_DIRECTORY) {
                        // FROM MY CODE: retrieve only known pipeline assets;
                        // downloadFromConsul validates names and writes atomically.
                        PIPELINE1_CONFIG_FILES.each { fileName ->
                            downloadFromConsul(
                                env.CONSUL_PREFIX_PIPELINE1,
                                fileName
                            )
                        }

                        SAFETY_CONFIG_FILES.each { fileName ->
                            downloadFromConsul(
                                env.CONSUL_PREFIX_SAFETY,
                                fileName
                            )
                        }

                        if (params.RUN_SMOKE) {
                            PLAYBOOK_FILES.each { fileName ->
                                downloadFromConsul(
                                    env.CONSUL_PREFIX_PIPELINE1,
                                    fileName
                                )
                            }
                        }
                    }

                    // Jenkins writeFile runs as the Jenkins agent user. Write the
                    // embedded runner into a Jenkins-owned temporary directory first.
                    def runnerDirectory = pwd(tmp: true)

                    dir(runnerDirectory) {
                        writeFile(
                            file: 'run_integration_module.yaml',
                            text: RUN_INTEGRATION_MODULE_YAML
                        )
                    }

                    // The shell runs as root inside the Docker container, so it can
                    // safely install the file into the root-owned cloned repository.
                    withEnv([
                        "RUNNER_SOURCE=${runnerDirectory}/run_integration_module.yaml"
                    ]) {
                        sh '''#!/bin/bash
        set -euo pipefail

        install \
            -m 0644 \
            "${RUNNER_SOURCE}" \
            "${COLLECTIONS_DIRECTORY}/run_integration_module.yaml"

        test -s "${COLLECTIONS_DIRECTORY}/run_integration_module.yaml"
        echo "Materialized run_integration_module.yaml successfully"
        '''
                    }
                }
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '''#!/bin/bash
set -euo pipefail
cd "${COLLECTIONS_DIRECTORY}"
source "${BASE_DIRECTORY}/venv/bin/activate"

for required_file in \
    requirements.txt \
    requirements.yaml \
    ansible.cfg \
    nd_precheck.yaml \
    nd_cleanup_verify.yaml \
    reset_fabric.yaml \
    run_integration_module.yaml; do
    if [ ! -f "${required_file}" ]; then
        echo "Required pipeline asset is missing: ${required_file}"
        exit 1
    fi
done

python -m pip install --disable-pip-version-check \
    "ansible-core>=2.19,<2.20"
python -m pip install --disable-pip-version-check \
    -r requirements.txt
ansible-galaxy collection install -r requirements.yaml

echo "Python: $(python --version)"
echo "Ansible: $(ansible --version | head -1)"
if command -v ansible-lint >/dev/null 2>&1; then
    echo "Ansible-lint: $(ansible-lint --version | head -1)"
else
    echo "Ansible-lint is not installed; the lint stage will report an infrastructure error"
fi
'''
            }
        }

        stage('Run ND 4.2 Tests') {
            steps {
                // FROM MY CODE: mark the stage/build failed but still allow
                // lint, reset, and the post-build notification to execute.
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    script {
                        initializeResultState()

                        def ndConfig = [
                            version: '4.2',
                            versionId: 'ND42',
                            fabric_name: env.FABRIC_NAME
                        ]

                        runNDTests(ndConfig)
                    }
                }
            }
        }

        stage('Run Ansible Lint') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    script {
                        try {
                            def lintPassed = runLintCheck()

                            if (!lintPassed && params.LINT_GATES_BUILD) {
                                env.PIPELINE_FAILED = 'true'
                                appendFailureReason(
                                    'ansible-lint failed and LINT_GATES_BUILD is enabled'
                                )
                                error('ansible-lint reported violations or could not run')
                            }
                        } catch (Exception lintError) {
                            if (!env.BUILD_FAILURE_REASON?.contains('ansible-lint')) {
                                appendFailureReason(
                                    "ansible-lint stage error: ${compactReason(lintError.getMessage())}"
                                )
                            }
                            throw lintError
                        }
                    }
                }
            }
        }

        stage('Reset Fabric') {
            when {
                expression { return params.RESET_FABRIC_AFTER_RUN }
            }
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    script {
                        resetFabricAfterRun()
                    }
                }
            }
        }
    }

    post {
        always {
            script {
                try {
                    sendWebexSummary()
                } catch (Exception notificationError) {
                    echo "Webex notification failed: ${notificationError.getMessage()}"
                } finally {
                    if (env.CURRENT_ND_INVENTORY?.trim()) {
                        sh(
                            returnStatus: true,
                            script: '''#!/bin/bash
rm -f -- "${CURRENT_ND_INVENTORY}"
'''
                        )
                    }
                }
            }
        }
    }
}

def initializeResultState() {
    env.PIPELINE_FAILED = 'false'
    env.TEST_RESULT_SUMMARY = ''
    env.BUILD_FAILURE_REASON = ''
    env.TOTAL_PASSED_COUNT = '0'
    env.TOTAL_FAILED_COUNT = '0'
    env.TOTAL_SKIPPED_COUNT = '0'
    env.TOTAL_UNREACHABLE_COUNT = '0'
    env.TOTAL_ERROR_COUNT = '0'
}

def downloadFromConsul(String consulPrefix, String fileName) {
    // FROM MY CODE: validate remote/local names and use curl timeouts plus a
    // temporary file so a failed download cannot replace a valid asset.
    if (!(consulPrefix ==~ /[A-Za-z0-9._\/-]+/)) {
        error("Unsafe Consul prefix: ${consulPrefix}")
    }

    if (!(fileName ==~ /[A-Za-z0-9._-]+/)) {
        error("Unsafe Consul filename: ${fileName}")
    }

    def consulUrl = (
        "${env.CONSUL_URL}/v1/kv/${consulPrefix}/${fileName}?raw"
    )

    withEnv([
        "CONSUL_DOWNLOAD_URL=${consulUrl}",
        "CONSUL_TARGET_FILE=${fileName}"
    ]) {
        sh '''#!/bin/bash
set -euo pipefail

temporary_file=$(mktemp ".${CONSUL_TARGET_FILE}.XXXXXX")
trap 'rm -f -- "${temporary_file}"' EXIT

curl \
    --fail \
    --silent \
    --show-error \
    --connect-timeout 10 \
    --max-time 60 \
    --output "${temporary_file}" \
    "${CONSUL_DOWNLOAD_URL}"

mv -- "${temporary_file}" "${CONSUL_TARGET_FILE}"
trap - EXIT
'''
    }

    echo "Downloaded ${fileName} from Consul prefix ${consulPrefix}"
}

def runNDTests(ndConfig) {
    generateInventory(ndConfig)

    // FROM MY CODE: fail early when credentials, connectivity, or the ND
    // platform version do not satisfy the testbed requirements.
    try {
        timeout(time: 10, unit: 'MINUTES') {
            sh '''#!/bin/bash
set -euo pipefail
cd "${COLLECTIONS_DIRECTORY}"
source "${BASE_DIRECTORY}/venv/bin/activate"

ansible-playbook \
    -i "${CURRENT_ND_INVENTORY}" \
    nd_precheck.yaml
'''
        }
    } catch (Exception precheckError) {
        env.PIPELINE_FAILED = 'true'
        appendFailureReason(
            "ND precheck failed: ${compactReason(precheckError.getMessage())}"
        )
        throw precheckError
    }

    def targetPlan = []
    INTEGRATION_MODULES.each { targetName ->
        targetPlan << [name: targetName, type: 'integration']
    }

    if (params.RUN_SMOKE) {
        PLAYBOOK_FILES.each { targetName ->
            targetPlan << [name: targetName, type: 'smoke']
        }
    }

    // FROM MY CODE: collect every failed target and raise one aggregate error
    // only after the remaining targets have had an opportunity to execute.
    def failedTargets = []

    targetPlan.each { target ->
        def outcome = runTarget(ndConfig, target.name, target.type)
        if (!outcome.success) {
            failedTargets << "${target.name}: ${outcome.status}"
        }
    }

    if (failedTargets) {
        env.PIPELINE_FAILED = 'true'
        error("One or more ND targets failed: ${failedTargets.join('; ')}")
    }
}

def runTarget(ndConfig, String targetName, String targetType) {
    // FROM MY CODE: every target owns its output file, timeout, duration,
    // parsed result, cleanup verification, and Jenkins artifact.
    validateTargetName(targetName, targetType)

    int targetTimeout = targetType == 'integration' ?
        INTEGRATION_TIMEOUT_MINUTES : SMOKE_TIMEOUT_MINUTES
    def outputFileName = (
        "test_output_${ndConfig.fabric_name}_${ndConfig.versionId}_${targetName}.txt"
    )
    def outputFile = "${env.COLLECTIONS_DIRECTORY}/${outputFileName}"

    int executionRc = -1
    boolean executionInterrupted = false
    boolean cleanupFailed = false
    def executionReason = ''
    def cleanupReason = ''

    withEnv([
        "ND_CURRENT_TARGET=${targetName}",
        "ND_TARGET_TYPE=${targetType}",
        "ND_OUTPUT_FILE=${outputFile}"
    ]) {
        try {
            executionRc = timeout(time: targetTimeout, unit: 'MINUTES') {
                sh(
                    returnStatus: true,
                    script: '''#!/bin/bash
set -euo pipefail
cd "${COLLECTIONS_DIRECTORY}"
source "${BASE_DIRECTORY}/venv/bin/activate"

: > "${ND_OUTPUT_FILE}"
START_TIME=$(date +%s)
echo "[TARGET: ${ND_CURRENT_TARGET}] Starting" | tee -a "${ND_OUTPUT_FILE}"
echo "[TIMESTAMP_START: ${START_TIME}]" >> "${ND_OUTPUT_FILE}"

set +e
if [ "${ND_TARGET_TYPE}" = "integration" ]; then
    ansible-playbook \
        -i "${CURRENT_ND_INVENTORY}" \
        run_integration_module.yaml \
        -e "test_module=${ND_CURRENT_TARGET}" 2>&1 | tee -a "${ND_OUTPUT_FILE}"
else
    ansible-playbook \
        -i "${CURRENT_ND_INVENTORY}" \
        "${ND_CURRENT_TARGET}" 2>&1 | tee -a "${ND_OUTPUT_FILE}"
fi
# FROM MY CODE: preserve ansible-playbook's status; tee's zero status must not
# turn a failed Ansible invocation into a successful Jenkins shell step.
TARGET_RC=${PIPESTATUS[0]}
set -e

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
echo "[TIMESTAMP_END: ${END_TIME}]" >> "${ND_OUTPUT_FILE}"
echo "[DURATION_SECONDS: ${DURATION}]" >> "${ND_OUTPUT_FILE}"
echo "[EXIT_CODE: ${TARGET_RC}]" >> "${ND_OUTPUT_FILE}"
echo "[TARGET: ${ND_CURRENT_TARGET}] Completed with rc=${TARGET_RC}" | tee -a "${ND_OUTPUT_FILE}"

exit "${TARGET_RC}"
'''
                )
            }

            if (executionRc != 0) {
                executionReason = "ansible-playbook exited with code ${executionRc}"
            }
        } catch (Exception executionError) {
            executionInterrupted = true
            executionReason = compactReason(executionError.getMessage())
        }

        // FROM MY CODE: cleanup verification is attempted even after the main
        // target fails, and its outcome is retained independently.
        if (targetType == 'integration') {
            try {
                int cleanupRc = timeout(time: 15, unit: 'MINUTES') {
                    sh(
                        returnStatus: true,
                        script: '''#!/bin/bash
set -euo pipefail
cd "${COLLECTIONS_DIRECTORY}"
source "${BASE_DIRECTORY}/venv/bin/activate"

echo "[CLEANUP VERIFY: ${ND_CURRENT_TARGET}] Starting" | tee -a "${ND_OUTPUT_FILE}"
ansible-playbook \
    -i "${CURRENT_ND_INVENTORY}" \
    -e "nd_suite=${ND_CURRENT_TARGET}" \
    nd_cleanup_verify.yaml 2>&1 | tee -a "${ND_OUTPUT_FILE}"
'''
                    )
                }

                if (cleanupRc != 0) {
                    cleanupFailed = true
                    cleanupReason = "cleanup verification exited with code ${cleanupRc}"
                }
            } catch (Exception cleanupError) {
                cleanupFailed = true
                cleanupReason = compactReason(cleanupError.getMessage())
            }
        }
    }

    def outcome
    if (fileExists(outputFile)) {
        try {
            outcome = parseTestResults(
                ndConfig,
                targetName,
                targetType,
                outputFile,
                executionRc != 0 || executionInterrupted,
                executionReason,
                cleanupFailed,
                cleanupReason
            )
        } catch (Exception parseError) {
            def reason = "result parsing failed: ${compactReason(parseError.getMessage())}"
            recordTestResult(
                ndConfig,
                targetName,
                targetType,
                0,
                1,
                0,
                0,
                'N/A',
                'ERROR',
                reason
            )
            outcome = [success: false, status: 'ERROR']
        }

        archiveTargetOutput(outputFileName)
    } else {
        def reason = executionReason ?
            "no output file; ${executionReason}" : 'no output file was produced'
        recordTestResult(
            ndConfig,
            targetName,
            targetType,
            0,
            1,
            0,
            0,
            'N/A',
            'ERROR',
            reason
        )
        outcome = [success: false, status: 'ERROR']
    }

    return outcome
}

def validateTargetName(String targetName, String targetType) {
    if (targetType == 'integration') {
        if (!(targetName ==~ /nd_[a-z0-9_]+/)) {
            error("Unsafe integration target name: ${targetName}")
        }
        return
    }

    if (targetType == 'smoke') {
        if (!(targetName ==~ /nd_[a-z0-9_]+[.]yaml/)) {
            error("Unsafe smoke playbook name: ${targetName}")
        }
        return
    }

    error("Unsupported target type: ${targetType}")
}

def parseTestResults(
    ndConfig,
    String targetName,
    String targetType,
    String outputFile,
    boolean executionFailed,
    String executionReason,
    boolean cleanupFailed,
    String cleanupReason
) {
    // FROM MY CODE: parse each target's own saved output instead of trying to
    // infer the complete build result from one combined console stream.
    def output = readFile(outputFile)
    def duration = extractDuration(output)

    // FROM MY CODE: the cleanup verifier is a separate health check. Its PLAY
    // RECAP must not inflate the target's passed/failed/skipped totals.
    def suiteOutput = output
    def cleanupIndex = output.indexOf('[CLEANUP VERIFY:')
    if (cleanupIndex >= 0) {
        suiteOutput = output.substring(0, cleanupIndex)
    }

    int passedCount = 0
    int failedCount = 0
    int skippedCount = 0
    int unreachableCount = 0
    boolean hasRecap = false

    suiteOutput.split('\n').each { line ->
        if (isRecapLine(line)) {
            hasRecap = true
            passedCount += extractRecapValue(line, 'ok')
            failedCount += extractRecapValue(line, 'failed')
            skippedCount += extractRecapValue(line, 'skipped')
            unreachableCount += extractRecapValue(line, 'unreachable')
        }
    }

    def statusParts = []
    def reasons = []

    if (failedCount > 0) {
        statusParts << 'FAILED'
        reasons << "${failedCount} failed Ansible task(s)"
    }

    if (unreachableCount > 0) {
        statusParts << 'UNREACHABLE'
        reasons << "${unreachableCount} unreachable host result(s)"
    }

    // FROM MY CODE: preserve a visible failure when setup, timeout, or another
    // infrastructure error prevents Ansible from writing a PLAY RECAP.
    if (executionFailed) {
        if (!hasRecap && failedCount == 0 && unreachableCount == 0) {
            // Preserve a visible failure even when setup/timeout prevents a recap.
            failedCount = 1
            statusParts << 'ERROR'
        }
        if (!statusParts) {
            statusParts << 'ERROR'
        }
        reasons << (executionReason ?: 'target execution failed')
    }

    if (!hasRecap && !executionFailed) {
        failedCount = 1
        statusParts << 'ERROR'
        reasons << 'no PLAY RECAP was found'
    }

    if (cleanupFailed) {
        statusParts << 'CLEANUP_FAILED'
        reasons << (cleanupReason ?: 'cleanup verification failed')
    }

    def status = statusParts ? statusParts.unique().join('+') : 'PASSED'
    def reason = reasons.collect { compactReason(it) }.unique().join('; ')

    recordTestResult(
        ndConfig,
        targetName,
        targetType,
        passedCount,
        failedCount,
        skippedCount,
        unreachableCount,
        duration,
        status,
        reason
    )

    return [success: status == 'PASSED', status: status]
}

def isRecapLine(String line) {
    return (
        line.contains('ok=') &&
        line.contains('changed=') &&
        line.contains('unreachable=') &&
        line.contains('failed=') &&
        line.contains('skipped=')
    )
}

def extractRecapValue(String line, String fieldName) {
    def marker = "${fieldName}="
    def markerIndex = line.indexOf(marker)

    if (markerIndex < 0) {
        return 0
    }

    def remainder = line.substring(markerIndex + marker.length()).trim()
    int valueEnd = 0

    while (
        valueEnd < remainder.length() &&
        Character.isDigit(remainder.charAt(valueEnd))
    ) {
        valueEnd++
    }

    def digits = remainder.substring(0, valueEnd)
    return digits ? digits as Integer : 0
}

def extractDuration(String output) {
    def marker = '[DURATION_SECONDS:'
    def markerIndex = output.indexOf(marker)

    if (markerIndex < 0) {
        return 'N/A'
    }

    def remainder = output.substring(markerIndex + marker.length())
    def markerEnd = remainder.indexOf(']')

    if (markerEnd <= 0) {
        return 'N/A'
    }

    try {
        int totalSeconds = remainder.substring(0, markerEnd).trim() as Integer
        return "${(int) (totalSeconds / 60)}m ${totalSeconds % 60}s"
    } catch (Exception ignored) {
        return 'N/A'
    }
}

def recordTestResult(
    ndConfig,
    String targetName,
    String targetType,
    int passedCount,
    int failedCount,
    int skippedCount,
    int unreachableCount,
    String duration,
    String status,
    String reason
) {
    env.TOTAL_PASSED_COUNT = (
        (env.TOTAL_PASSED_COUNT as Integer) + passedCount
    ).toString()
    env.TOTAL_FAILED_COUNT = (
        (env.TOTAL_FAILED_COUNT as Integer) + failedCount
    ).toString()
    env.TOTAL_SKIPPED_COUNT = (
        (env.TOTAL_SKIPPED_COUNT as Integer) + skippedCount
    ).toString()
    env.TOTAL_UNREACHABLE_COUNT = (
        (env.TOTAL_UNREACHABLE_COUNT as Integer) + unreachableCount
    ).toString()

    if (status.contains('ERROR') || status.contains('CLEANUP_FAILED')) {
        env.TOTAL_ERROR_COUNT = (
            (env.TOTAL_ERROR_COUNT as Integer) + 1
        ).toString()
    }

    def displayName = targetName.endsWith('.yaml') ?
        targetName.substring(0, targetName.length() - 5) : targetName
    def resultLine = (
        "📋 Playbook: ${displayName} | Type: ${targetType} | " +
        "Fabric: ${ndConfig.fabric_name} | ND: ${ndConfig.version} | " +
        "Passed: ${passedCount} | Failed: ${failedCount} | " +
        "Skipped: ${skippedCount} | Unreachable: ${unreachableCount} | " +
        "Duration: ${duration} | Status: ${status}"
    )

    env.TEST_RESULT_SUMMARY = env.TEST_RESULT_SUMMARY?.trim() ?
        "${env.TEST_RESULT_SUMMARY}\n${resultLine}" : resultLine

    if (status != 'PASSED') {
        env.PIPELINE_FAILED = 'true'
        appendFailureReason(
            "${displayName} (${targetType}) ${status}: ${reason ?: 'no reason recorded'}"
        )
    }
}

def appendFailureReason(String reason) {
    def safeReason = compactReason(reason)
    env.BUILD_FAILURE_REASON = env.BUILD_FAILURE_REASON?.trim() ?
        "${env.BUILD_FAILURE_REASON}\n❌ ${safeReason}" : "❌ ${safeReason}"
}

def compactReason(def reason) {
    def value = reason?.toString()?.replaceAll(/\s+/, ' ')?.trim()
    if (!value) {
        return 'unspecified error'
    }
    return value.length() > 300 ? "${value.substring(0, 297)}..." : value
}

def archiveTargetOutput(String outputFileName) {
    // FROM MY CODE: retain each target's raw output as a Jenkins artifact so
    // the Webex summary can be traced back to its source evidence.
    try {
        archiveArtifacts(
            artifacts: "nd/${outputFileName}",
            allowEmptyArchive: true,
            fingerprint: true
        )
    } catch (Exception archiveError) {
        echo "Could not archive ${outputFileName}: ${archiveError.getMessage()}"
    }
}

def generateInventory(ndConfig) {
    // FROM MY CODE: create a temporary inventory with restrictive permissions
    // and remove it in post/always. JSON generation is a combined-draft safety
    // extension that avoids placing secrets inside a Groovy-interpolated string.
    def inventoryDirectory = pwd(tmp: true)
    def inventoryName = "inventory_${ndConfig.versionId}.json"
    def inventoryFile = "${inventoryDirectory}/${inventoryName}"

    env.CURRENT_ND_INVENTORY = inventoryFile

    withEnv(["ND_INVENTORY_FILE=${inventoryFile}"]) {
        sh '''#!/bin/bash
set -euo pipefail

python3.12 - <<'PY'
import json
import os

inventory = {
    "nd": {
        "hosts": {
            "nd": {
                "ansible_host": os.environ["ANSIBLE_HOST"]
            }
        },
        "vars": {
            "ansible_connection": "ansible.netcommon.httpapi",
            "ansible_python_interpreter": "{{ ansible_playbook_python }}",
            "ansible_network_os": "cisco.nd.nd",
            "ansible_httpapi_validate_certs": False,
            "ansible_httpapi_use_ssl": True,
            "ansible_httpapi_use_proxy": False,
            "ansible_httpapi_login_domain": "local",
            "ansible_command_timeout": 600,
            "ansible_connect_timeout": 60,
            "ansible_user": os.environ["ND_USER"],
            "ansible_password": os.environ["ND_PASSWORD"],
            "fabric_name": os.environ["FABRIC_NAME"],
            "ansible_it_fabric": os.environ["FABRIC_NAME"],
            "nd_test_fabric_name": os.environ["FABRIC_NAME"],
            "nd_test_vpc_access_fabric_name": os.environ["FABRIC_NAME"],
            "nd_test_vpc_trunk_host_fabric_name": os.environ["FABRIC_NAME"],
            "nd_test_switch_ip": os.environ["ND_SWITCH_IP"],
            "switch_serial_1": os.environ["ND_SWITCH_SERIAL_1"],
            "switch_serial_2": os.environ["ND_SWITCH_SERIAL_2"],
            "switch_serial_3": os.environ["ND_SWITCH_SERIAL_3"],
            "ansible_switch1": os.environ["ND_SWITCH_SERIAL_1"],
            "ansible_switch2": os.environ["ND_SWITCH_SERIAL_2"],
            "ansible_switch3": os.environ["ND_SWITCH_SERIAL_3"],
            "ansible_sno_1": os.environ["ND_SWITCH_SERIAL_1"],
            "ansible_sno_2": os.environ["ND_SWITCH_SERIAL_2"],
            "ansible_sno_3": os.environ["ND_SWITCH_SERIAL_3"],
            "nd_test_vpc_peer1_ip": os.environ["ND_SWITCH_SERIAL_1"],
            "nd_test_vpc_peer2_ip": os.environ["ND_SWITCH_SERIAL_2"],
            "nd_test_route_map_enable_overridden": False
        }
    }
}

with open(os.environ["ND_INVENTORY_FILE"], "w", encoding="utf-8") as inventory_file:
    json.dump(inventory, inventory_file)
PY

chmod 600 "${ND_INVENTORY_FILE}"
'''
    }

    echo 'Generated protected temporary ND inventory'
}

def runLintCheck() {
    def lintOutput = "${env.BASE_DIRECTORY}/ansible-lint-output.txt"
    def lintSummary = "${env.BASE_DIRECTORY}/lint_summary.txt"
    int lintRc

    withEnv([
        "LINT_OUTPUT_FILE=${lintOutput}",
        "LINT_SUMMARY_FILE=${lintSummary}"
    ]) {
        lintRc = sh(
            returnStatus: true,
            script: '''#!/bin/bash
set -uo pipefail
mkdir -p "${BASE_DIRECTORY}"
cd "${COLLECTIONS_DIRECTORY}"
source "${BASE_DIRECTORY}/venv/bin/activate"

if ! command -v ansible-lint >/dev/null 2>&1; then
    echo "ansible-lint is not installed" | tee "${LINT_OUTPUT_FILE}"
    echo "Infrastructure error: ansible-lint is not installed" > "${LINT_SUMMARY_FILE}"
    exit 127
fi

set +e
ansible-lint --profile=production > "${LINT_OUTPUT_FILE}" 2>&1
LINT_RC=$?
set -e

cat "${LINT_OUTPUT_FILE}"

if [ "${LINT_RC}" -eq 0 ]; then
    echo "Passed: ansible-lint found no violations" > "${LINT_SUMMARY_FILE}"
    exit 0
fi

CONDENSED_RULES=$(awk '
    /^# Rule Violation Summary/{found=1; next}
    /^Failed:/{exit}
    found && $1 ~ /^[0-9]+$/ {counts[$2]+=$1}
    END {for (rule in counts) print counts[rule], rule}
' "${LINT_OUTPUT_FILE}" | sort -rn | awk '{printf "%s%d %s", (NR > 1 ? ", " : ""), $1, $2}')

FAILED_LINE=$(grep '^Failed:' "${LINT_OUTPUT_FILE}" | head -1 | sed 's/ Profile.*$//' || true)

{
    if [ -n "${CONDENSED_RULES}" ]; then
        echo "cisco.nd: ${CONDENSED_RULES}"
    fi
    if [ -n "${FAILED_LINE}" ]; then
        echo "${FAILED_LINE}"
    else
        echo "ansible-lint exited with code ${LINT_RC}"
    fi
} > "${LINT_SUMMARY_FILE}"

exit "${LINT_RC}"
'''
        )
    }

    env.LINT_STATUS = lintRc == 0 ? 'PASSED' : 'FAILED'

    archiveArtifacts(
        artifacts: '.jenkins-runtime/ansible-lint-output.txt',
        allowEmptyArchive: true
    )

    return lintRc == 0
}

def resetFabricAfterRun() {
    if (!env.CURRENT_ND_INVENTORY?.trim()) {
        env.PIPELINE_FAILED = 'true'
        appendFailureReason('fabric reset skipped because no generated inventory exists')
        error('Cannot reset fabric without an inventory')
    }

    def resetPlaybook = "${env.COLLECTIONS_DIRECTORY}/reset_fabric.yaml"
    if (!fileExists(resetPlaybook)) {
        env.PIPELINE_FAILED = 'true'
        appendFailureReason('fabric reset playbook is missing')
        error("Missing reset playbook: ${resetPlaybook}")
    }

    int resetRc = sh(
        returnStatus: true,
        script: '''#!/bin/bash
set -euo pipefail
cd "${COLLECTIONS_DIRECTORY}"
source "${BASE_DIRECTORY}/venv/bin/activate"

ansible-playbook \
    -i "${CURRENT_ND_INVENTORY}" \
    reset_fabric.yaml
'''
    )

    if (resetRc != 0) {
        env.PIPELINE_FAILED = 'true'
        appendFailureReason("fabric reset failed with exit code ${resetRc}")
        error("Fabric reset failed with exit code ${resetRc}")
    }
}

def sendWebexSummary() {
    // FROM MY CODE: build the notification from accumulated per-target
    // counters and detailed results, then send it directly to the Webex API.
    def message = 'ND NIGHTLY NOTIFICATION\n'
    message += (
        "📊 Pipeline completed for the ND Nightly run - Build ${env.BUILD_NUMBER}\n"
    )
    message += "Result: ${currentBuild.currentResult}\n\n"
    message += "Total Passed: ${env.TOTAL_PASSED_COUNT ?: '0'}\n"
    message += "Total Failed: ${env.TOTAL_FAILED_COUNT ?: '0'}\n"
    message += "Total Skipped: ${env.TOTAL_SKIPPED_COUNT ?: '0'}\n"
    message += "Total Unreachable: ${env.TOTAL_UNREACHABLE_COUNT ?: '0'}\n"
    message += "Suite/Cleanup Errors: ${env.TOTAL_ERROR_COUNT ?: '0'}\n\n"
    message += '📝 DETAILED TEST RESULTS:\n'
    message += "${env.TEST_RESULT_SUMMARY?.trim() ?: 'No target results were recorded'}\n"

    def lintSummaryFile = "${env.BASE_DIRECTORY}/lint_summary.txt"
    if (fileExists(lintSummaryFile)) {
        def lintSummary = readFile(lintSummaryFile).trim()
        if (lintSummary) {
            message += "\n🧹 Ansible-lint Results (${env.LINT_STATUS}):\n"
            message += "${lintSummary}\n"
        }
    }

    if (env.BUILD_FAILURE_REASON?.trim()) {
        message += "\n⚠️ FAILURE DETAILS:\n${env.BUILD_FAILURE_REASON.trim()}\n"
    }

    message += "\n🔗 Results: ${env.BUILD_URL}console"

    def webexPayload = createWebexPayload(message)

    httpRequest(
        url: 'https://webexapis.com/v1/messages',
        httpMode: 'POST',
        acceptType: 'APPLICATION_JSON',
        contentType: 'APPLICATION_JSON',
        customHeaders: [[
            name: 'Authorization',
            value: 'Bearer ' + env.WEBEX_TOKEN,
            maskValue: true
        ]],
        requestBody: webexPayload,
        validResponseCodes: '200:299',
        consoleLogResponseBody: false
    )
}

def createWebexPayload(String message) {
    // FROM MY CODE: locally generate valid JSON instead of depending on the
    // Pipeline Utility Steps writeJSON operation or a downloaded helper script.
    def payload

    withEnv(["WEBEX_MESSAGE=${message}"]) {
        payload = sh(
            returnStdout: true,
            script: '''#!/bin/bash
set -euo pipefail

python3.12 -c \
  'import json, os; print(json.dumps({"roomId": os.environ["WEBEX_ROOM_ID"], "text": os.environ["WEBEX_MESSAGE"]}))'
'''
        ).trim()
    }

    if (!payload) {
        error('Python produced an empty Webex JSON payload')
    }

    return payload
}
