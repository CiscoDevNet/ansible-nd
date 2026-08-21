pipeline {
    agent {
        docker {
            image 'ansible_nd_setup'
            args "--user root"
        }
    }

    parameters {
        booleanParam(
            name: 'DEBUG',
            defaultValue: false,
            description: 'Enable additional non-sensitive logging'
        )

        choice(
            name: 'TARGET_SET',
            choices: [
                'both',
                'nd_interface_loopback',
                'nd_interface_ethernet_access'
            ],
            description: 'Run both supported suites or select one suite'
        )
    }

    environment {
        WEBEX_TOKEN = credentials('ANSIBLE_WEBEX_TOKEN')
        WEBEX_ROOM_ID = "61f7d4c0-9566-11f0-b070-451eba08616c" // private test space
        ND_USER = credentials('ANSIBLE_NDFC_USERNAME')
        ND_PASSWORD = credentials('ANSIBLE_NDFC_41_117_PASSWORD')
        ANSIBLE_HOST = "10.122.84.112"
        ND_SWITCH_IP = '10.122.84.71'
        BASE_DIR = "$WORKSPACE/.jenkins-runtime"
        COLLECTIONS_DIR = "$WORKSPACE/nd"
        COLL_DIR = "$WORKSPACE"
        CONSUL_URL = "http://10.78.210.155:8500"
        CONSUL_PREFIX = "ansible/nd4x-nightly"
        ND_BRANCH = 'develop'
        FABRIC = 'VXLAN_Fabric'
        PIPELINE_FAILED = 'false'
        TEST_RESULT_SUMMARY = ''
        BUILD_FAILURE_REASON = ''
        TOTAL_PASSED_COUNT = '0'
        TOTAL_FAILED_COUNT = '0'
        TOTAL_SKIPPED_COUNT = '0'
        RECORDED_SUITES = ''
        CURRENT_ND_INVENTORY = ''
    }

    triggers {
        cron('TZ=Asia/Kolkata\n0 2 * * *')
    }

    options {
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
                mkdir -p "${BASE_DIR}"
                cd "${BASE_DIR}"
                export PATH="${BASE_DIR}:$PATH"

                # Create or verify the Python virtual environment.
                if [ -d "${BASE_DIR}/venv" ]; then
                    VENV_PYTHON=$(${BASE_DIR}/venv/bin/python --version 2>&1 | awk '{print $2}')
                    if [[ "$VENV_PYTHON" != 3.12.* ]]; then
                        echo "Python version mismatch, recreating venv..."
                        rm -rf ${BASE_DIR}/venv
                        python3.12 -m venv ${BASE_DIR}/venv
                    fi
                else
                    echo "Creating venv with Python 3.12.3..."
                    python3.12 -m venv ${BASE_DIR}/venv
                fi

                source ${BASE_DIR}/venv/bin/activate
                echo "Python: $(python --version)"
                '''
            }
        }

        stage('Clone Repository') {
            steps {
                sh '''#!/bin/bash
                set -e
                cd "${COLL_DIR}"

                if [ -d "nd/.git" ]; then
                    cd nd
                    LOCAL_COMMIT=$(git rev-parse HEAD)
                    REMOTE_COMMIT=$(git ls-remote https://github.com/CiscoDevNet/ansible-nd.git refs/heads/${ND_BRANCH} | awk '{print $1}')

                    if [ "${LOCAL_COMMIT}" == "${REMOTE_COMMIT}" ]; then
                        echo "Repository is up-to-date"
                        exit 0
                    fi
                    cd "${COLL_DIR}"
                    rm -rf -- nd
                fi

                git clone --branch "${ND_BRANCH}" --single-branch https://github.com/CiscoDevNet/ansible-nd.git nd
                cd nd
                echo "Cloned at: $(git rev-parse HEAD)"
                source "${BASE_DIR}/venv/bin/activate"
                '''
            }
        }

        stage('Download ND Assets from Consul') {
            steps {
                script {
                    dir(env.COLLECTIONS_DIR) {
                        // Download the manifest first.
                        downloadFromConsul('nd_suite_manifest.yaml')

                        // Download common support files.
                        [
                            'ansible.cfg',
                            'requirements.txt',
                            'requirements.yaml',
                            'nd_precheck.yaml',
                            'nd_cleanup_verify.yaml'
                        ].each { fileName ->
                            downloadFromConsul(fileName)
                        }

                        // Download only the wrappers selected for this build.
                        getRequestedSuiteNames().each { suiteName ->
                            downloadFromConsul("${suiteName}.yaml")
                        }
                    }
                }
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '''#!/bin/bash
                set -euo pipefail
                cd "${COLLECTIONS_DIR}"
                source "${BASE_DIR}/venv/bin/activate"

                for required_file in \
                    ansible.cfg \
                    requirements.txt \
                    requirements.yaml \
                    nd_suite_manifest.yaml \
                    nd_precheck.yaml \
                    nd_cleanup_verify.yaml; do
                    if [ ! -f "$required_file" ]; then
                        echo "Required support file is missing: $required_file"
                        exit 1
                    fi
                done

                python -m pip install --disable-pip-version-check \
                  "ansible-core>=2.19,<2.20"
                python -m pip install --disable-pip-version-check \
                  -r requirements.txt
                ansible-galaxy collection install -r requirements.yaml
                python -c 'import yaml; print("PyYAML: " + yaml.__version__)'

                echo "Python: $(python --version)"
                echo "Ansible: $(ansible --version | head -1)"
                '''
            }
        }

        stage('Run Integration Tests') {
            steps {
                script {
                    def ndConfig = [
                        version: '4.1',
                        versionId: 'ND41',
                        server: 'ANSIBLE_HOST',
                        fabric_name: 'cisco_test_fabric',
                    ]

                    env.PIPELINE_FAILED = 'false'
                    env.TEST_RESULT_SUMMARY = ''
                    env.BUILD_FAILURE_REASON = ''
                    env.TOTAL_PASSED_COUNT = '0'
                    env.TOTAL_FAILED_COUNT = '0'
                    env.TOTAL_SKIPPED_COUNT = '0'
                    env.RECORDED_SUITES = ''

                    try {
                        runNDTests(ndConfig)
                    } catch (Exception e) {
                        echo "ND tests failed: ${e.getMessage()}"
                        env.PIPELINE_FAILED = 'true'
                        currentBuild.result = 'FAILURE'
                        throw e
                    }
                }
            }
        }
    }

    post {
        always {
            script {
                try {
                    if (env.CURRENT_ND_INVENTORY?.trim()) {
                        sh returnStatus: true, script: '''#!/bin/bash
                            rm -f -- "${CURRENT_ND_INVENTORY}"
                            '''
                    }

                    def message = "ND NIGHTLY NOTIFICATION\n"
                    message += (
                        "📊 Pipeline completed for the ND Nightly run - " +
                        "Build ${BUILD_NUMBER}\n\n"
                    )
                    message += "Total Passed: ${env.TOTAL_PASSED_COUNT ?: '0'}\n"
                    message += "Total Failed: ${env.TOTAL_FAILED_COUNT ?: '0'}\n\n"
                    message += "📝 DETAILED TEST RESULTS:\n"
                    message += "${env.TEST_RESULT_SUMMARY ?: 'No results'}\n\n"
                    message += "🔗 Build: ${BUILD_URL}console\n"

                    def webexPayload = createWebexPayload(message)

                    httpRequest(
                        url: 'https://webexapis.com/v1/messages',
                        httpMode: 'POST',
                        acceptType: 'APPLICATION_JSON',
                        contentType: 'APPLICATION_JSON',
                        customHeaders: [[
                            name: 'Authorization',
                            value: "Bearer ${env.WEBEX_TOKEN}",
                            maskValue: true
                        ]],
                        requestBody: webexPayload,
                        validResponseCodes: '200:299',
                        consoleLogResponseBody: false
                    )
                } catch (Exception e) {
                    echo "Webex notification failed: ${e.getMessage()}"
                }
            }
        }
    }
}

def getRequestedSuiteNames() {
    def supportedTargets = [
        'nd_interface_loopback',
        'nd_interface_ethernet_access'
    ]

    if (params.TARGET_SET == 'both') {
        return supportedTargets
    }

    def requestedTarget = params.TARGET_SET?.toString()

    if (!supportedTargets.contains(requestedTarget)) {
        error("Unsupported TARGET_SET: ${requestedTarget}")
    }

    return [requestedTarget]
}

def createWebexPayload(String message) {
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

def downloadFromConsul(fileName, localFileName = null) {
    if (!(fileName ==~ /[A-Za-z0-9._-]+/)) {
        error("Unsafe Consul filename: ${fileName}")
    }

    def targetFileName = localFileName ?: fileName

    if (!(targetFileName ==~ /[A-Za-z0-9._-]+/)) {
        error("Unsafe local filename: ${targetFileName}")
    }

    def consulUrl =
        "${env.CONSUL_URL}/v1/kv/${env.CONSUL_PREFIX}/${fileName}?raw"

    echo "Downloading ${fileName} from Consul prefix ${env.CONSUL_PREFIX}"

    withEnv([
        "CONSUL_DOWNLOAD_URL=${consulUrl}",
        "CONSUL_TARGET_FILE=${targetFileName}"
    ]) {
        sh '''#!/bin/bash
            set -euo pipefail

            temporary_file="$(mktemp ".${CONSUL_TARGET_FILE}.XXXXXX")"
            trap 'rm -f -- "$temporary_file"' EXIT

            curl --fail \
                --silent \
                --show-error \
                --connect-timeout 10 \
                --max-time 60 \
                --output "$temporary_file" \
                "$CONSUL_DOWNLOAD_URL"

            mv -- "$temporary_file" "$CONSUL_TARGET_FILE"
            trap - EXIT
            '''
    }

    echo "Downloaded ${fileName}"
}

def loadSuiteConfiguration(String suiteName) {
    if (!(suiteName ==~ /nd_[a-z0-9_]+/)) {
        error("Unsafe suite name: ${suiteName}")
    }

    def manifestRecord

    dir(env.COLLECTIONS_DIR) {
        withEnv(["ND_REQUESTED_SUITE=${suiteName}"]) {
            manifestRecord = sh(
                returnStdout: true,
                script: '''#!/bin/bash
set -euo pipefail
source "${BASE_DIR}/venv/bin/activate"

python - <<'PY'
import os
import re

import yaml


with open("nd_suite_manifest.yaml", encoding="utf-8") as manifest_file:
    manifest = yaml.safe_load(manifest_file)

if not isinstance(manifest, dict):
    raise SystemExit("nd_suite_manifest.yaml must contain a YAML mapping")

if manifest.get("schema_version") != 1:
    raise SystemExit(
        "Unsupported manifest schema_version: "
        f"{manifest.get('schema_version')}"
    )

suites = manifest.get("suites")
if not isinstance(suites, dict) or not suites:
    raise SystemExit("nd_suite_manifest.yaml contains no suites")

suite_name = os.environ["ND_REQUESTED_SUITE"]
suite = suites.get(suite_name)
if not isinstance(suite, dict):
    raise SystemExit(f"Suite is not present in the manifest: {suite_name}")

testbed = suite.get("testbed")
timeout_minutes = suite.get("timeout_minutes")
local_status = suite.get("local_status")
tags = suite.get("tags", [])

if not isinstance(testbed, str) or not re.fullmatch(r"[a-z0-9_-]+", testbed):
    raise SystemExit(f"Suite {suite_name} has an invalid testbed value")

if (
    not isinstance(timeout_minutes, int)
    or isinstance(timeout_minutes, bool)
):
    raise SystemExit(f"Suite {suite_name} has no valid timeout_minutes value")

if (
    not isinstance(local_status, str)
    or not re.fullmatch(r"[a-z0-9_-]+", local_status)
):
    raise SystemExit(f"Suite {suite_name} has an invalid local_status value")

if not isinstance(tags, list):
    raise SystemExit(f"Suite {suite_name} tags must be a YAML list")

for tag in tags:
    if not isinstance(tag, str) or not re.fullmatch(r"[a-zA-Z0-9_:-]+", tag):
        raise SystemExit(f"Suite {suite_name} contains an unsafe tag: {tag}")

tags_record = ",".join(tags) if tags else "-"
print(
    "\t".join(
        [testbed, str(timeout_minutes), local_status, tags_record]
    )
)
PY
'''
            ).trim()
        }
    }

    def fields = manifestRecord.split('\t', -1)

    if (fields.size() != 4) {
        error("Unable to parse manifest configuration for ${suiteName}")
    }

    def tags = fields[3] == '-' ? [] : fields[3].split(',').toList()

    return [
        testbed: fields[0],
        timeout_minutes: fields[1] as Integer,
        local_status: fields[2],
        tags: tags
    ]
}

def runNDTests(ndConfig) {
    echo "Running ND ${ndConfig.version} tests..."

    generateInventory(ndConfig)

    timeout(time: 10, unit: 'MINUTES') {
        sh '''#!/bin/bash
        set -euo pipefail
        cd "${COLLECTIONS_DIR}"
        source "${BASE_DIR}/venv/bin/activate"

        ansible-playbook \
          -i "${CURRENT_ND_INVENTORY}" \
          nd_precheck.yaml
        '''
    }

    def requestedSuiteNames = getRequestedSuiteNames()

    def selectedSuites = [:]

    requestedSuiteNames.each { requestedSuite ->
        def requestedConfig = loadSuiteConfiguration(requestedSuite)

        if (requestedConfig.local_status != 'passed') {
            error(
                "Suite ${requestedSuite} is not approved: " +
                "local_status=${requestedConfig.local_status}"
            )
        }

        selectedSuites[requestedSuite] = requestedConfig
    }

    if (!selectedSuites) {
        error('No manifest-approved suites were selected')
    }

    env.TOTAL_PASSED_COUNT = '0'
    env.TOTAL_FAILED_COUNT = '0'
    env.TOTAL_SKIPPED_COUNT = '0'
    env.TEST_RESULT_SUMMARY = ''
    env.RECORDED_SUITES = ''

    def suiteFailures = []

    selectedSuites.each { suiteName, suiteConfig ->
        try {
            validateSuiteConfiguration(suiteName, suiteConfig)
            runSuiteWithVerification(ndConfig, suiteName, suiteConfig)
        } catch (Exception suiteError) {
            env.PIPELINE_FAILED = 'true'
            if (!hasRecordedTestResult(suiteName)) {
                recordTestResult(
                    ndConfig,
                    suiteName,
                    0,
                    1,
                    0,
                    '0m 0s'
                )
            }
            suiteFailures << "${suiteName}: ${suiteError.getMessage()}"
            echo "Suite execution failed: ${suiteName}"
        }
    }

    if (suiteFailures) {
        error("One or more suites failed: ${suiteFailures.join('; ')}")
    }
}

def validateSuiteConfiguration(String suiteName, suiteConfig) {
    if (!suiteName.matches('^nd_[a-z0-9_]+$')) {
        error("Unsafe suite name in manifest: ${suiteName}")
    }

    if (suiteConfig.testbed != 'primary') {
        error(
            "Suite ${suiteName} uses unsupported testbed: " +
            "${suiteConfig.testbed}"
        )
    }

    if (suiteConfig.timeout_minutes == null) {
        error("Suite ${suiteName} has no timeout_minutes value")
    }

    int timeoutMinutes = suiteConfig.timeout_minutes as Integer
    if (timeoutMinutes <= 0) {
        error("Suite ${suiteName} has an invalid timeout: ${timeoutMinutes}")
    }

    def tags = suiteConfig.tags ?: []
    if (!(tags instanceof List)) {
        error("Suite ${suiteName} tags must be a YAML list")
    }

    tags.each { tag ->
        if (!tag.toString().matches('^[a-zA-Z0-9_:-]+$')) {
            error("Suite ${suiteName} contains an unsafe tag: ${tag}")
        }
    }

    def wrapperFile = "${env.COLLECTIONS_DIR}/${suiteName}.yaml"
    if (!fileExists(wrapperFile)) {
        error("Suite wrapper is missing: ${suiteName}.yaml")
    }
}

def runSuiteWithVerification(ndConfig, String suiteName, suiteConfig) {
    int timeoutMinutes = suiteConfig.timeout_minutes as Integer
    def tags = (suiteConfig.tags ?: []).collect { it.toString() }
    def outputFile = "${env.COLLECTIONS_DIR}/test_output_${suiteName}.txt"
    def failureMessages = []

    withEnv([
        "ND_CURRENT_SUITE=${suiteName}",
        "ND_SUITE_TAGS=${tags.join(',')}",
        "ND_OUTPUT_FILE=${outputFile}"
    ]) {
        try {
            timeout(time: timeoutMinutes, unit: 'MINUTES') {
                sh '''#!/bin/bash
                set -euo pipefail
                cd "${COLLECTIONS_DIR}"
                source "${BASE_DIR}/venv/bin/activate"

                : > "${ND_OUTPUT_FILE}"
                echo "[TARGET: ${ND_CURRENT_SUITE}] Starting..." | tee -a "${ND_OUTPUT_FILE}"
                START_TIME=$(date +%s)
                echo "[TIMESTAMP_START: ${START_TIME}]" >> "${ND_OUTPUT_FILE}"

                set +e
                if [ -n "${ND_SUITE_TAGS}" ]; then
                    ansible-playbook \
                      -i "${CURRENT_ND_INVENTORY}" \
                      --tags "${ND_SUITE_TAGS}" \
                      "${ND_CURRENT_SUITE}.yaml" 2>&1 | tee -a "${ND_OUTPUT_FILE}"
                else
                    ansible-playbook \
                      -i "${CURRENT_ND_INVENTORY}" \
                      "${ND_CURRENT_SUITE}.yaml" 2>&1 | tee -a "${ND_OUTPUT_FILE}"
                fi
                SUITE_RC=${PIPESTATUS[0]}
                set -e

                END_TIME=$(date +%s)
                DURATION=$((END_TIME - START_TIME))
                echo "[TIMESTAMP_END: ${END_TIME}]" >> "${ND_OUTPUT_FILE}"
                echo "[DURATION_SECONDS: ${DURATION}]" >> "${ND_OUTPUT_FILE}"
                echo "[TARGET: ${ND_CURRENT_SUITE}] Done with rc=${SUITE_RC}." | tee -a "${ND_OUTPUT_FILE}"
                exit "${SUITE_RC}"
                '''
            }
        } catch (Exception suiteError) {
            failureMessages << "suite failed: ${suiteError.getMessage()}"
            env.PIPELINE_FAILED = 'true'
        } finally {
            try {
                timeout(time: 10, unit: 'MINUTES') {
                    sh '''#!/bin/bash
                    set -euo pipefail
                    cd "${COLLECTIONS_DIR}"
                    source "${BASE_DIR}/venv/bin/activate"

                    echo "[CLEANUP VERIFY: ${ND_CURRENT_SUITE}] Starting..." | tee -a "${ND_OUTPUT_FILE}"
                    ansible-playbook \
                      -i "${CURRENT_ND_INVENTORY}" \
                      -e "nd_suite=${ND_CURRENT_SUITE}" \
                      nd_cleanup_verify.yaml 2>&1 | tee -a "${ND_OUTPUT_FILE}"
                    echo "[CLEANUP VERIFY: ${ND_CURRENT_SUITE}] Passed." | tee -a "${ND_OUTPUT_FILE}"
                    '''
                }
            } catch (Exception verificationError) {
                failureMessages << (
                    "cleanup verification failed: " +
                    verificationError.getMessage()
                )
                env.PIPELINE_FAILED = 'true'
            }
        }
    }

    if (fileExists(outputFile)) {
        parseTestResults(
            ndConfig,
            suiteName,
            outputFile,
            !failureMessages.isEmpty()
        )
        def timestamp = new Date().format('yyyyMMdd_HHmmss')
        def artifactName = "test_output_${suiteName}_${timestamp}.txt"
        sh "cp '${outputFile}' '${env.WORKSPACE}/${artifactName}'"
        archiveArtifacts artifacts: artifactName, allowEmptyArchive: true
        sh "rm -f '${env.WORKSPACE}/${artifactName}'"
    } else {
        failureMessages << 'no output file was produced'
        env.PIPELINE_FAILED = 'true'
        recordTestResult(ndConfig, suiteName, 0, 1, 0, 'N/A')
    }

    if (failureMessages) {
        error("${suiteName}: ${failureMessages.join('; ')}")
    }
}

def generateInventory(ndConfig) {
    if (!env.ND_SWITCH_IP?.trim()) {
        error('ND_SWITCH_IP is not configured')
    }

    def inv = """[nd]
nd ansible_host=${env.ANSIBLE_HOST}

[nd:vars]
ansible_connection=ansible.netcommon.httpapi
ansible_python_interpreter={{ ansible_playbook_python }}
ansible_network_os=cisco.nd.nd
ansible_httpapi_validate_certs=False
ansible_httpapi_use_ssl=True
ansible_httpapi_use_proxy=False
ansible_httpapi_login_domain=local
ansible_command_timeout=600
ansible_connect_timeout=60
ansible_user=${env.ND_USER}
ansible_password=${env.ND_PASSWORD}
nd_test_fabric_name=${env.FABRIC}
nd_test_switch_ip=${env.ND_SWITCH_IP}
"""

    def inventoryDirectory = pwd(tmp: true)
    def inventoryName = "inventory_${ndConfig.versionId}.networking"
    def inventoryFile = "${inventoryDirectory}/${inventoryName}"

    dir(inventoryDirectory) {
        writeFile file: inventoryName, text: inv
        sh "chmod 600 '${inventoryName}'"
    }

    env.CURRENT_ND_INVENTORY = inventoryFile
    echo 'Generated temporary ND inventory'
}


def parseTestResults(
    ndConfig,
    String targetName,
    String outputFile,
    boolean executionFailed
) {
    def output = readFile(outputFile)

    // Extract duration
    def durationStr = 'N/A'
    if (output.contains('[DURATION_SECONDS:')) {
        def idx = output.indexOf('[DURATION_SECONDS:')
        def after = output.substring(idx + '[DURATION_SECONDS:'.length())
        def end = after.indexOf(']')
        if (end > 0) {
            def secs = after.substring(0, end).trim() as Integer
            durationStr = "${secs / 60}m ${secs % 60}s"
        }
    }

    // Exclude the cleanup verification recap from the suite's own result.
    def suiteOutput = output
    def cleanupIndex = output.indexOf('[CLEANUP VERIFY:')
    if (cleanupIndex >= 0) {
        suiteOutput = output.substring(0, cleanupIndex)
    }

    // Parse the suite PLAY RECAP lines.
    def okCount = 0
    def failedCount = 0
    def skippedCount = 0

    suiteOutput.split('\n').each { line ->
        if (
            line.contains('ok=') &&
            line.contains('changed=') &&
            line.contains('unreachable=') &&
            line.contains('failed=') &&
            line.contains('skipped=')
        ) {
            okCount += extractRecapValue(line, 'ok')
            failedCount += extractRecapValue(line, 'failed')
            skippedCount += extractRecapValue(line, 'skipped')
        }
    }

    // A wrapper/setup/timeout failure may occur before Ansible emits a recap.
    if (executionFailed && failedCount == 0) {
        failedCount = 1
    }

    recordTestResult(
        ndConfig,
        targetName,
        okCount,
        failedCount,
        skippedCount,
        durationStr
    )

    if (failedCount > 0) {
        env.PIPELINE_FAILED = 'true'
        echo "Failures detected in ${targetName}: ${failedCount} tasks failed"
    }
}

def extractRecapValue(String line, String fieldName) {
    def marker = "${fieldName}="
    def markerIndex = line.indexOf(marker)

    if (markerIndex < 0) {
        return 0
    }

    def valueStart = markerIndex + marker.length()
    def remainder = line.substring(valueStart).trim()
    def valueEnd = 0

    while (
        valueEnd < remainder.length() &&
        Character.isDigit(remainder.charAt(valueEnd))
    ) {
        valueEnd++
    }

    def digits = remainder.substring(0, valueEnd)

    return digits ? digits as Integer : 0
}

def recordTestResult(
    ndConfig,
    String targetName,
    int passedCount,
    int failedCount,
    int skippedCount,
    String duration
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

    def resultLine = (
        "📋 Playbook: ${targetName} | Fabric: ${env.FABRIC} | " +
        "ND: ${ndConfig.version} | Passed: ${passedCount} | " +
        "Failed: ${failedCount} | Skipped: ${skippedCount} | " +
        "Duration: ${duration}"
    )

    env.TEST_RESULT_SUMMARY = env.TEST_RESULT_SUMMARY?.trim() ?
        "${env.TEST_RESULT_SUMMARY}\n${resultLine}" :
        resultLine

    def recordedSuites = env.RECORDED_SUITES?.trim() ?
        env.RECORDED_SUITES.split(',').toList() :
        []
    if (!recordedSuites.contains(targetName)) {
        recordedSuites << targetName
    }
    env.RECORDED_SUITES = recordedSuites.join(',')
}

def hasRecordedTestResult(String targetName) {
    if (!env.RECORDED_SUITES?.trim()) {
        return false
    }

    return env.RECORDED_SUITES.split(',').contains(targetName)
}
