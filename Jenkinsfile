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
            description: 'Run all manifest-approved suites or select one approved suite'
        )
    }

    environment {
        WEBEX_TOKEN = credentials('ANSIBLE_WEBEX_TOKEN')
        WEBEX_ROOM_ID = "61f7d4c0-9566-11f0-b070-451eba08616c" // private test space
        ND_USER = credentials('ANSIBLE_NDFC_USERNAME')
        ND_PASSWORD = credentials('ANSIBLE_NDFC_41_117_PASSWORD')
        ANSIBLE_HOST = "10.122.84.112"
        ND_SWITCH_IP = '10.122.84.71'
        BASE_DIR = "$HOME/ansible"
        COLLECTIONS_DIR = "$HOME/ansible/collections/ansible_collections/cisco/nd"
        COLL_DIR = "$HOME/ansible/collections/ansible_collections/cisco"
        CONSUL_URL = "http://10.78.210.155:8500"
        CONSUL_PREFIX = "ansible/nd4x-nightly"
        ND_BRANCH = 'develop'
        FABRIC = 'VXLAN_Fabric'
        PIPELINE_FAILED = 'false'
        TEST_RESULT_SUMMARY = ''
        BUILD_FAILURE_REASON = ''
        TOTAL_PASSED_COUNT = '0'
        TOTAL_FAILED_COUNT = '0'
        CURRENT_ND_INVENTORY = ''
    }

    triggers {
        cron('TZ=Asia/Kolkata\n0 2 * * *')
    }

    options {
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
                set -e
                cd ${BASE_DIR}
                export PATH=${BASE_DIR}:$PATH

                # Create or verify the Python virtual environment.
                if [ -d "$HOME/ansible/venv" ]; then
                    VENV_PYTHON=$($HOME/ansible/venv/bin/python --version 2>&1 | awk '{print $2}')
                    if [[ "$VENV_PYTHON" != 3.12.* ]]; then
                        echo "Python version mismatch, recreating venv..."
                        rm -rf $HOME/ansible/venv
                        python3.12 -m venv $HOME/ansible/venv
                    fi
                else
                    echo "Creating venv with Python 3.12.3..."
                    python3.12 -m venv $HOME/ansible/venv
                fi

                source $HOME/ansible/venv/bin/activate
                echo "Python: $(python --version)"
                '''
            }
        }

        stage('Clone Repository') {
            steps {
                sh '''#!/bin/bash
                set -e
                cd ${COLL_DIR}

                if [ -d "nd/.git" ]; then
                    cd nd
                    LOCAL_COMMIT=$(git rev-parse HEAD)
                    REMOTE_COMMIT=$(git ls-remote https://github.com/CiscoDevNet/ansible-nd.git refs/heads/${ND_BRANCH} | awk '{print $1}')

                    if [ "${LOCAL_COMMIT}" == "${REMOTE_COMMIT}" ]; then
                        echo "Repository is up-to-date"
                        exit 0
                    fi
                    cd ${COLL_DIR}
                    rm -rf nd
                fi

                git clone -b ${ND_BRANCH} https://github.com/CiscoDevNet/ansible-nd.git nd
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

                        // Derive wrapper names from the reviewed manifest.
                        def manifest = readYaml file: 'nd_suite_manifest.yaml'

                        if (!manifest?.suites) {
                            error('Downloaded manifest contains no suites')
                        }

                        manifest.suites.keySet().each { suiteName ->
                            def safeSuiteName = suiteName.toString()

                            if (!(safeSuiteName ==~ /nd_[a-z0-9_]+/)) {
                                error("Unsafe suite name in manifest: ${safeSuiteName}")
                            }

                            downloadFromConsul("${safeSuiteName}.yaml")
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

                    def message = "ND Nightly Build ${BUILD_NUMBER}\n"
                    message += "Result: ${currentBuild.currentResult}\n"
                    message += "Total Passed: ${env.TOTAL_PASSED_COUNT ?: '0'}\n"
                    message += "Total Failed: ${env.TOTAL_FAILED_COUNT ?: '0'}\n"
                    message += "\nDetailed Results:\n${env.TEST_RESULT_SUMMARY ?: 'No results'}\n"
                    message += "Link: ${BUILD_URL}console\n"

                    def safeMessage = message.replace('"', '\\"')

                    withEnv(["SAFE_MESSAGE=${safeMessage}"]) {
                        sh returnStatus: true, script: '''#!/bin/bash
                            set +e
                            curl -s -X POST https://webexapis.com/v1/messages \
                                -H "Authorization: Bearer ${WEBEX_TOKEN}" \
                                -H "Content-Type: application/json" \
                                -d "{\"roomId\": \"${WEBEX_ROOM_ID}\", \"text\": \"${SAFE_MESSAGE}\"}"
                            '''
                    }
                } catch (Exception e) {
                    echo "Webex notification failed: ${e.getMessage()}"
                }
            }
        }
    }
}

def downloadFromConsul(fileName, localFileName = null) {
    if (!(fileName ==~ /[A-Za-z0-9._-]+/)) {
        error("Unsafe Consul filename: ${fileName}")
    }

    def targetFileName = localFileName ?: fileName
    def consulUrl =
        "${env.CONSUL_URL}/v1/kv/${env.CONSUL_PREFIX}/${fileName}?raw"

    echo "Downloading ${fileName} from Consul prefix ${env.CONSUL_PREFIX}"

    def response = httpRequest(
        url: consulUrl,
        httpMode: 'GET',
        validResponseCodes: '200',
        consoleLogResponseBody: false
    )

    writeFile(
        file: targetFileName,
        text: response.content
    )

    echo "Downloaded ${fileName}"
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

    def manifest
    dir(env.COLLECTIONS_DIR) {
        manifest = readYaml file: 'nd_suite_manifest.yaml'
    }

    if (manifest.schema_version != 1) {
        error("Unsupported manifest schema_version: ${manifest.schema_version}")
    }

    if (!manifest.suites) {
        error('nd_suite_manifest.yaml contains no suites')
    }

    def approvedSuites = manifest.suites.findAll { suiteName, suiteConfig ->
        suiteConfig.local_status == 'passed'
    }

    def selectedSuites
    if (params.TARGET_SET == 'both') {
        selectedSuites = approvedSuites
    } else {
        def requestedSuite = params.TARGET_SET
        def requestedConfig = manifest.suites[requestedSuite]

        if (!requestedConfig) {
            error("Suite is not present in the manifest: ${requestedSuite}")
        }

        if (requestedConfig.local_status != 'passed') {
            error(
                "Suite ${requestedSuite} is not approved: " +
                "local_status=${requestedConfig.local_status}"
            )
        }

        selectedSuites = [(requestedSuite): requestedConfig]
    }

    if (!selectedSuites) {
        error('No manifest-approved suites were selected')
    }

    env.TOTAL_PASSED_COUNT = '0'
    env.TOTAL_FAILED_COUNT = '0'
    env.TEST_RESULT_SUMMARY = ''

    def suiteFailures = []

    selectedSuites.each { suiteName, suiteConfig ->
        try {
            validateSuiteConfiguration(suiteName, suiteConfig)
            runSuiteWithVerification(ndConfig, suiteName, suiteConfig)
        } catch (Exception suiteError) {
            env.PIPELINE_FAILED = 'true'
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
        parseTestResults(ndConfig, suiteName, outputFile)
        def timestamp = new Date().format('yyyyMMdd_HHmmss')
        def artifactName = "test_output_${suiteName}_${timestamp}.txt"
        sh "cp '${outputFile}' '${env.WORKSPACE}/${artifactName}'"
        archiveArtifacts artifacts: artifactName, allowEmptyArchive: true
        sh "rm -f '${env.WORKSPACE}/${artifactName}'"
    } else {
        failureMessages << 'no output file was produced'
        env.PIPELINE_FAILED = 'true'
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


def parseTestResults(ndConfig, targetName, outputFile) {
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

    // Parse PLAY RECAP lines for ok= and failed= counts
    def okCount = 0
    def failedCount = 0

    output.split('\n').each { line ->
        if (line.contains('ok=')) {
            def idx = line.indexOf('ok=')
            def after = line.substring(idx + 3)
            def end = after.indexOf(' ')
            def val = (end > 0 ? after.substring(0, end) : after).replaceAll('[^0-9]', '')
            if (val) okCount += val as Integer
        }
        if (line.contains('failed=')) {
            def idx = line.indexOf('failed=')
            def after = line.substring(idx + 7)
            def end = after.indexOf(' ')
            def val = (end > 0 ? after.substring(0, end) : after).replaceAll('[^0-9]', '')
            if (val) failedCount += val as Integer
        }
    }

    // Accumulate into global counters
    env.TOTAL_PASSED_COUNT = ((env.TOTAL_PASSED_COUNT as Integer) + okCount).toString()
    env.TOTAL_FAILED_COUNT = ((env.TOTAL_FAILED_COUNT as Integer) + failedCount).toString()
    env.TEST_RESULT_SUMMARY += "\nTarget: ${targetName} | Passed: ${okCount} | Failed: ${failedCount} | Duration: ${durationStr}"

    if (failedCount > 0) {
        env.PIPELINE_FAILED = 'true'
        echo "Failures detected in ${targetName}: ${failedCount} tasks failed"
    }
}
