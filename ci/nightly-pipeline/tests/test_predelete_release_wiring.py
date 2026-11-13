"""Execute runtime download selection without Jenkins, HTTP or switch operations."""
import os
from pathlib import Path
import subprocess

import pytest

from test_five_issue_pipeline_fixes import PRELUDE

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ("Jenkinsfile_nd_jenkins_script", "Jenkinsfile_nd_jenkins_script_temp_switches",
            "Jenkinsfile_nd_jenkins_script_comm_list")


@pytest.mark.parametrize("variant", VARIANTS)
def test_leaf_tor_clearance_release_is_selected(variant):
    source = (ROOT / variant).read_text()
    assert "def SWITCH_LIFECYCLE_CONSUL_PREFIX = 'releases/leaf-tor-forward-force-20261111'" in source
    assert "def CONSUL_PREFLIGHT_FILES = ['nd_ensure_switches.yaml', 'action_plugins/nd_switch_discovery.py']" in source


@pytest.mark.parametrize("variant", VARIANTS)
def test_runtime_downloads_verified_deploy_guard_and_action_as_one_release(variant, tmp_path):
    java = Path(os.environ.get("ND_WEBEX_TEST_JAVA", "/private/tmp/nd-local-groovy-runtime/jdk-21.0.13+9-jre/Contents/Home/bin/java"))
    jar = Path(os.environ.get("ND_WEBEX_TEST_GROOVY", "/private/tmp/nd-groovy-all-2.4.21.jar"))
    if not java.is_file() or not jar.is_file():
        pytest.skip("A local JVM and Groovy jar are required")
    harness = tmp_path / "release.groovy"
    harness.write_text(PRELUDE + r'''
def downloads = []
script.metaClass.downloadFromConsul = { Object key, Object target ->
    downloads.add([key: key.toString(), target: target.toString()])
}
script.prepareRuntimeInputs()
assert script.binding.env.ND_RUNTIME_INPUTS_READY == 'true'
def release = 'releases/leaf-tor-forward-force-20261111/'
def guarded = ['nd_ensure_switches.yaml', 'action_plugins/nd_switch_discovery.py']
assert downloads.findAll { it.key.startsWith(release) }.size() == 2
guarded.each { name ->
    assert downloads.count { it.key == release + name } == 1
    assert downloads.find { it.key == release + name }.target == 'fixture-reports/runtime-inputs/' + name
    assert !downloads.any { it.key == name }
}
assert !downloads.any { it.key.contains('bounded-switch-lifecycle-20261029') }
assert !downloads.any { it.key.contains('predelete-deploy-verified-20261030') }
assert !downloads.any { it.key.contains('predelete-response-compatible-20261030') }
// The release changes switch prerequisites only; authored collection sources are untouched.
assert downloads.every { !it.key.endsWith('.md') && !it.key.endsWith('.doc') }
assert downloads.count { it.key == 'compat_action_plugins/normal.py' } == 1
assert downloads.find { it.key == 'compat_action_plugins/normal.py' }.target == 'fixture-reports/runtime-inputs/compat_action_plugins/normal.py'
println('CHECK_PASSED')
''')
    result = subprocess.run([str(java), "-cp", str(jar), "groovy.ui.GroovyMain",
                             str(harness), str(ROOT / variant)],
                            text=True, capture_output=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "CHECK_PASSED" in result.stdout
