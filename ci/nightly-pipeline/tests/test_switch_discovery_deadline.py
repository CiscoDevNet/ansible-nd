"""Discovery deadline, batching and existing HTTPAPI adapter checks; no ND calls."""
import importlib.util
from pathlib import Path
import signal
import time
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def plugin(tmp_path, monkeypatch):
    monkeypatch.setenv('ANSIBLE_LOCAL_TEMP', str(tmp_path / 'ansible-tmp'))
    spec = importlib.util.spec_from_file_location('fixture_discovery_action',
        ROOT / 'playbooks/action_plugins/nd_switch_discovery.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def seeds(count=2):
    return [{'seed_ip': '192.0.2.' + str(10 + index), 'serial': 'SERIAL' + str(index),
             'fabric': 'fixture/fabric?'} for index in range(count)]


def response(expected, batch, status='ok'):
    return {'status': 200, 'current': {'switches': [
        {'ip': ip, 'serialNumber': next(row['serial'] for row in expected if row['seed_ip'] == ip),
         'status': status} for ip in batch]}}


class Clock:
    def __init__(self):
        self.value = 0.0
        self.sleeps = []

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


def test_batching_and_sha_fallback_only_probe_pending_seeds(plugin):
    expected, calls = seeds(), []

    def request(fabric, batch, protocol, limit):
        calls.append((fabric, batch, protocol))
        result = response(expected, batch)
        if protocol == 'md5':
            result['current']['switches'][0]['status'] = 'notAuthorized'
        return result

    result = plugin.DiscoveryGate(expected, ['md5', 'sha'], request).run()
    assert result['discovery_status'] == 'READY'
    assert calls == [('fixture/fabric?', ['192.0.2.10', '192.0.2.11'], 'md5'),
                     ('fixture/fabric?', ['192.0.2.10'], 'sha')]
    assert result['protocol_by_seed'] == {'192.0.2.11': 'md5', '192.0.2.10': 'sha'}


def test_null_identity_fields_remain_pending_until_a_positive_discovery(plugin):
    calls = []

    def request(fabric, batch, protocol, limit):
        calls.append(protocol)
        result = response(seeds(), batch)
        if len(calls) == 1:
            for row in result['current']['switches']:
                row.update(serialNumber=None, status='notReachable')
        return result

    result = plugin.DiscoveryGate(seeds(), ['md5', 'sha'], request).run()
    assert result['discovery_status'] == 'READY'
    assert calls == ['md5', 'sha']


def test_deadline_counts_api_time_and_truncates_the_last_sleep(plugin):
    clock, calls = Clock(), []

    def request(fabric, batch, protocol, limit):
        calls.append(limit)
        clock.value += 0.04
        return response(seeds(), batch, 'notReachable')

    result = plugin.DiscoveryGate(seeds(), ['md5', 'sha'], request, timeout_seconds=0.11,
                                  interval_seconds=1, clock=clock.now, sleep=clock.sleep).run()
    assert result['discovery_status'] == 'DEADLINE_EXCEEDED'
    assert result['discovery_seconds'] == pytest.approx(0.11)
    assert calls == pytest.approx([0.11, 0.07])
    assert clock.sleeps == pytest.approx([0.03])


def test_a_positive_classification_after_the_deadline_is_never_ready(plugin):
    clock = Clock()

    class LateGate(plugin.DiscoveryGate):
        def classify(self, *args):
            result = super().classify(*args)
            clock.value += 0.11
            return result

    result = LateGate(seeds(), ['md5'], lambda fabric, batch, *args: response(seeds(), batch),
                      timeout_seconds=0.1, clock=clock.now, sleep=clock.sleep).run()
    assert result['discovery_status'] == 'DEADLINE_EXCEEDED' and result['failed']


def test_default_deadline_replaces_the_old_32_cycle_limit(plugin):
    clock, calls = Clock(), []

    def request(fabric, batch, protocol, limit):
        calls.append(protocol)
        clock.value += 0.01
        result = response(seeds(), batch)
        if len(calls) < 70:
            for row in result['current']['switches']:
                row['serialNumber'] = ''
        return result

    result = plugin.DiscoveryGate(seeds(), ['md5', 'sha'], request, timeout_seconds=100,
                                  interval_seconds=1, clock=clock.now, sleep=clock.sleep).run()
    assert result['discovery_status'] == 'READY' and len(calls) == 70


def test_permanent_failure_stops_after_the_last_protocol_before_unrelated_work(plugin):
    expected, calls = seeds(), []
    expected[1]['fabric'] = 'later-fabric'

    def request(fabric, batch, protocol, limit):
        calls.append((fabric, protocol))
        return response(expected, batch, 'notManageable' if batch == ['192.0.2.10'] else 'notReachable')

    result = plugin.DiscoveryGate(expected, ['md5', 'sha'], request).run()
    assert result['discovery_status'] == 'PERMANENT_DISCOVERY_FAILURE'
    assert calls == [('fixture/fabric?', 'md5'), ('later-fabric', 'md5'), ('fixture/fabric?', 'sha')]


@pytest.mark.parametrize('status', [400, 404, 422])
def test_non_authentication_4xx_is_terminal(plugin, status):
    result = plugin.DiscoveryGate(seeds(), ['md5', 'sha'],
        lambda *args: {'failed': True, 'status': status}).run()
    assert result['discovery_status'] == 'API_REJECTED' and result['discovery_batches'] == 1


@pytest.mark.parametrize('status', [408, 421, 425, 429])
def test_collection_defined_transient_statuses_can_recover_within_the_deadline(plugin, status):
    calls = []

    def request(fabric, batch, protocol, limit):
        calls.append(protocol)
        return {'failed': True, 'status': status} if len(calls) == 1 else response(seeds(), batch)

    result = plugin.DiscoveryGate(seeds(), ['md5', 'sha'], request).run()
    assert result['discovery_status'] == 'READY' and calls == ['md5', 'sha']


def test_arbitrary_controller_status_text_is_not_copied_to_diagnostics(plugin):
    result = plugin.DiscoveryGate(seeds(), ['md5'],
        lambda fabric, batch, *args: response(seeds(), batch, 'secret-controller-text')).run()
    assert result['discovery_status'] == 'UNSUPPORTED_STATUS'
    assert 'secret-controller-text' not in str(result)


@pytest.mark.parametrize('name,value', [('timeout_seconds', float('nan')),
                                      ('call_timeout_seconds', float('inf')),
                                      ('interval_seconds', float('nan'))])
def test_nonfinite_budgets_cannot_disable_the_deadline(plugin, name, value):
    with pytest.raises(ValueError):
        plugin.DiscoveryGate(seeds(), ['md5'], lambda *args: {}, **{name: value})


def test_time_limit_never_exceeds_fifteen_minutes(plugin):
    gate = plugin.DiscoveryGate(seeds(), ['md5'], lambda *args: {}, timeout_seconds=9999)
    assert gate.timeout == 900


def test_unknown_failure_and_inherited_alarm_escape_the_gate(plugin):
    class Sentinel(Exception):
        pass

    original_handler = signal.getsignal(signal.SIGALRM)
    original_timer = signal.getitimer(signal.ITIMER_REAL)
    try:
        def prior_handler(signum, frame):
            raise Sentinel('earlier alarm')

        def request(*args):
            with plugin.bounded_call(0.2):
                time.sleep(1)

        signal.signal(signal.SIGALRM, prior_handler)
        signal.setitimer(signal.ITIMER_REAL, 0.02)
        with pytest.raises(Sentinel):
            plugin.DiscoveryGate(seeds(), ['md5'], request).run()
        assert signal.getsignal(signal.SIGALRM) is prior_handler
        assert signal.getitimer(signal.ITIMER_REAL)[0] == 0
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, original_handler)
        signal.setitimer(signal.ITIMER_REAL, *original_timer)


def action(plugin, monkeypatch, execute, args=None, restore_slow=False):
    monkeypatch.setattr(plugin.ActionBase, 'run', lambda *a, **kw: {})
    events = []

    class Options:
        _socket_path = 'fake-existing-httpapi.sock'

        def get_option(self, name):
            return 30

        def set_option(self, name, value):
            events.append(('local', value))

    class RPC(Options):
        def set_option(self, name, value):
            events.append(('server', value))
            if restore_slow and value == 30:
                time.sleep(1)

    monkeypatch.setattr(plugin, 'Connection', lambda path: RPC())
    instance = object.__new__(plugin.ActionModule)
    instance._task = SimpleNamespace(no_log=False, args=args or {'seeds': seeds(), 'protocols': ['md5']})
    instance._connection = Options()
    instance._templar = SimpleNamespace(template=lambda value: value)

    def child(**kwargs):
        assert instance._task.no_log is True
        assert kwargs['module_name'] == 'cisco.nd.nd_rest'
        assert kwargs['module_args']['path'].endswith('/fixture%2Ffabric%3F/actions/shallowDiscovery')
        assert kwargs['task_vars']['existing_connection_context'] is True
        return execute(kwargs)

    instance._execute_module = child
    result = instance.run(task_vars={'nd_switch_username': 'fixture-user', 'nd_switch_password': 'fixture-password',
                                     'existing_connection_context': True})
    assert instance._task.no_log is False
    assert 'fixture-password' not in str(result)
    return result, events


def test_adapter_reuses_nd_rest_and_bounds_and_restores_existing_httpapi_options(plugin, monkeypatch):
    result, events = action(plugin, monkeypatch, lambda kwargs: response(seeds(), kwargs['module_args']['content']['seedIpCollection']))
    assert result['discovery_status'] == 'READY'
    assert events[0][0] == 'server' and 1 <= events[0][1] <= 60
    assert events[1] == ('local', events[0][1])
    assert events[2:] == [('server', 30), ('local', 30)]


def test_slow_option_restoration_cannot_escape_the_phase_deadline(plugin, monkeypatch):
    started = time.monotonic()
    result, events = action(plugin, monkeypatch,
        lambda kwargs: response(seeds(), kwargs['module_args']['content']['seedIpCollection']),
        args={'seeds': seeds(), 'protocols': ['md5'], 'timeout_seconds': 0.1,
              'call_timeout_seconds': 0.05, 'interval_seconds': 0}, restore_slow=True)
    assert result['discovery_status'] == 'DEADLINE_EXCEEDED'
    assert result['discovery_seconds'] < 0.3 and time.monotonic() - started < 0.5


def test_whole_gate_alarm_bounds_classification_work_too(plugin, monkeypatch):
    original = plugin.DiscoveryGate.classify

    def slow_classify(self, *args):
        time.sleep(1)
        return original(self, *args)

    monkeypatch.setattr(plugin.DiscoveryGate, 'classify', slow_classify)
    result, events = action(plugin, monkeypatch,
        lambda kwargs: response(seeds(), kwargs['module_args']['content']['seedIpCollection']),
        args={'seeds': seeds(), 'protocols': ['md5'], 'timeout_seconds': 0.1})
    assert result['discovery_status'] == 'DEADLINE_EXCEEDED'
    assert result['discovery_seconds'] < 0.3


def test_inherited_alarm_is_not_masked_by_adapter_cleanup_rpc(plugin, monkeypatch):
    class Sentinel(Exception):
        pass

    original_handler = signal.getsignal(signal.SIGALRM)
    original_timer = signal.getitimer(signal.ITIMER_REAL)
    try:
        def prior_handler(signum, frame):
            raise Sentinel('earlier alarm')

        signal.signal(signal.SIGALRM, prior_handler)
        signal.setitimer(signal.ITIMER_REAL, 0.02)
        with pytest.raises(Sentinel):
            action(plugin, monkeypatch, lambda kwargs: time.sleep(1), restore_slow=True)
        assert signal.getsignal(signal.SIGALRM) is prior_handler
        assert signal.getitimer(signal.ITIMER_REAL)[0] == 0
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, original_handler)
        signal.setitimer(signal.ITIMER_REAL, *original_timer)
