from conftest import CONTRACT
import json


DOCUMENT = 'https://records.example/document'
POLICY = 'https://records.example/policy'
LINES = '\n'.join([
    'PUBLIC: Exhibition opens at noon.',
    "PRIVATE_ADDRESS: The maker's home address is 14 Lantern Row.",
    'PUBLIC: The installation uses recycled glass.',
    'SECRET_TOKEN: Backstage access token is ORBIT-441.',
    'PUBLIC: Admission is free on Friday.',
    'PUBLIC: The closing discussion starts at 18:00.',
])


def opened(vm, deploy, owner):
    vm.strict_mocks = True; vm.check_pickling = True; vm.sender = owner
    contract = deploy(CONTRACT); contract.open_aperture('ap-7', 'Studio release copy', DOCUMENT, POLICY)
    return contract


def sources(vm):
    vm.mock_web(r'/document$', {'status': 200, 'body': LINES})
    vm.mock_web(r'/policy$', {'status': 200, 'body': 'PRIVATE_ADDRESS is PERSONAL category 0. SECRET_TOKEN is SECURITY category 1. PUBLIC lines may be released.'})


def llm(vm, rows=None):
    rows = rows if rows is not None else [{'line_index': 1, 'category': 0}, {'line_index': 3, 'category': 1}]
    vm.mock_llm(r'.*RedactionAperture policy application.*', json.dumps({'rows': rows}))


def test_sensitive_lines_create_exact_release_runs(direct_vm, direct_deploy, direct_alice):
    contract = opened(direct_vm, direct_deploy, direct_alice); sources(direct_vm); llm(direct_vm)
    contract.resolve_aperture('ap-7'); row = contract.get_aperture('ap-7')
    assert row['state'] == 'REDACTED' and row['line_count'] == 6
    assert row['release_runs'] == [[0, 0], [2, 2], [4, 5]] and len(row['digests']) == 2


def test_clear_document_releases_whole_range(direct_vm, direct_deploy, direct_alice):
    contract = opened(direct_vm, direct_deploy, direct_alice); sources(direct_vm); llm(direct_vm, [])
    contract.resolve_aperture('ap-7'); row = contract.get_aperture('ap-7')
    assert row['state'] == 'CLEAR' and row['release_runs'] == [[0, 5]]


def test_validator_rejects_forged_line_attribution(direct_vm, direct_deploy, direct_alice):
    contract = opened(direct_vm, direct_deploy, direct_alice); sources(direct_vm); llm(direct_vm)
    result = contract._classify(contract.apertures['AP-7']); assert direct_vm.run_validator(leader_result=result) is True
    forged = {'line_count': result['line_count'], 'rows': [dict(item) for item in result['rows']], 'digests': list(result['digests'])}
    forged['rows'][0]['line_index'] = 2
    assert direct_vm.run_validator(leader_result=forged) is False


def test_duplicate_id_and_source_rejected(direct_vm, direct_deploy, direct_alice):
    contract = opened(direct_vm, direct_deploy, direct_alice)
    with direct_vm.expect_revert('unique aperture id'):
        contract.open_aperture('ap-7', 'Duplicate record', DOCUMENT, POLICY)
    with direct_vm.expect_revert('distinct document and policy'):
        contract.open_aperture('ap-8', 'Same source record', DOCUMENT, DOCUMENT)


def test_malformed_output_is_rejected(direct_vm, direct_deploy, direct_alice):
    contract = opened(direct_vm, direct_deploy, direct_alice); sources(direct_vm)
    llm(direct_vm, [{'line_index': 1, 'category': 0}, {'line_index': 1, 'category': 1}])
    with direct_vm.expect_revert('unique bounded redaction row'):
        contract.resolve_aperture('ap-7')


def test_cancel_authorization_and_terminal_replay(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = opened(direct_vm, direct_deploy, direct_alice); direct_vm.sender = direct_bob
    with direct_vm.expect_revert('owner of open aperture'):
        contract.cancel_open('ap-7')
    direct_vm.sender = direct_alice; sources(direct_vm); llm(direct_vm); contract.resolve_aperture('ap-7')
    with direct_vm.expect_revert('open aperture required'):
        contract.resolve_aperture('ap-7')
