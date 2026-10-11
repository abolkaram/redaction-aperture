import json
import re
import time
from pathlib import Path

from genlayer_py import create_account, create_client
from genlayer_py.chains import studionet
from genlayer_py.contracts import actions as contract_actions


def calldata_compat(method=None, args=None, kwargs=None):
    result = {}
    if method is not None:
        result['method'] = method
    if args:
        result['args'] = args
    if kwargs:
        result['kwargs'] = kwargs
    return result


contract_actions.make_calldata_object = calldata_compat
ROOT = Path(__file__).parents[1]
ENV = (ROOT.parents[3] / 'accounts.env').read_text()
DEPLOYMENT = json.loads((ROOT / 'deployment.json').read_text())
ADDRESS = DEPLOYMENT['contractAddress']
COMMIT = DEPLOYMENT['sourceCommit']


def account(number):
    key = re.search(rf'^ACCOUNT_{number}_GENLAYER_PRIVATE_KEY\s*=\s*"?([^"\r\n]+)', ENV, re.M).group(1).strip()
    return create_account(account_private_key=key)


def client(number):
    return create_client(chain=studionet, account=account(number))


def write(number, name, args):
    active = client(number); tx = active.write_contract(address=ADDRESS, function_name=name, args=args)
    print(name + '_tx=' + str(tx), flush=True)
    receipt = active.wait_for_transaction_receipt(transaction_hash=tx, wait_until='finalized', retries=180, interval=5000, full_transaction=True)
    leaders = receipt.get('consensus_data', {}).get('leader_receipt') or []
    leaders = [leaders] if isinstance(leaders, dict) else leaders
    assert receipt.get('result_name') == 'MAJORITY_AGREE'
    assert any(item.get('execution_result') == 'SUCCESS' for item in leaders)
    return str(tx)


base = f'https://raw.githubusercontent.com/abolkaram/redaction-aperture/{COMMIT}/evidence'
aperture_id = 'AP-' + str(int(time.time()))
transactions = {}
transactions['open'] = write(5, 'open_aperture', [aperture_id, 'Studio release copy', base + '/document.md', base + '/policy.md'])
transactions['resolve'] = write(5, 'resolve_aperture', [aperture_id])
state = client(5).read_contract(address=ADDRESS, function_name='get_aperture', args=[aperture_id])
assert state['state'] == 'REDACTED'
assert state['sensitive_rows'] == [{'line_index': 1, 'category': 0}, {'line_index': 3, 'category': 1}]
assert state['release_runs'] == [[0, 0], [2, 2], [4, 5]]
proof = {'apertureId': aperture_id, 'transactions': transactions, 'state': state,
         'disclosure': 'The document and policy are operator-authored technical fixtures.'}
(ROOT / 'evidence' / 'live-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
print(json.dumps(proof, indent=2), flush=True)
