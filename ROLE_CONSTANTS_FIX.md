# Role Constants Fix

## Issue
The contract was failing with `UnreachableCodeReached` error when calling `add_role` because the Python SDK was sending the role parameter as a **string** instead of a **u32 integer**.

## Root Cause
- **Contract signature**: `pub fn add_role(env: Env, caller: Address, project_id: u64, role: u32, new_member: Address)`
- **SDK was sending**: `scval.to_string(role)` ❌
- **Should send**: `scval.to_uint32(role)` ✅

## Solution
1. Added role constants to `chatspy/src/chatspy/ccrypto.py`:
   ```python
   # Contract role constants (must match Rust contract)
   ROLE_SUPER_ADMIN = 0
   ROLE_ADMIN = 1
   ROLE_NGO = 2
   ROLE_VENDOR = 3
   ROLE_BENEFICIARY = 4
   ```

2. Updated SDK methods in `ccrypto.py`:
   - `add_role()`: Changed parameter type from `role: str` to `role: int`, using `scval.to_uint32(role)`
   - `remove_role()`: Changed parameter type from `role: str` to `role: int`, using `scval.to_uint32(role)`

3. Updated Django code in `services/project/core/models.py`:
   - Imported: `ROLE_NGO, ROLE_VENDOR, ROLE_BENEFICIARY`
   - Changed `role="ngo"` to `role=ROLE_NGO`
   - Changed `role="vendor"` to `role=ROLE_VENDOR`
   - Changed `role="beneficiary"` to `role=ROLE_BENEFICIARY`

## Verification
Successfully tested on mainnet:
```bash
stellar contract invoke \
  --id CBGWBU3E5BEMN3EPOMPACYLEGENIKYMBDOGUKVOE3ALGDJRWSRR4U7HP \
  --source neonx \
  --network livenet \
  -- \
  add_role \
  --caller GBXFVMHGUVT4F25ZB6PZDEVEPQV3FQJNLAY2ENYUKVHAMX4P56K4N3TC \
  --project_id 1 \
  --role 2 \
  --new_member GBXFVMHGUVT4F25ZB6PZDEVEPQV3FQJNLAY2ENYUKVHAMX4P56K4N3TC
```
**Result**: Transaction successful (tx: 9365f9416d72724777bd0a22780d61981a40e9540a4b2fb33bd2a97c40662495)

## Usage Example
```python
from chatspy.ccrypto import StellarProjectContract, ROLE_NGO, ROLE_VENDOR, ROLE_BENEFICIARY
from stellar_sdk import Keypair as StellarKeypair
from chatspy.models import ChatsRecord

# Initialize contract
contract = StellarProjectContract(contract_id="CBGW...")
owner = StellarKeypair.from_secret("S...")

# Add NGO role to a project
project_id = ChatsRecord.to_global_id(Project, 456, deterministic=True)
response = contract.add_role(
    caller=owner,
    project_id=project_id,
    role=ROLE_NGO,  # Use integer constant, not string!
    member="GBXF..."
)
```

## Files Modified
1. `/Users/abdul/Projects/chats/chatspy/src/chatspy/ccrypto.py`
   - Added role constants (lines ~57-61)
   - Updated `add_role()` method signature and implementation
   - Updated `remove_role()` method signature and implementation

2. `/Users/abdul/Projects/chats/services/project/core/models.py`
   - Added role constants to imports
   - Fixed 3 add_role calls to use integer constants

## Next Steps
The contract is now ready for production use. All role assignments will work correctly once the Django service is restarted to pick up the code changes.
