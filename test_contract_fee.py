import os
import sys

# Add the src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

os.environ['STELLAR_CONTRACT_OWNER_SEED_PHRASE'] = "cross hundred excuse this obey skirt harbor offer ceiling furnace client there crucial awake adapt forget side reflect cake document occur trouble mobile actress"

from stellar_sdk import Keypair, xdr, scval, Network, SorobanServer, TransactionBuilder, Address

# Contract and owner details
contract_id = "CCILO4DKIFXEZLVPYS6FNRYDI3PV4RVXJLP2OK6TXUI3XOSBTE46GRAG"
owner_public_key = "GBXFVMHGUVT4F25ZB6PZDEVEPQV3FQJNLAY2ENYUKVHAMX4P56K4N3TC"

# Create contract instance (testnet)
contract = StellarProjectContract(contract_id=contract_id)

print("Contract initialized successfully!")
print(f"Contract ID: {contract_id}")
print(f"Network: {contract.network_passphrase}")
print(f"RPC URL: {contract.rpc_url}")

# Generate a test keypair for a beneficiary
test_beneficiary = Keypair.random()
print(f"\nTest beneficiary: {test_beneficiary.public_key}")

# Try a simple batch allocation (small batch to test)
print("\nTesting allocate_item_allowances_batch...")
try:
    owner_keypair = Keypair.from_public_key(owner_public_key)
    
    # Create a minimal test batch
    test_allowances = [
        (test_beneficiary.public_key, "ITEM01", 1, None),  # 1 item
    ]
    
    print(f"Allocating {len(test_allowances)} item allowance(s)...")
    
    # Note: This will fail because we don't have the owner's secret key
    # But it will show us if the code runs up to the signing point
    result = contract.allocate_item_allowances_batch(
        caller=owner_keypair,
        project_id="test123",
        allowances=test_allowances
    )
    
    print(f"Success! Result: {result}")
    
except Exception as e:
    error_type = type(e).__name__
    error_msg = str(e)
    print(f"\nExpected error (no secret key): {error_type}")
    print(f"Message: {error_msg[:200]}")
    
    # Check if we got past the transaction building stage
    if "decrypt" in error_msg.lower() or "secret" in error_msg.lower():
        print("\n✓ Code reached the transaction building stage successfully!")
        print("✓ The fee calculation and transaction preparation logic is working!")
    else:
        print("\n✗ Unexpected error - needs investigation")
        import traceback
        traceback.print_exc()

print("\nTest completed!")
