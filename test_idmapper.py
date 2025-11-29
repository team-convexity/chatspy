#!/usr/bin/env python3

from src.chatspy.models import IDMapper, ChatsRecord

def test_idmapper():
    test_cases = [
        ("Project", 1),
        ("Project", 12345),
        ("Project", 2**63 - 1),
    ]
    
    for type_name, numeric_id in test_cases:
        global_id = ChatsRecord.to_global_id(type_name, numeric_id, deterministic=True)
        contract_id = IDMapper.to_contract_id(global_id)
        reconstructed_global_id = IDMapper.from_contract_id(contract_id, type_name)
        
        assert contract_id == numeric_id, f"Failed: {contract_id} != {numeric_id}"
        
        reconstructed_type, reconstructed_id = ChatsRecord.from_global_id(reconstructed_global_id)
        assert reconstructed_id == numeric_id, f"Failed: {reconstructed_id} != {numeric_id}"
        assert reconstructed_type == type_name, f"Failed: {reconstructed_type} != {type_name}"
        
        print(f"✓ {type_name} ID {numeric_id}: {global_id[:20]}... → {contract_id} → {reconstructed_global_id[:20]}...")
    
    print("\n✓ All IDMapper tests passed!")

def test_validation():
    MAX_IDENTIFIER_LENGTH = 6
    
    def validate_identifier(identifier: str, field_name: str):
        if len(identifier) > MAX_IDENTIFIER_LENGTH:
            raise ValueError(f"{field_name} must be {MAX_IDENTIFIER_LENGTH} characters or less, got: {identifier}")
        if not identifier.strip():
            raise ValueError(f"{field_name} cannot be empty")
    
    try:
        validate_identifier("USD", "currency")
        print("✓ Valid currency 'USD' passed")
    except ValueError as e:
        print(f"✗ Unexpected error: {e}")
    
    try:
        validate_identifier("TOOLONG", "currency")
        print("✗ Should have failed for 7-char currency")
    except ValueError as e:
        print(f"✓ Correctly rejected 7-char currency: {e}")
    
    try:
        validate_identifier("ITEM01", "item_id")
        print("✓ Valid item_id 'ITEM01' passed")
    except ValueError as e:
        print(f"✗ Unexpected error: {e}")
    
    try:
        validate_identifier("", "item_id")
        print("✗ Should have failed for empty item_id")
    except ValueError as e:
        print(f"✓ Correctly rejected empty item_id: {e}")
    
    print("\n✓ All validation tests passed!")

if __name__ == "__main__":
    print("Testing IDMapper functionality...\n")
    test_idmapper()
    print("\nTesting validation...\n")
    test_validation()
