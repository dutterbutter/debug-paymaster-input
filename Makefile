PRIVATE_KEY := <PRIVATE_KEY>
PAYMASTER_ADDRESS := 0xE06BBF12Cc8140d23504080eC28f3d8163994bef
ERC20Mock_ADDRESS := 0xde639613B521449Ddc5448e61D0609F8a8e8e77f
VAULT_ADDRESS := 0xe363A7B7aFCef3F1C86C5D047EbbEF7650b92c4A

.PHONY: deploy-paymaster mint-tokens fund-paymaster deploy-vault all

# Deploy the Paymaster
deploy-paymaster:
	forge script script/PaymasterScript.s.sol:DeployPaymasterScript \
		--rpc-url anvil-zksync \
		--broadcast \
		-vvvv --slow

# Mint ERC20Mock tokens from create2 deployment to the Paymaster
# Note: This is done in the deploy-paymaster script as well
mint-tokens:
	cast send $(ERC20Mock_ADDRESS) "mint(address,uint256)" \
		$(PAYMASTER_ADDRESS) 10000000000000000000000000 \
		--rpc-url anvil-zksync \
		--private-key $(PRIVATE_KEY)

# Fund the Paymaster
# Note: This is done in the deploy-paymaster script as well
fund-paymaster:
	cast send $(PAYMASTER_ADDRESS) \
		--value 2ether \
		--rpc-url anvil-zksync \
		--private-key $(PRIVATE_KEY)

# Deploy the Sponsorship Vault
deploy-vault:
	forge script script/SponsorshipVaultScript.s.sol:SponsorshipVaultScript \
		--rpc-url anvil-zksync \
		--broadcast \
		-vvvv --slow

# Set the Vault address in the Paymaster
# Note: This is done in the deploy-paymaster script as well
set-vault: 
	cast send $(PAYMASTER_ADDRESS) \
		"setVault(address)" $(VAULT_ADDRESS) \
		 --rpc-url anvil-zksync --gas-limit 2100000 --private-key $(PRIVATE_KEY)

# Run all steps in order
all: deploy-paymaster mint-tokens fund-paymaster deploy-vault set-vault
