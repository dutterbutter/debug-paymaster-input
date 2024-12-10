## debugging only

### Step 1: Start `anvil-zksync`
Run the following command to start `anvil-zksync` with:

```bash
./target/release/anvil-zksync --show-calls=all --resolve-hashes=true fork --fork-url sepolia-testnet
```

### Step 2: Deploy the Paymaster
Use the following command to deploy the Paymaster contract:

```bash
make deploy-paymaster
```

### Step 3: Deploy the Sponsorship Vault
To deploy the Sponsorship Vault contract, run:

```bash
make deploy-vault
```

Then test against provided go / npm tests. 