// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import {ERC20SponsorPaymaster} from "../src/ERC20SponsorPaymaster.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20Mock} from "../src/ERC20Mock.sol";

/// @notice A Forge script to deploy the ERC20SponsorPaymaster
contract DeployPaymasterScript is Script {
    // retrieved from `0xC530313f1AF0B2B3A41DB2C20D88aF1c93A4f878` paymaster
    address constant VERIFIER_ADDRESS =
        0xa5A40aBBb41Ecb9379fE4E19Fcbc1788B8bFdE59;
    // create2 SponsorshipVault contract address
    address constant VAULT_ADDRESS = 0xe363A7B7aFCef3F1C86C5D047EbbEF7650b92c4A;
    // ERC20Mock contract address
    address constant ERC20_TOKEN_ADDRESS =
        0xde639613B521449Ddc5448e61D0609F8a8e8e77f;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        address deployerAddress = vm.addr(deployerPrivateKey); // Derive deployer address

        vm.startBroadcast(deployerPrivateKey);

        // Deploy the Paymaster
        bytes32 salt = keccak256(abi.encodePacked("1234"));
        ERC20SponsorPaymaster paymaster = new ERC20SponsorPaymaster{salt: salt}(
            VERIFIER_ADDRESS
        );
        require(
            paymaster.owner() == deployerAddress,
            "Deployer is not the owner"
        );
        paymaster.setVault(VAULT_ADDRESS);

        ERC20Mock token = new ERC20Mock{salt: salt}(
            "MockERC20",
            "MockERC20",
            18
        );
        console.log("Deployed ERC20Mock at:", address(token));

        // Mint tokens to the Paymaster
        uint256 mintAmount = 10_000_000 * 10 ** 18;
        IERC20 erc20 = IERC20(address(token));
        (bool success, ) = address(token).call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                address(paymaster),
                mintAmount
            )
        );
        require(success, "Minting tokens to Paymaster failed");

        // Fund the Paymaster with ETH
        address(paymaster).call{value: 2 ether}("");

        console.log("Deployed Paymaster at:", address(paymaster));

        vm.stopBroadcast();
    }

    receive() external payable {}
}
