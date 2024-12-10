// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import {SponsorshipVault} from "../src/SponsorshipVault.sol";

/// @notice A Forge script to deploy the SponsorshipVault
contract SponsorshipVaultScript is Script {
    // create2 address of the Paymaster
    address constant PAYMASTER_ADDRESS =
        0xE06BBF12Cc8140d23504080eC28f3d8163994bef;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Deploy the Paymaster
        bytes32 salt = keccak256(abi.encodePacked("1234"));
        SponsorshipVault vault = new SponsorshipVault{salt: salt}(
            PAYMASTER_ADDRESS
        );

        vm.stopBroadcast();
    }
}
