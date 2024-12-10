// SPDX-License-Identifier: GPL-3.0

//        @@@@%%%%%%%@@@
//      @@@%%%%%%%%%%%%@@@             @%%%%%%%%%%@@                 @@@  @@
//    @@%%%%%%%%%%%%%%%%%%@@          @%%%%%%%%%%@@               @@@%%@@%%@@
//   @@%%%%%%%@@  @%%%%%%%%@@                  @%@@               @%@     @@
//  @@%%%%%%@@@    @@%%%%%%%@@               @@%@@                @%@
//  @%%%%%@@@        @@%%%%%%@              @@@@   @%@@       @@%%@%@%%@@@%@@
//  @%%%%@@            @%%%%%@             @@@@     @@@@     @@%@@@%@@@@ @%@@
//  @%%%%%%%%%@@    @%%%%%%%%@            @@@@      @@%@     @%@@ @%@    @%@@
//  @@%%%%%%%%%%@   @%%%%%%%%@           @@@@        @@@@   @@@@  @%@    @%@@
//   @%%%%%%%@@%%@@ @%%%%%%%@@          @@@@          @@@@ @@@@   @%@    @%@@
//   @@%%%%%%@@@%@@@@%%%%%%@@          @@@@            @@@@@@@    @%@    @%@@
//     @%%%%%@ @@%%%@%%%%%@           @%@@@@@@@@@@@     @%%%@     @%@    @%@@
//      @@@@%@   @@%%%@@@@           @@@@@@@@@@@@@@     @@@@      @@@    @@@@
//         @@@    @@@@@                                 @@@@
//                                                     @@@@
//                                                    @@%@

pragma solidity ^0.8.19;

import {IPaymaster, ExecutionResult, PAYMASTER_VALIDATION_SUCCESS_MAGIC} from "lib/era-contracts/system-contracts/contracts/interfaces/IPaymaster.sol";
import {IPaymasterFlow} from "lib/era-contracts/system-contracts/contracts/interfaces/IPaymasterFlow.sol";
import {TransactionHelper, Transaction} from "lib/era-contracts/system-contracts/contracts/libraries/TransactionHelper.sol";
import "lib/era-contracts/system-contracts/contracts/Constants.sol";
import "forge-std/console.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Errors} from "./libraries/Errors.sol";
import {ISponsorshipVault} from "./interfaces/ISponsorshipVault.sol";

contract ERC20SponsorPaymaster is IPaymaster, Ownable {
    using ECDSA for bytes32;
    // Using OpenZeppelin's SafeERC20 library to perform token transfers
    using SafeERC20 for IERC20;

    // Used to identify the contract version
    string public constant version = "1.0";

    // The nominator used for markup calculations
    uint256 constant MARKUP_NOMINATOR = 1e4;
    // The nominator used for calculating the sponsorship ratio
    uint256 constant SPONSORSHIP_RATIO_NOMINATOR = 1e4;

    // Use this if no specific markup is set for a protocol. 1e4 = no markup
    uint256 public defaultMarkup;

    // Protocol address -> markup
    mapping(address => uint256) private markups;

    // Public address of the Zyfi signer
    address public verifier;

    // Address of the SponsorshipVault
    address public vault;

    event VerifierChanged(address indexed newVerifier);
    event VaultChanged(address indexed newVault);
    event DefaultMarkupChanged(uint256 newMarkup);
    event MarkupChanged(address indexed protocol, uint256 newMarkup);
    event RefundedToken(
        address indexed account,
        address indexed token,
        uint256 amount
    );

    modifier onlyBootloader() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS) {
            revert Errors.NotFromBootloader();
        }
        // Continue execution if called from the bootloader.
        _;
    }

    // Note: set 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 as owner just for quick debugging
    constructor(
        address _verifier
    ) Ownable(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266) {
        if (_verifier == address(0)) revert Errors.InvalidAddress();
        verifier = _verifier;
        // Set the default markup to +0%
        defaultMarkup = 1e4;

        emit VerifierChanged(_verifier);
    }

    function validateAndPayForPaymasterTransaction(
        bytes32 /* _txHash */,
        bytes32 /* _suggestedSignedHash */,
        Transaction calldata _transaction
    )
        external
        payable
        onlyBootloader
        returns (bytes4 magic, bytes memory context)
    {
        // By default we consider the transaction as accepted.
        magic = PAYMASTER_VALIDATION_SUCCESS_MAGIC;

        console.log("validateAndPayForPaymasterTransaction called");
        console.log("Transaction from:", address(uint160(_transaction.from)));
        console.log("Transaction to:", address(uint160(_transaction.to)));
        console.log("Transaction nonce:", _transaction.nonce);
        console.log("Transaction gasLimit:", _transaction.gasLimit);
        console.log("Transaction maxFeePerGas:", _transaction.maxFeePerGas);
        console.log(
            "paymasterInput length:",
            _transaction.paymasterInput.length
        );

        if (_transaction.paymasterInput.length < 4) {
            console.log("Reverting: ShortPaymasterInput");
            revert Errors.ShortPaymasterInput();
        }

        bytes4 paymasterInputSelector = bytes4(
            _transaction.paymasterInput[0:4]
        );
        console.log("paymasterInputSelector");
        console.logBytes4(paymasterInputSelector);

        if (paymasterInputSelector != IPaymasterFlow.approvalBased.selector) {
            console.log("Reverting: UnsupportedPaymasterFlow");
            revert Errors.UnsupportedPaymasterFlow();
        }
        console.log("decoding...");
        console.log("paymaster input [4:]");
        console.logBytes(_transaction.paymasterInput[4:]);
        (address token, uint256 amount, bytes memory data) = abi.decode(
            _transaction.paymasterInput[4:],
            (address, uint256, bytes)
        );

        console.log("Decoded token:", token);
        console.log("Decoded amount:", amount);
        console.log("Decoded extra data length:", data.length);

        (
            uint64 expirationTime,
            uint256 maxNonce,
            address protocolAddress,
            uint16 sponsorshipRatio,
            bytes memory signedMessage
        ) = abi.decode(data, (uint64, uint256, address, uint16, bytes));

        console.log("expirationTime:", expirationTime);
        console.log("maxNonce:", maxNonce);
        console.log("protocolAddress:", protocolAddress);
        console.log("sponsorshipRatio:", sponsorshipRatio);
        console.log("signedMessage length:", signedMessage.length);

        // Validate that the transaction generated by the API is not expired
        if (block.timestamp > expirationTime) {
            console.log(
                "Reverting: TransactionExpired, block.timestamp:",
                block.timestamp
            );
            revert Errors.TransactionExpired();
        }

        // Validate that the nonce is not higher than the maximum allowed
        if (_transaction.nonce > maxNonce) {
            console.log(
                "Reverting: InvalidNonce, nonce:",
                _transaction.nonce,
                "maxNonce:",
                maxNonce
            );
            revert Errors.InvalidNonce();
        }

        address userAddress = address(uint160(_transaction.from));
        console.log("userAddress:", userAddress);

        //Validate that the message was signed by the Zyfi api
        // Note: this will return false for nonce incorrectness
        bool isValidSignature = _isValidSignature(
            signedMessage,
            userAddress,
            address(uint160(_transaction.to)),
            token,
            amount,
            expirationTime,
            maxNonce,
            protocolAddress,
            sponsorshipRatio,
            _transaction.maxFeePerGas,
            _transaction.gasLimit
        );
        console.log("isValidSignature:", isValidSignature);

        if (!isValidSignature) {
            console.log(
                "Invalid signature detected. Setting magic to 0x00000000."
            );
            magic = bytes4(0);
        }

        address thisAddress = address(this);
        console.log("Paymaster address:", thisAddress);

        uint256 requiredETH = _transaction.gasLimit * _transaction.maxFeePerGas;
        console.log("requiredETH:", requiredETH);

        uint256 requiredETHProtocol = 0;
        // If protocol sponsors part of the transaction
        if (protocolAddress != address(0)) {
            if (sponsorshipRatio > 100_00) {
                console.log(
                    "Reverting: InvalidRatio, sponsorshipRatio:",
                    sponsorshipRatio
                );
                revert Errors.InvalidRatio();
            }

            uint256 markup = getMarkup(protocolAddress);
            console.log("protocol markup:", markup);

            requiredETHProtocol =
                (requiredETH * markup * sponsorshipRatio) /
                (MARKUP_NOMINATOR * SPONSORSHIP_RATIO_NOMINATOR);

            console.log("requiredETHProtocol:", requiredETHProtocol);
            ISponsorshipVault(vault).getSponsorship(
                protocolAddress,
                requiredETHProtocol
            );
            console.log("Called getSponsorship on vault.");
        }

        if (amount > 0) {
            uint256 allowance = IERC20(token).allowance(
                userAddress,
                thisAddress
            );
            console.log("User allowance:", allowance);

            if (allowance < amount) {
                console.log(
                    "Reverting: AllowanceTooLow, required:",
                    amount,
                    "actual:",
                    allowance
                );
                revert Errors.AllowanceTooLow();
            }

            IERC20(token).safeTransferFrom(userAddress, thisAddress, amount);
            console.log("Transferred token from user to paymaster.");
        }

        (bool success, ) = payable(BOOTLOADER_FORMAL_ADDRESS).call{
            value: requiredETH
        }("");
        console.log("Transfer ETH to bootloader success:", success);
        if (!success) {
            console.log("Reverting: FailedTransferToBootloader");
            revert Errors.FailedTransferToBootloader();
        }

        context = abi.encode(
            token,
            amount,
            protocolAddress,
            requiredETHProtocol
        );
        console.log("Context encoded.");
        console.log(
            "validateAndPayForPaymasterTransaction completed successfully."
        );

        return (magic, context);
    }

    function postTransaction(
        bytes calldata _context,
        Transaction calldata _transaction,
        bytes32 /* _txHash */,
        bytes32 /* _suggestedSignedHash */,
        ExecutionResult /* _txResult */,
        uint256 _maxRefundedGas
    ) external payable override onlyBootloader {
        (
            address token,
            uint256 amount,
            address protocolAddress,
            uint256 requiredETHProtocol
        ) = abi.decode(_context, (address, uint256, address, uint256));

        // Processes the refund fairly between user and protocol.
        // E.g. If the user paid 60%, he is gets 60% of the refund, the rest is sent to the protocol

        // Refund the protocol if it sponsored the transaction
        if (requiredETHProtocol > 0) {
            // We can do the proportion between _maxRefundedGas and _transaction.gasLimit to calculate the fair refund
            uint256 refundEthProtocol = (requiredETHProtocol *
                _maxRefundedGas) / _transaction.gasLimit;

            ISponsorshipVault(vault).refundSponsorship{
                value: refundEthProtocol
            }(protocolAddress);
        }

        // Refund the user
        if (amount > 0) {
            address userAddress = address(uint160(_transaction.from));

            uint256 refundAmount = (amount * _maxRefundedGas) /
                _transaction.gasLimit;
            IERC20(token).safeTransfer(userAddress, refundAmount);
            emit RefundedToken(userAddress, token, refundAmount);
        }
    }

    /**
     * @notice Checks the validity of the API signature.
     * @param _signature The signature to be validated.
     * @param _from The address of the sender.
     * @param _to The address of the recipient.
     * @param _token The address of the token being transferred.
     * @param _amount The amount of tokens being transferred.
     * @param _expirationTime The expiration time for the transaction.
     * @param _maxNonce The maximum nonce for the transaction.
     * @param _protocolAddress The address of the protocol contract.
     * @param _sponsorshipRatio The sponsorship ratio for the transaction.
     * @param _maxFeePerGas The maximum fee per gas for the transaction.
     * @param _gasLimit The gas limit for the transaction.
     * @return A boolean indicating whether the signature is valid or not.
     */
    function _isValidSignature(
        bytes memory _signature,
        address _from,
        address _to,
        address _token,
        uint256 _amount,
        uint64 _expirationTime,
        uint256 _maxNonce,
        address _protocolAddress,
        uint16 _sponsorshipRatio,
        uint256 _maxFeePerGas,
        uint256 _gasLimit
    ) internal view returns (bool) {
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                _from,
                _to,
                _token,
                _amount,
                _expirationTime,
                _maxNonce,
                _protocolAddress,
                _sponsorshipRatio,
                _maxFeePerGas,
                _gasLimit
            )
        );

        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(
            messageHash
        );

        (
            address recoveredAddress,
            ECDSA.RecoverError error2,
            bytes32 length
        ) = ECDSA.tryRecover(ethSignedMessageHash, _signature);
        if (error2 != ECDSA.RecoverError.NoError) {
            return false;
        }
        return recoveredAddress == verifier;
    }

    /**
     * @notice Retrieves the markup value for a given address.
     * @param _address The address for which to retrieve the markup value.
     * @return The markup value for the given address. If the markup is not set for the address, it returns the default markup value.
     */
    function getMarkup(address _address) public view returns (uint256) {
        uint256 markup = markups[_address];
        // Return default markup if not set
        if (markup == 0) {
            return defaultMarkup;
        }
        return markup;
    }

    // --- ADMIN FUNCTIONS ---

    /**
     * @notice Sets the verifier address.
     * @param _newVerifier The new verifier address.
     */
    function setVerifier(address _newVerifier) external onlyOwner {
        if (_newVerifier == address(0)) revert Errors.InvalidAddress();
        verifier = _newVerifier;
        emit VerifierChanged(_newVerifier);
    }

    /**
     * @notice Sets the address of the vault contract.
     * @param _newVault The address of the new vault contract.
     */
    function setVault(address _newVault) external onlyOwner {
        vault = _newVault;
        emit VaultChanged(_newVault);
    }

    /**
     * @notice Withdraws a specified amount of ETH from the paymaster contract and sends it to the given address.
     * Can only be called by the contract owner.
     * @param to The address to which the ETH will be sent.
     * @param amount The amount of ETH to be withdrawn.
     */
    function withdrawETH(address to, uint256 amount) external onlyOwner {
        _withdrawETH(to, amount);
    }

    /**
     * @dev Withdraws all ETH from the contract and transfers it to the specified address.
     * Can only be called by the contract owner.
     * @param to The address to transfer the ETH to.
     */
    function withdrawAllETH(address to) external onlyOwner {
        _withdrawETH(to, address(this).balance);
    }

    /**
     * @dev Internal function to withdraw ETH from the contract.
     * @param to The address to which the ETH will be transferred.
     * @param amount The amount of ETH to be withdrawn.
     */
    function _withdrawETH(address to, uint256 amount) internal {
        if (to == address(0)) revert Errors.InvalidAddress();
        (bool success, ) = payable(to).call{value: amount}("");
        if (!success) revert Errors.FailedTransfer();
    }

    /**
     * @notice Withdraws ERC20 tokens from the contract.
     * @param token The address of the ERC20 token to withdraw.
     * @param to The address to transfer the tokens to.
     * @param amount The amount of tokens to withdraw.
     */
    function withdrawERC20(
        address to,
        address token,
        uint256 amount
    ) external onlyOwner {
        if (to == address(0)) revert Errors.InvalidAddress();
        IERC20(token).safeTransfer(to, amount);
    }

    /**
     * @notice Withdraws multiple ERC20 tokens to a specified address.
     * @param to The address to which the tokens will be withdrawn.
     * @param tokens An array of ERC20 token addresses.
     * @param amounts An array of corresponding token amounts to be withdrawn.
     * Requirements:
     * - The `to` address must not be the zero address.
     * - The `tokens` and `amounts` arrays must have the same length.
     */
    function withdrawERC20Batch(
        address to,
        address[] calldata tokens,
        uint256[] calldata amounts
    ) external onlyOwner {
        if (to == address(0)) revert Errors.InvalidAddress();

        if (tokens.length != amounts.length)
            revert Errors.ArraysLengthMismatch();

        for (uint i = 0; i < tokens.length; i++) {
            IERC20(tokens[i]).safeTransfer(to, amounts[i]);
        }
    }

    /**
     * @notice Sets the markup for a specific protocol address.
     * @param _address The address for which to set the markup.
     * @param _newMarkup The markup value to set.
     * @dev Allows the markup to be set back to 0, which means the default markup will be used.
     */
    function setMarkup(address _address, uint256 _newMarkup) public onlyOwner {
        // Refuses a markup lower than 50% and higher than 200%
        // Accepts 0 to reset the protocol to using the default markup
        if (_newMarkup != 0 && (_newMarkup < 50_00 || _newMarkup > 200_00))
            revert Errors.InvalidMarkup();
        markups[_address] = _newMarkup;
        emit MarkupChanged(_address, _newMarkup);
    }

    /**
     * @notice Sets the default markup for the paymaster.
     * @param _newMarkup The new default markup value to be set.
     */
    function setDefaultMarkup(uint256 _newMarkup) external onlyOwner {
        // Refuses a markup lower than 50% and higher than 150%
        if (_newMarkup < 50_00 || _newMarkup > 150_00)
            revert Errors.InvalidMarkup();

        defaultMarkup = _newMarkup;
        emit DefaultMarkupChanged(_newMarkup);
    }

    /**
     * @dev The Ownable renounceOwnership function is overridden to prevent a premature call from locking up the contract's ETH or ERC20s balance.
     */
    function renounceOwnership() public override onlyOwner {}

    receive() external payable {}
}
