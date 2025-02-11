// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

library Errors {
    /*//////////////////////////////////////////////////////////////
                              PAYMASTER
    //////////////////////////////////////////////////////////////*/

    error NotFromBootloader();
    error ShortPaymasterInput();
    error UnsupportedPaymasterFlow();
    error TransactionExpired();
    error InvalidAddress();
    error InvalidMarkup();
    error InvalidNonce();
    error InvalidRatio();
    error AllowanceTooLow();
    error FailedTransferToBootloader();
    error FailedTransfer();
    error ArraysLengthMismatch();

    /*//////////////////////////////////////////////////////////////
                              VAULT
    //////////////////////////////////////////////////////////////*/
    error FailedTransferToPaymaster();
    error FailedWithdrawal();
    error NotEnoughFunds();
    error NotFromPaymaster();
}
