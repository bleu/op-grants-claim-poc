// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import "@openzeppelin/contracts/finance/VestingWallet.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract VestingWalletWithDelegation is VestingWallet, ReentrancyGuard {
    using SafeERC20 for ERC20Votes;

    ERC20Votes public immutable governanceToken;
    address public immutable grantsManager;
    address public delegatee;
    address public beneficiary;

    event DelegationChanged(
        address indexed previousDelegatee,
        address indexed newDelegatee
    );
    event FundsRevoked(uint256 amount);

    constructor(
        address beneficiaryAddress,
        uint64 startTimestamp,
        address tokenAddress,
        address _grantsManager
    ) VestingWallet(beneficiaryAddress, startTimestamp, 0) {
        require(tokenAddress != address(0), "Token address is zero address");
        require(_grantsManager != address(0), "Grants manager is zero address");

        governanceToken = ERC20Votes(tokenAddress);
        grantsManager = _grantsManager;
        beneficiary = beneficiaryAddress;
    }

    function delegate(address newDelegatee) external {
        require(tx.origin == beneficiary, "Only beneficiary can delegate");
        address oldDelegatee = delegatee;
        delegatee = newDelegatee;
        governanceToken.delegate(newDelegatee);
        emit DelegationChanged(oldDelegatee, newDelegatee);
    }

    function release() public override(VestingWallet) nonReentrant {
        require(
            governanceToken.delegates(beneficiary) == delegatee,
            "Delegatee has not been delegated by beneficiary"
        );

        uint256 releasable = vestedAmount(uint64(block.timestamp)) - released();
        uint256 balance = governanceToken.balanceOf(address(this));
        require(releasable <= balance, "Insufficient balance");
        _release(releasable);
        if (delegatee != address(0)) {
            governanceToken.delegate(delegatee);
        }
    }

    function _release(uint256 amount) internal virtual {
        if (amount > 0) {
            governanceToken.safeTransfer(beneficiary, amount);
            emit ERC20Released(address(governanceToken), amount);
        }
    }

    function revoke() external nonReentrant {
        require(msg.sender == grantsManager, "Only grants manager can revoke");

        uint256 balance = governanceToken.balanceOf(address(this));
        if (balance > 0) {
            governanceToken.safeTransfer(grantsManager, balance);
            emit FundsRevoked(balance);
        }
    }

    // Override vestedAmount to return full balance after start time
    function vestedAmount(
        uint64 timestamp
    ) public view override returns (uint256) {
        if (timestamp < start()) {
            return 0;
        }
        return governanceToken.balanceOf(address(this));
    }

    function released() public view virtual override returns (uint256) {
        return released(address(governanceToken));
    }

    function start() public view override returns (uint256) {
        return super.start();
    }
}
