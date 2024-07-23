// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import "forge-std/Test.sol";
import "../contracts/VestingWalletWithDelegation.sol";
import "./GrantsManagerResolver.t.sol";

contract VestingWalletWithDelegationTest is Test {
    VestingWalletWithDelegation public vestingWallet;
    MockOptimismToken public optimismToken;
    address public beneficiary;
    address public grantsManager;
    uint64 public startTimestamp;

    function setUp() public {
        beneficiary = address(0x1);
        grantsManager = address(0x2);
        startTimestamp = uint64(block.timestamp + 1 days);

        optimismToken = new MockOptimismToken(
            "Optimism Token",
            "OPT",
            1000000 * 10 ** 18
        );
        vestingWallet = new VestingWalletWithDelegation(
            beneficiary,
            startTimestamp,
            address(optimismToken),
            grantsManager
        );

        optimismToken.transfer(address(vestingWallet), 1000 * 10 ** 18);
    }

    function testDelegation() public {
        address newDelegatee = address(0x3);

        vm.prank(beneficiary, beneficiary);
        vestingWallet.delegate(newDelegatee);

        assertEq(vestingWallet.delegatee(), newDelegatee);
        assertEq(optimismToken.delegates(address(vestingWallet)), newDelegatee);
    }

    function testRelease() public {
        // Move time forward to start vesting
        vm.warp(startTimestamp);

        uint256 expectedVested = 1000 * 10 ** 18; // Full amount
        uint256 initialBalance = optimismToken.balanceOf(beneficiary);

        vestingWallet.release();

        uint256 finalBalance = optimismToken.balanceOf(beneficiary);
        assertEq(finalBalance - initialBalance, expectedVested);
    }

    function testReleaseWithDelegationFailsWhenDelegateeIsNotDelegatedByBeneficiary()
        public
    {
        address newDelegatee = address(0x3);

        vm.prank(beneficiary, beneficiary);
        vestingWallet.delegate(newDelegatee);

        vm.warp(startTimestamp);

        uint256 expectedVested = 1000 * 10 ** 18; // Full amount
        uint256 initialBalance = optimismToken.balanceOf(beneficiary);

        assertTrue(
            optimismToken.delegates(address(beneficiary)) != newDelegatee
        );

        vm.expectRevert("Delegatee has not been delegated by beneficiary");
        vestingWallet.release();
    }

    function testReleaseWithDelegation() public {
        address newDelegatee = address(0x3);

        vm.prank(beneficiary, beneficiary);
        vestingWallet.delegate(newDelegatee);

        vm.warp(startTimestamp);

        uint256 expectedVested = 1000 * 10 ** 18; // Full amount
        uint256 initialBalance = optimismToken.balanceOf(beneficiary);

        vm.prank(beneficiary);
        optimismToken.delegate(newDelegatee);

        vestingWallet.release();

        uint256 finalBalance = optimismToken.balanceOf(beneficiary);
        assertEq(finalBalance - initialBalance, expectedVested);
        assertEq(optimismToken.delegates(address(beneficiary)), newDelegatee);
    }

    function testRevoke() public {
        uint256 expectedRevoked = 1000 * 10 ** 18; // Full amount

        uint256 initialManagerBalance = optimismToken.balanceOf(grantsManager);

        vm.prank(grantsManager);
        vestingWallet.revoke();

        uint256 finalManagerBalance = optimismToken.balanceOf(grantsManager);

        assertEq(finalManagerBalance - initialManagerBalance, expectedRevoked);
    }

    function testVestedAmount() public {
        // Test before start
        assertEq(vestingWallet.vestedAmount(uint64(block.timestamp)), 0);

        // Test at start
        vm.warp(startTimestamp);
        assertEq(
            vestingWallet.vestedAmount(uint64(block.timestamp)),
            1000 * 10 ** 18
        );

        // Test after start
        vm.warp(startTimestamp + 1 days);
        assertEq(
            vestingWallet.vestedAmount(uint64(block.timestamp)),
            1000 * 10 ** 18
        );
    }

    function testVestedAmountWithToken() public {
        // Test with correct token
        vm.warp(startTimestamp);
        assertEq(
            vestingWallet.vestedAmount(
                address(optimismToken),
                uint64(block.timestamp)
            ),
            1000 * 10 ** 18
        );

        // Test with incorrect token
        MockOptimismToken wrongToken = new MockOptimismToken(
            "Wrong Token",
            "WRONG",
            1000000 * 10 ** 18
        );
        assertEq(
            vestingWallet.vestedAmount(
                address(wrongToken),
                uint64(block.timestamp)
            ),
            0
        );
    }

    function testOnlyBeneficiaryCanDelegate() public {
        address newDelegatee = address(0x3);

        vm.prank(grantsManager);
        vm.expectRevert("Only beneficiary can delegate");
        vestingWallet.delegate(newDelegatee);

        vm.prank(beneficiary, beneficiary);
        vestingWallet.delegate(newDelegatee);

        assertEq(vestingWallet.delegatee(), newDelegatee);
    }

    function testOnlyGrantsManagerCanRevoke() public {
        vm.prank(beneficiary);
        vm.expectRevert("Only grants manager can revoke");
        vestingWallet.revoke();

        vm.prank(grantsManager);
        vestingWallet.revoke();

        assertEq(optimismToken.balanceOf(address(vestingWallet)), 0);
    }
}
