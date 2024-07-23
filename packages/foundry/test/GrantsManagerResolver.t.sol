// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import "forge-std/Test.sol";
import "../contracts/GrantsManagerResolver.sol";
import "../contracts/VestingWalletWithDelegation.sol";
import "@eas-contracts/EAS.sol";
import "@eas-contracts/ISchemaRegistry.sol";
import "@eas-contracts/SchemaRegistry.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/access/IAccessControl.sol";

contract MockEAS is EAS {
    constructor(ISchemaRegistry registry) EAS(registry) {}
}

contract MockOptimismToken is ERC20, ERC20Permit, ERC20Votes {
    constructor(
        string memory name,
        string memory symbol,
        uint256 totalSupply
    ) ERC20(name, symbol) ERC20Permit(name) {
        _mint(msg.sender, totalSupply);
    }

    function _update(
        address from,
        address to,
        uint256 value
    ) internal override(ERC20Votes, ERC20) {
        super._update(from, to, value);
    }

    function nonces(
        address owner
    ) public view override(ERC20Permit, Nonces) returns (uint256) {
        return super.nonces(owner);
    }
}

contract GrantsManagerResolverTest is Test {
    GrantsManagerResolver public resolver;
    MockEAS public eas;
    MockOptimismToken public optimismToken;
    SchemaRegistry public schemaRegistry;
    address public owner;
    address public proposer;
    address public approver;
    address public delegatee;

    function setUp() public {
        owner = address(this);
        proposer = address(0x1);
        approver = address(0x2);
        delegatee = address(0x3);

        schemaRegistry = new SchemaRegistry();
        eas = new MockEAS(schemaRegistry);
        optimismToken = new MockOptimismToken(
            "Optimism Token",
            "OPT",
            1000000 * 10 ** 18
        );

        // Transfer tokens to owner
        optimismToken.transfer(owner, 1000000 * 10 ** 18);

        vm.startPrank(owner, owner);
        resolver = new GrantsManagerResolver(
            IEAS(address(eas)),
            ERC20Votes(address(optimismToken)),
            schemaRegistry
        );
        resolver.registerSchemas();
        resolver.setApprover(approver, true);
        vm.stopPrank();

        optimismToken.transfer(owner, 1000000 * 10 ** 18);
        vm.prank(owner);
        optimismToken.approve(address(resolver), type(uint256).max);

        // Approve MockEAS to spend tokens
        vm.prank(owner);
        optimismToken.approve(address(eas), type(uint256).max);
    }

    function testGrantProposalWithInvalidSchema() public {
        bytes32 invalidSchemaUID = bytes32(uint256(1));
        bytes memory data = abi.encode(proposer, 3, 1000 * 10 ** 18);
        AttestationRequest memory request = AttestationRequest({
            schema: invalidSchemaUID,
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: bytes32(0),
                data: data,
                value: 0
            })
        });

        vm.prank(proposer);
        vm.expectRevert();
        eas.attest(request);
    }

    function testGrantProposal() public {
        bytes memory data = abi.encode(proposer, 3, 1000 * 10 ** 18);
        AttestationRequest memory request = AttestationRequest({
            schema: resolver.GRANT_PROPOSAL_SCHEMA_UID(),
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: bytes32(0),
                data: data,
                value: 0
            })
        });

        vm.prank(proposer);
        bytes32 uid = eas.attest(request);
        assertTrue(uid != bytes32(0), "Attestation failed");

        Attestation memory attestation = eas.getAttestation(uid);
        assertEq(attestation.attester, proposer, "Incorrect attester");
        assertEq(
            attestation.schema,
            resolver.GRANT_PROPOSAL_SCHEMA_UID(),
            "Incorrect schema"
        );

        (
            address storedProposer,
            uint256 storedMilestoneCount,
            uint256 storedAmount
        ) = abi.decode(attestation.data, (address, uint256, uint256));
        assertEq(storedProposer, proposer, "Incorrect proposer");
        assertEq(storedMilestoneCount, 3, "Incorrect milestone count");
        assertEq(storedAmount, 1000 * 10 ** 18, "Incorrect amount");
    }

    function testGrantApproval() public {
        // First, create a grant proposal
        bytes memory proposalData = abi.encode(proposer, 3, 1000 * 10 ** 18);
        AttestationRequest memory proposalRequest = AttestationRequest({
            schema: resolver.GRANT_PROPOSAL_SCHEMA_UID(),
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: bytes32(0),
                data: proposalData,
                value: 0
            })
        });

        vm.prank(proposer);
        bytes32 proposalUid = eas.attest(proposalRequest);

        // Now, approve the grant
        bytes memory approvalData = abi.encode(
            proposalUid,
            block.timestamp,
            1000 * 10 ** 18
        );
        AttestationRequest memory approvalRequest = AttestationRequest({
            schema: resolver.GRANT_APPROVAL_SCHEMA_UID(),
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: proposalUid,
                data: approvalData,
                value: 0
            })
        });

        vm.prank(approver, approver);
        bytes32 approvalUid = eas.attest(approvalRequest);
        assertTrue(approvalUid != bytes32(0), "Approval attestation failed");

        Attestation memory attestation = eas.getAttestation(approvalUid);
        assertEq(attestation.attester, approver, "Incorrect approver");
        assertEq(
            attestation.schema,
            resolver.GRANT_APPROVAL_SCHEMA_UID(),
            "Incorrect schema"
        );
    }

    function testVestingWalletCreation() public {
        // Create a grant proposal and approve it
        bytes32 proposalUid = _createAndApproveGrantProposal();

        assertTrue(
            resolver.grantProposalToVestingWallet(proposalUid) != address(0),
            "Invalid vesting wallet address"
        );
    }

    function testMilestoneCompletion() public {
        // Create a grant proposal and approve it
        bytes32 proposalUid = _createAndApproveGrantProposal();

        // Complete a milestone
        uint256 milestoneNumber = 1;
        bytes memory milestoneData = abi.encode(proposalUid, milestoneNumber);
        AttestationRequest memory milestoneRequest = AttestationRequest({
            schema: resolver.MILESTONE_COMPLETION_SCHEMA_UID(),
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: proposalUid,
                data: milestoneData,
                value: 0
            })
        });

        vm.prank(proposer);
        bytes32 milestoneUid = eas.attest(milestoneRequest);
        assertTrue(
            milestoneUid != bytes32(0),
            "Milestone completion attestation failed"
        );

        Attestation memory attestation = eas.getAttestation(milestoneUid);
        assertEq(attestation.attester, proposer, "Incorrect attester");
        assertEq(
            attestation.schema,
            resolver.MILESTONE_COMPLETION_SCHEMA_UID(),
            "Incorrect schema"
        );
    }

    function testMilestoneApproval() public {
        // Create a grant proposal, approve it, and create a vesting wallet
        bytes32 proposalUid = _createAndApproveGrantProposal();

        // Complete the milestone
        _completeMilestone(proposalUid, 1);

        // Approve the milestone
        uint256 milestoneNumber = 1;
        bytes memory approvalData = abi.encode(proposalUid, milestoneNumber);
        AttestationRequest memory approvalRequest = AttestationRequest({
            schema: resolver.MILESTONE_APPROVAL_SCHEMA_UID(),
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: proposalUid,
                data: approvalData,
                value: 0
            })
        });

        vm.prank(approver, approver);
        bytes32 approvalUid = eas.attest(approvalRequest);
        assertTrue(
            approvalUid != bytes32(0),
            "Milestone approval attestation failed"
        );

        Attestation memory attestation = eas.getAttestation(approvalUid);
        assertEq(attestation.attester, approver, "Incorrect attester");
        assertEq(
            attestation.schema,
            resolver.MILESTONE_APPROVAL_SCHEMA_UID(),
            "Incorrect schema"
        );
    }

    function testDelegation() public {
        // Create a grant proposal, approve it, and create a vesting wallet
        bytes32 proposalUid = _createAndApproveGrantProposal();

        // Perform delegation
        bytes memory delegationData = abi.encode(proposalUid, delegatee);
        AttestationRequest memory delegationRequest = AttestationRequest({
            schema: resolver.DELEGATION_SCHEMA_UID(),
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: proposalUid,
                data: delegationData,
                value: 0
            })
        });

        vm.prank(proposer, proposer);
        bytes32 delegationUid = eas.attest(delegationRequest);
        assertTrue(
            delegationUid != bytes32(0),
            "Delegation attestation failed"
        );

        Attestation memory attestation = eas.getAttestation(delegationUid);
        assertEq(attestation.attester, proposer, "Incorrect attester");
        assertEq(
            attestation.schema,
            resolver.DELEGATION_SCHEMA_UID(),
            "Incorrect schema"
        );
    }

    function testGrantRevocation() public {
        // Create a grant proposal, approve it, and create a vesting wallet
        bytes32 proposalUid = _createAndApproveGrantProposal();

        // Revoke the grant
        bytes memory revocationData = abi.encode(proposalUid);
        AttestationRequest memory revocationRequest = AttestationRequest({
            schema: resolver.GRANT_REVOCATION_SCHEMA_UID(),
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: proposalUid,
                data: revocationData,
                value: 0
            })
        });

        vm.prank(approver, approver);
        bytes32 revocationUid = eas.attest(revocationRequest);
        assertTrue(
            revocationUid != bytes32(0),
            "Grant revocation attestation failed"
        );

        Attestation memory attestation = eas.getAttestation(revocationUid);
        assertEq(attestation.attester, approver, "Incorrect attester");
        assertEq(
            attestation.schema,
            resolver.GRANT_REVOCATION_SCHEMA_UID(),
            "Incorrect schema"
        );
    }

    function _createAndApproveGrantProposal() internal returns (bytes32) {
        bytes memory proposalData = abi.encode(proposer, 3, 1000 * 10 ** 18);
        AttestationRequest memory proposalRequest = AttestationRequest({
            schema: resolver.GRANT_PROPOSAL_SCHEMA_UID(),
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: bytes32(0),
                data: proposalData,
                value: 0
            })
        });

        vm.prank(proposer);
        bytes32 proposalUid = eas.attest(proposalRequest);

        bytes memory approvalData = abi.encode(
            proposalUid,
            block.timestamp,
            1000 * 10 ** 18
        );

        AttestationRequest memory approvalRequest = AttestationRequest({
            schema: resolver.GRANT_APPROVAL_SCHEMA_UID(),
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: proposalUid,
                data: approvalData,
                value: 0
            })
        });

        vm.prank(approver, approver);
        eas.attest(approvalRequest);

        return proposalUid;
    }

    function _completeMilestone(
        bytes32 proposalUid,
        uint256 milestoneNumber
    ) internal {
        bytes memory milestoneData = abi.encode(proposalUid, milestoneNumber);
        AttestationRequest memory milestoneRequest = AttestationRequest({
            schema: resolver.MILESTONE_COMPLETION_SCHEMA_UID(),
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: proposalUid,
                data: milestoneData,
                value: 0
            })
        });

        vm.prank(proposer);
        eas.attest(milestoneRequest);
    }

    function testOnlyApproverCanApproveGrant() public {
        bytes32 proposalUid = _createGrantProposal();

        bytes memory approvalData = abi.encode(
            proposalUid,
            block.timestamp,
            1000 * 10 ** 18
        );
        AttestationRequest memory approvalRequest = AttestationRequest({
            schema: resolver.GRANT_APPROVAL_SCHEMA_UID(),
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: proposalUid,
                data: approvalData,
                value: 0
            })
        });

        vm.prank(proposer);
        vm.expectRevert();
        eas.attest(approvalRequest);
    }

    function testOnlyAdminCanSetApprover() public {
        address newApprover = address(0x4);

        vm.prank(proposer, proposer);
        vm.expectRevert();
        resolver.setApprover(newApprover, true);

        vm.prank(owner, owner);
        resolver.setApprover(newApprover, true);

        assertTrue(resolver.hasRole(resolver.APPROVER_ROLE(), newApprover));
    }

    function _createGrantProposal() internal returns (bytes32) {
        bytes memory proposalData = abi.encode(proposer, 3, 1000 * 10 ** 18);
        AttestationRequest memory proposalRequest = AttestationRequest({
            schema: resolver.GRANT_PROPOSAL_SCHEMA_UID(),
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: bytes32(0),
                data: proposalData,
                value: 0
            })
        });

        vm.prank(proposer);
        return eas.attest(proposalRequest);
    }

    function testMultipleGrantProposals() public {
        uint256 proposalCount = 3;
        bytes32[] memory proposalUids = new bytes32[](proposalCount);

        for (uint256 i = 0; i < proposalCount; i++) {
            bytes memory data = abi.encode(proposer, 3, 1000 * 10 ** 18);
            AttestationRequest memory request = AttestationRequest({
                schema: resolver.GRANT_PROPOSAL_SCHEMA_UID(),
                data: AttestationRequestData({
                    recipient: address(0),
                    expirationTime: 0,
                    revocable: false,
                    refUID: bytes32(0),
                    data: data,
                    value: 0
                })
            });

            vm.prank(proposer);
            proposalUids[i] = eas.attest(request);
        }

        for (uint256 i = 0; i < proposalCount; i++) {
            assertTrue(proposalUids[i] != bytes32(0), "Attestation failed");
        }
    }

    function testMilestoneCompletionAndApprovalFlow() public {
        bytes32 proposalUid = _createAndApproveGrantProposal();

        // Complete milestones
        for (uint256 i = 1; i <= 3; i++) {
            _completeMilestone(proposalUid, i);

            // Approve milestone
            bytes memory approvalData = abi.encode(proposalUid, i);
            AttestationRequest memory approvalRequest = AttestationRequest({
                schema: resolver.MILESTONE_APPROVAL_SCHEMA_UID(),
                data: AttestationRequestData({
                    recipient: address(0),
                    expirationTime: 0,
                    revocable: false,
                    refUID: proposalUid,
                    data: approvalData,
                    value: 0
                })
            });

            vm.prank(approver, approver);
            bytes32 approvalUid = eas.attest(approvalRequest);
            assertTrue(
                approvalUid != bytes32(0),
                "Milestone approval attestation failed"
            );
        }

        // Verify all milestones are completed and approved
        for (uint256 i = 1; i <= 3; i++) {
            assertTrue(
                _isMilestoneCompleted(proposalUid, i),
                "Milestone not marked as completed"
            );
            assertTrue(
                _isMilestoneApproved(proposalUid, i),
                "Milestone not marked as approved"
            );
        }
    }

    function testGrantRevocationBeforeMilestoneCompletion() public {
        bytes32 proposalUid = _createAndApproveGrantProposal();

        // Attempt to revoke before any milestones are completed
        bytes memory revocationData = abi.encode(proposalUid);
        AttestationRequest memory revocationRequest = AttestationRequest({
            schema: resolver.GRANT_REVOCATION_SCHEMA_UID(),
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: proposalUid,
                data: revocationData,
                value: 0
            })
        });

        vm.prank(approver, approver);
        bytes32 revocationUid = eas.attest(revocationRequest);
        assertTrue(
            revocationUid != bytes32(0),
            "Grant revocation attestation failed"
        );

        // Verify the grant is revoked
        assertTrue(_isGrantRevoked(proposalUid), "Grant not marked as revoked");
    }

    function testDelegationAndVestingWalletInteraction() public {
        bytes32 proposalUid = _createAndApproveGrantProposal();
        address vestingWalletAddress = resolver.grantProposalToVestingWallet(
            proposalUid
        );

        // Perform delegation
        address newDelegatee = address(0x1234);
        bytes memory delegationData = abi.encode(proposalUid, newDelegatee);
        AttestationRequest memory delegationRequest = AttestationRequest({
            schema: resolver.DELEGATION_SCHEMA_UID(),
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: proposalUid,
                data: delegationData,
                value: 0
            })
        });

        vm.prank(proposer, proposer);
        bytes32 delegationUid = eas.attest(delegationRequest);
        assertTrue(
            delegationUid != bytes32(0),
            "Delegation attestation failed"
        );

        // Verify delegation in vesting wallet
        VestingWalletWithDelegation vestingWallet = VestingWalletWithDelegation(
            payable(vestingWalletAddress)
        );
        assertEq(
            vestingWallet.delegatee(),
            newDelegatee,
            "Delegation not properly set in vesting wallet"
        );
    }

    function _isMilestoneCompleted(
        bytes32 proposalUid,
        uint256 milestoneNumber
    ) internal view returns (bool) {
        bytes32 milestoneKey = keccak256(
            abi.encodePacked(
                resolver.MILESTONE_COMPLETION_SCHEMA_UID(),
                milestoneNumber
            )
        );
        return
            resolver.getLastAttestationUIDBySchema(proposalUid, milestoneKey) !=
            bytes32(0);
    }

    function _isMilestoneApproved(
        bytes32 proposalUid,
        uint256 milestoneNumber
    ) internal view returns (bool) {
        bytes32 milestoneKey = keccak256(
            abi.encodePacked(
                resolver.MILESTONE_APPROVAL_SCHEMA_UID(),
                milestoneNumber
            )
        );
        return
            resolver.getLastAttestationUIDBySchema(proposalUid, milestoneKey) !=
            bytes32(0);
    }

    function _isGrantRevoked(bytes32 proposalUid) internal view returns (bool) {
        return
            resolver.getLastAttestationUIDBySchema(
                proposalUid,
                resolver.GRANT_REVOCATION_SCHEMA_UID()
            ) != bytes32(0);
    }
}
