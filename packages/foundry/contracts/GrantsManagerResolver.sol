// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@eas-contracts/resolver/SchemaResolver.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import "@eas-contracts/IEAS.sol";
import "@eas-contracts/ISchemaRegistry.sol";
import "./VestingWalletWithDelegation.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
contract GrantsManagerResolver is
    SchemaResolver,
    Ownable,
    AccessControl,
    Pausable
{
    ERC20Votes public immutable optimismToken;
    bytes32 public immutable APPROVER_ROLE = keccak256("APPROVER_ROLE");

    string public constant GRANT_PROPOSAL_SCHEMA =
        "address proposer, uint256 milestoneCount, uint256 amount";
    string public constant GRANT_APPROVAL_SCHEMA =
        "bytes32 grantProposalUID, uint64 startTime, uint256 approvedAmount";
    string public constant MILESTONE_COMPLETION_SCHEMA =
        "bytes32 grantProposalUID, uint256 milestoneNumber";
    string public constant MILESTONE_APPROVAL_SCHEMA =
        "bytes32 grantProposalUID, uint256 approvedMilestone";
    string public constant DELEGATION_SCHEMA =
        "bytes32 grantProposalUID, address delegatee";
    string public constant GRANT_REVOCATION_SCHEMA = "bytes32 grantProposalUID";

    bytes32 public GRANT_PROPOSAL_SCHEMA_UID;
    bytes32 public GRANT_APPROVAL_SCHEMA_UID;
    bytes32 public VESTING_WALLET_CREATION_SCHEMA_UID;
    bytes32 public MILESTONE_COMPLETION_SCHEMA_UID;
    bytes32 public MILESTONE_APPROVAL_SCHEMA_UID;
    bytes32 public DELEGATION_SCHEMA_UID;
    bytes32 public GRANT_REVOCATION_SCHEMA_UID;

    mapping(bytes32 => mapping(bytes32 => bytes32))
        public grantProposalAttestationUidToLastAttestationsBySchema;

    mapping(bytes32 => address) public grantProposalToVestingWallet;

    event GrantProposed(
        bytes32 indexed proposalUid,
        address indexed proposer,
        uint256 amount
    );
    event GrantApproved(
        bytes32 indexed proposalUid,
        address indexed approver,
        uint256 amount
    );
    event GrantRevoked(bytes32 indexed proposalUid, address indexed revoker);
    event MilestoneCompleted(
        bytes32 indexed proposalUid,
        uint256 milestoneNumber
    );
    event MilestoneApproved(
        bytes32 indexed proposalUid,
        uint256 milestoneNumber
    );

    error OnlyProposerCanAttest(address attester, address proposer);
    error OnlyApprovedEntities(address attester);
    error GrantAlreadyApproved(bytes32 proposalUid);
    error GrantNotApproved();
    error VestingWalletAlreadyCreated();
    error OnlyContractCanCreateVestingWallet();
    error InvalidBeneficiary();
    error TokenTransferFailed();
    error InvalidMilestoneNumber();
    error MilestoneAlreadyCompleted();
    error MilestoneNotCompleted();
    error MilestoneAlreadyApproved();
    error InvalidVestingWallet();
    error OnlyBeneficiaryCanDelegate();
    error GrantAlreadyRevoked();
    error VestingWalletNotFound();

    ISchemaRegistry public immutable schemaRegistry;

    constructor(
        IEAS _eas,
        ERC20Votes _optimismToken,
        ISchemaRegistry _schemaRegistry
    ) SchemaResolver(_eas) Ownable(msg.sender) {
        optimismToken = _optimismToken;
        schemaRegistry = _schemaRegistry;

        _grantRole(DEFAULT_ADMIN_ROLE, owner());
        _grantRole(APPROVER_ROLE, owner());
    }

    function registerSchemas() external onlyOwner {
        GRANT_PROPOSAL_SCHEMA_UID = _registerOrGetSchema(GRANT_PROPOSAL_SCHEMA);
        GRANT_APPROVAL_SCHEMA_UID = _registerOrGetSchema(GRANT_APPROVAL_SCHEMA);
        MILESTONE_COMPLETION_SCHEMA_UID = _registerOrGetSchema(
            MILESTONE_COMPLETION_SCHEMA
        );
        MILESTONE_APPROVAL_SCHEMA_UID = _registerOrGetSchema(
            MILESTONE_APPROVAL_SCHEMA
        );
        DELEGATION_SCHEMA_UID = _registerOrGetSchema(DELEGATION_SCHEMA);
        GRANT_REVOCATION_SCHEMA_UID = _registerOrGetSchema(
            GRANT_REVOCATION_SCHEMA
        );
    }

    function _registerOrGetSchema(
        string memory schema
    ) internal returns (bytes32) {
        bytes32 schemaUID = _getSchemaUID(schema);
        SchemaRecord memory existingSchema = schemaRegistry.getSchema(
            schemaUID
        );

        if (existingSchema.uid != bytes32(0)) {
            // Schema already exists, return its UID
            return existingSchema.uid;
        } else {
            // Schema doesn't exist, register it
            return schemaRegistry.register(schema, this, false);
        }
    }

    function _getSchemaUID(
        string memory schema
    ) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(schema, address(this), false));
    }

    function setApprover(
        address account,
        bool isApprover
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (isApprover) {
            _grantRole(APPROVER_ROLE, account);
        } else {
            _revokeRole(APPROVER_ROLE, account);
        }
    }

    function _checkRole(bytes32 role) internal view virtual override {
        _checkRole(role, tx.origin);
    }

    function registerSchema(string memory schema) internal returns (bytes32) {
        return schemaRegistry.register(schema, this, false);
    }

    function calculateSchemaUID(
        string memory schema
    ) internal returns (bytes32) {
        return keccak256(abi.encodePacked(schema, address(this), false));
    }

    function onAttest(
        Attestation calldata attestation,
        uint256
    ) internal override returns (bool) {
        bytes32 schemaUID = attestation.schema;

        if (schemaUID == GRANT_PROPOSAL_SCHEMA_UID) {
            return _handleGrantProposal(attestation);
        } else if (schemaUID == GRANT_APPROVAL_SCHEMA_UID) {
            return _handleGrantApproval(attestation);
        } else if (schemaUID == MILESTONE_COMPLETION_SCHEMA_UID) {
            return _handleMilestoneCompletion(attestation);
        } else if (schemaUID == MILESTONE_APPROVAL_SCHEMA_UID) {
            return _handleMilestoneApproval(attestation);
        } else if (schemaUID == DELEGATION_SCHEMA_UID) {
            return _handleDelegation(attestation);
        } else if (schemaUID == GRANT_REVOCATION_SCHEMA_UID) {
            return _handleGrantApprovalRevoke(attestation);
        }

        return false;
    }

    function onRevoke(
        Attestation calldata attestation,
        uint256
    ) internal pure override returns (bool) {
        return false;
    }

    function _handleGrantProposal(
        Attestation calldata attestation
    ) internal returns (bool) {
        (address proposer, uint256 milestoneCount, uint256 amount) = abi.decode(
            attestation.data,
            (address, uint256, uint256)
        );
        if (attestation.attester != proposer)
            revert OnlyProposerCanAttest(attestation.attester, proposer);

        grantProposalAttestationUidToLastAttestationsBySchema[attestation.uid][
            GRANT_PROPOSAL_SCHEMA_UID
        ] = attestation.uid;

        emit GrantProposed(attestation.uid, proposer, amount);

        return true;
    }

    function _handleGrantApproval(
        Attestation calldata attestation
    ) internal onlyRole(APPROVER_ROLE) returns (bool) {
        (bytes32 grantProposalUID, uint64 startTime, ) = abi.decode(
            attestation.data,
            (bytes32, uint64, uint256)
        );
        if (_isGrantApproved(grantProposalUID))
            revert GrantAlreadyApproved(grantProposalUID);

        grantProposalAttestationUidToLastAttestationsBySchema[grantProposalUID][
            GRANT_APPROVAL_SCHEMA_UID
        ] = attestation.uid;

        _createVestingWallet(grantProposalUID, startTime);

        return true;
    }

    function _handleMilestoneCompletion(
        Attestation calldata attestation
    ) internal returns (bool) {
        (bytes32 grantProposalUID, uint256 milestoneNumber) = abi.decode(
            attestation.data,
            (bytes32, uint256)
        );
        (
            address proposer,
            uint256 milestoneCount,
            ,

        ) = _getGrantProposalDetails(grantProposalUID);
        if (attestation.attester != proposer)
            revert OnlyProposerCanAttest(attestation.attester, proposer);
        if (milestoneNumber > milestoneCount) revert InvalidMilestoneNumber();
        if (_isMilestoneCompleted(grantProposalUID, milestoneNumber))
            revert MilestoneAlreadyCompleted();

        bytes32 milestoneKey = keccak256(
            abi.encodePacked(MILESTONE_COMPLETION_SCHEMA_UID, milestoneNumber)
        );

        grantProposalAttestationUidToLastAttestationsBySchema[grantProposalUID][
            milestoneKey
        ] = attestation.uid;

        return true;
    }

    function _handleMilestoneApproval(
        Attestation calldata attestation
    ) internal onlyRole(APPROVER_ROLE) returns (bool) {
        (bytes32 grantProposalUID, uint256 milestoneNumber) = abi.decode(
            attestation.data,
            (bytes32, uint256)
        );
        if (!_isMilestoneCompleted(grantProposalUID, milestoneNumber))
            revert MilestoneNotCompleted();
        if (_isMilestoneApproved(grantProposalUID, milestoneNumber))
            revert MilestoneAlreadyApproved();

        bytes32 milestoneKey = keccak256(
            abi.encodePacked(MILESTONE_APPROVAL_SCHEMA_UID, milestoneNumber)
        );

        grantProposalAttestationUidToLastAttestationsBySchema[grantProposalUID][
            milestoneKey
        ] = attestation.uid;

        return true;
    }

    function _handleDelegation(
        Attestation calldata attestation
    ) internal returns (bool) {
        (bytes32 grantProposalUID, address newDelegatee) = abi.decode(
            attestation.data,
            (bytes32, address)
        );
        address vestingWallet = _getVestingWallet(grantProposalUID);
        if (
            attestation.attester !=
            VestingWalletWithDelegation(payable(vestingWallet)).beneficiary()
        ) {
            revert OnlyBeneficiaryCanDelegate();
        }

        VestingWalletWithDelegation(payable(vestingWallet)).delegate(
            newDelegatee
        );

        grantProposalAttestationUidToLastAttestationsBySchema[grantProposalUID][
            DELEGATION_SCHEMA_UID
        ] = attestation.uid;

        return true;
    }

    function _handleGrantApprovalRevoke(
        Attestation calldata attestation
    ) internal onlyRole(APPROVER_ROLE) returns (bool) {
        bytes32 grantProposalUID = abi.decode(attestation.data, (bytes32));
        if (!_isGrantApproved(grantProposalUID)) revert GrantNotApproved();
        if (_isGrantRevoked(grantProposalUID)) revert GrantAlreadyRevoked();

        address vestingWallet = _getVestingWallet(grantProposalUID);
        if (vestingWallet == address(0)) revert VestingWalletNotFound();

        VestingWalletWithDelegation(payable(vestingWallet)).revoke();

        grantProposalAttestationUidToLastAttestationsBySchema[grantProposalUID][
            GRANT_REVOCATION_SCHEMA_UID
        ] = attestation.uid;

        return true;
    }

    function _createVestingWallet(
        bytes32 grantProposalUID,
        uint64 startTimestamp
    ) internal returns (address) {
        if (!_isGrantApproved(grantProposalUID)) revert GrantNotApproved();
        if (_isVestingWalletCreated(grantProposalUID))
            revert VestingWalletAlreadyCreated();

        (
            address proposer,
            uint256 amount,
            ,
            bytes32 grantProposalAttestationUID
        ) = _getGrantProposalDetails(grantProposalUID);

        VestingWalletWithDelegation vestingWallet = new VestingWalletWithDelegation(
                proposer,
                startTimestamp,
                address(optimismToken),
                address(this)
            );

        if (
            !optimismToken.transferFrom(owner(), address(vestingWallet), amount)
        ) revert TokenTransferFailed();

        grantProposalToVestingWallet[grantProposalUID] = address(vestingWallet);

        return address(vestingWallet);
    }

    function _isGrantApproved(
        bytes32 grantProposalUID
    ) internal view returns (bool) {
        return
            grantProposalAttestationUidToLastAttestationsBySchema[
                grantProposalUID
            ][GRANT_APPROVAL_SCHEMA_UID] != bytes32(0);
    }

    function _isGrantRevoked(
        bytes32 grantProposalUID
    ) internal view returns (bool) {
        return
            grantProposalAttestationUidToLastAttestationsBySchema[
                grantProposalUID
            ][GRANT_REVOCATION_SCHEMA_UID] != bytes32(0);
    }

    function _isVestingWalletCreated(
        bytes32 grantProposalUID
    ) internal view returns (bool) {
        return
            grantProposalAttestationUidToLastAttestationsBySchema[
                grantProposalUID
            ][VESTING_WALLET_CREATION_SCHEMA_UID] != bytes32(0);
    }

    function _isMilestoneCompleted(
        bytes32 grantProposalUID,
        uint256 milestoneNumber
    ) internal view returns (bool) {
        bytes32 milestoneKey = keccak256(
            abi.encodePacked(MILESTONE_COMPLETION_SCHEMA_UID, milestoneNumber)
        );

        return
            grantProposalAttestationUidToLastAttestationsBySchema[
                grantProposalUID
            ][milestoneKey] != bytes32(0);
    }

    function _isMilestoneApproved(
        bytes32 grantProposalUID,
        uint256 milestoneNumber
    ) internal view returns (bool) {
        bytes32 milestoneKey = keccak256(
            abi.encodePacked(MILESTONE_APPROVAL_SCHEMA_UID, milestoneNumber)
        );
        return
            grantProposalAttestationUidToLastAttestationsBySchema[
                grantProposalUID
            ][milestoneKey] != bytes32(0);
    }

    function _getGrantProposalDetails(
        bytes32 grantProposalUID
    )
        internal
        view
        returns (
            address proposer,
            uint256 milestoneCount,
            uint256 amount,
            bytes32 attestationUID
        )
    {
        attestationUID = grantProposalAttestationUidToLastAttestationsBySchema[
            grantProposalUID
        ][GRANT_PROPOSAL_SCHEMA_UID];
        Attestation memory attestation = _eas.getAttestation(attestationUID);
        (proposer, milestoneCount, amount) = abi.decode(
            attestation.data,
            (address, uint256, uint256)
        );
    }

    function _getVestingWallet(
        bytes32 grantProposalUID
    ) internal view returns (address) {
        return grantProposalToVestingWallet[grantProposalUID];
    }

    function getLastAttestationUIDBySchema(
        bytes32 grantProposalUID,
        bytes32 schemaUID
    ) external view returns (bytes32) {
        return
            grantProposalAttestationUidToLastAttestationsBySchema[
                grantProposalUID
            ][schemaUID];
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}
