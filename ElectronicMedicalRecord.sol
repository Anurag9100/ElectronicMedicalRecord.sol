// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

contract EMRSystem is AccessControl {
    using Counters for Counters.Counter;
    Counters.Counter private _recordIds;

    // Roles
    bytes32 public constant ADMIN_ROLE    = keccak256("ADMIN_ROLE");
    bytes32 public constant DOCTOR_ROLE   = keccak256("DOCTOR_ROLE");
    bytes32 public constant NURSE_ROLE    = keccak256("NURSE_ROLE");
    bytes32 public constant LAB_ROLE      = keccak256("LAB_ROLE");
    bytes32 public constant PATIENT_ROLE  = keccak256("PATIENT_ROLE");
    bytes32 public constant RESEARCH_ROLE = keccak256("RESEARCH_ROLE"); // read-only, if granted by patient

    // Record status (optional)
    enum RecordStatus { Active, Archived, Revoked }

    // EMR Record (on-chain pointer + metadata only)
    struct Record {
        uint256 id;
        address patient;       // patient owner address
        address author;        // who created (doctor/nurse/lab)
        uint256 timestamp;     // creation timestamp
        string ipfsHash;       // IPFS CID or encrypted blob hash (off-chain encrypted content)
        string recordType;     // e.g. "prescription", "lab-report", "discharge-summary"
        RecordStatus status;
        bool exists;
    }

    // recordId => Record
    mapping(uint256 => Record) private records;

    // patient => list of their recordIds
    mapping(address => uint256[]) private patientRecords;

    // recordId => address => hasAccess
    mapping(uint256 => mapping(address => bool)) private recordAccess;

    // Global emergency/override access (admin only)
    mapping(address => bool) public emergencyAccessors;

    // Events
    event RecordCreated(uint256 indexed recordId, address indexed patient, address indexed author, string recordType, uint256 timestamp);
    event AccessGranted(uint256 indexed recordId, address indexed grantedTo, address indexed grantedBy);
    event AccessRevoked(uint256 indexed recordId, address indexed revokedFrom, address indexed revokedBy);
    event RecordStatusChanged(uint256 indexed recordId, RecordStatus newStatus, address indexed changedBy);
    event EmergencyAccessToggled(address indexed accessor, bool enabled, address indexed toggledBy);

    // Modifiers
    modifier onlyPatientOrAuthorized(uint256 recordId) {
        Record storage r = records[recordId];
        require(r.exists, "Record does not exist");
        if (msg.sender == r.patient) {
            _;
            return;
        }
        if (recordAccess[recordId][msg.sender]) {
            _;
            return;
        }
        // doctors/nurses/labs with role may access depending on policy:
        if (hasRole(DOCTOR_ROLE, msg.sender) || hasRole(NURSE_ROLE, msg.sender) || hasRole(LAB_ROLE, msg.sender)) {
            // they must have explicit grant unless you want role-wide access; kept strict here
            require(recordAccess[recordId][msg.sender], "No access to this record");
            _;
            return;
        }
        // Admin/emergency override allowed if enabled
        if (hasRole(ADMIN_ROLE, msg.sender) && emergencyAccessors[msg.sender]) {
            _;
            return;
        }
        revert("Access denied");
    }

    modifier recordExists(uint256 recordId) {
        require(records[recordId].exists, "Record does not exist");
        _;
    }

    // Constructor: deployer becomes DEFAULT_ADMIN and ADMIN_ROLE
    constructor(address initialAdmin) {
        address admin = initialAdmin == address(0) ? msg.sender : initialAdmin;
        _setupRole(DEFAULT_ADMIN_ROLE, admin);
        _setupRole(ADMIN_ROLE, admin);

        // Optionally assign deployer as a patient role too (not necessary)
        // _setupRole(PATIENT_ROLE, msg.sender);
    }

    // -------------------------
    // Record lifecycle functions
    // -------------------------

    /// @notice Create a new EMR record pointer (only DOCTOR / NURSE / LAB)
    /// @param patient Address of the patient (must be non-zero)
    /// @param ipfsHash IPFS CID or encrypted blob hash containing the encrypted EMR
    /// @param recordType Short string describing type e.g., "lab", "prescription"
    /// @return recordId Created record ID
    function createRecord(
        address patient,
        string calldata ipfsHash,
        string calldata recordType
    ) external returns (uint256 recordId) {
        require(patient != address(0), "Invalid patient address");
        require(bytes(ipfsHash).length > 0, "ipfsHash required");
        require(
            hasRole(DOCTOR_ROLE, msg.sender) || hasRole(NURSE_ROLE, msg.sender) || hasRole(LAB_ROLE, msg.sender),
            "Only medical staff can create records"
        );

        _recordIds.increment();
        recordId = _recordIds.current();

        records[recordId] = Record({
            id: recordId,
            patient: patient,
            author: msg.sender,
            timestamp: block.timestamp,
            ipfsHash: ipfsHash,
            recordType: recordType,
            status: RecordStatus.Active,
            exists: true
        });

        patientRecords[patient].push(recordId);

        // By default, patient and author have access
        recordAccess[recordId][patient] = true;
        recordAccess[recordId][msg.sender] = true;

        emit RecordCreated(recordId, patient, msg.sender, recordType, block.timestamp);
    }

    /// @notice Grant access to a specific record (patient or admin or author can grant)
    /// @param recordId ID of the record
    /// @param grantee Address to grant access
    function grantAccess(uint256 recordId, address grantee) external recordExists(recordId) {
        require(grantee != address(0), "Invalid grantee");
        Record storage r = records[recordId];

        // Only patient, author, or ADMIN_ROLE can grant
        require(
            msg.sender == r.patient || msg.sender == r.author || hasRole(ADMIN_ROLE, msg.sender),
            "Only patient, author or admin can grant access"
        );

        recordAccess[recordId][grantee] = true;
        emit AccessGranted(recordId, grantee, msg.sender);
    }

    /// @notice Revoke access to a specific record (patient, author, or admin)
    /// @param recordId ID of the record
    /// @param grantee Address whose access is revoked
    function revokeAccess(uint256 recordId, address grantee) external recordExists(recordId) {
        require(grantee != address(0), "Invalid grantee");
        Record storage r = records[recordId];

        // Only patient, author, or ADMIN_ROLE can revoke
        require(
            msg.sender == r.patient || msg.sender == r.author || hasRole(ADMIN_ROLE, msg.sender),
            "Only patient, author or admin can revoke access"
        );

        recordAccess[recordId][grantee] = false;
        emit AccessRevoked(recordId, grantee, msg.sender);
    }

    /// @notice Read record metadata (ipfsHash, author, timestamp, type). Caller must be patient or explicitly authorized.
    /// @param recordId ID of the record
    function readRecord(uint256 recordId)
        external
        view
        recordExists(recordId)
        onlyPatientOrAuthorized(recordId)
        returns (
            uint256 id,
            address patient,
            address author,
            uint256 timestamp,
            string memory ipfsHash,
            string memory recordType,
            RecordStatus status
        )
    {
        Record storage r = records[recordId];
        return (r.id, r.patient, r.author, r.timestamp, r.ipfsHash, r.recordType, r.status);
    }

    /// @notice Get list of record IDs for a patient
    /// @param patient Address of patient
    function getPatientRecords(address patient) external view returns (uint256[] memory) {
        return patientRecords[patient];
    }

    /// @notice Check whether an address has access to a record
    function hasAccess(uint256 recordId, address user) external view recordExists(recordId) returns (bool) {
        if (user == records[recordId].patient) return true;
        if (recordAccess[recordId][user]) return true;
        if (hasRole(ADMIN_ROLE, user) && emergencyAccessors[user]) return true;
        return false;
    }

    /// @notice Change the status of a record (archive or revoke) by authorized parties
    function changeRecordStatus(uint256 recordId, RecordStatus newStatus) external recordExists(recordId) {
        Record storage r = records[recordId];
        // Author, patient, or admin can change status
        require(
            msg.sender == r.patient || msg.sender == r.author || hasRole(ADMIN_ROLE, msg.sender),
            "Not authorized to change status"
        );
        r.status = newStatus;
        emit RecordStatusChanged(recordId, newStatus, msg.sender);
    }

    // -------------------------
    // Admin / Role management
    // -------------------------

    /// @notice Add a role to an account (only DEFAULT_ADMIN_ROLE)
    function addRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(role, account);
    }

    /// @notice Remove a role from an account (only DEFAULT_ADMIN_ROLE)
    function removeRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(role, account);
    }

    /// @notice Enable or disable emergency access for an admin account (only DEFAULT_ADMIN_ROLE)
    function toggleEmergencyAccessor(address accessor, bool enabled) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(accessor != address(0), "Invalid address");
        emergencyAccessors[accessor] = enabled;
        emit EmergencyAccessToggled(accessor, enabled, msg.sender);
    }

    // -------------------------
    // Safety helpers
    // -------------------------

    /// @notice Forcibly update record IPFS hash (admin only) — use sparingly
    function adminUpdateIpfsHash(uint256 recordId, string calldata newIpfsHash) external onlyRole(ADMIN_ROLE) recordExists(recordId) {
        require(bytes(newIpfsHash).length > 0, "ipfs required");
        records[recordId].ipfsHash = newIpfsHash;
    }

    /// @notice Returns basic info for debugging/inspection (not sensitive)
    function getRecordSummary(uint256 recordId) external view recordExists(recordId) returns (
        uint256 id,
        address patient,
        address author,
        uint256 timestamp,
        RecordStatus status
    ) {
        Record storage r = records[recordId];
        return (r.id, r.patient, r.author, r.timestamp, r.status);
    }
}
