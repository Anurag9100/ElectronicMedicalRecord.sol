# ElectronicMedicalRecord.sol

Developed a blockchain-based Electronic Medical Record (EMR) Management System using Solidity smart contracts on the Ethereum blockchain to securely store and manage patient health data. The system ensures data privacy, immutability, and role-based access control, allowing only authorized users such as doctors, patients, and healthcare administrators to access or update medical records.

The smart contract enforces access permissions through role-based authorization, ensuring that patients remain the true owners of their medical data. Records are stored off-chain (using IPFS) and linked to the blockchain through secure hashes, preventing unauthorized tampering or data leaks.

Key Features:

Decentralized Data Management: Eliminates central authority, providing transparency and trust between patients and healthcare providers.

Role-Based Access Control: Only authorized doctors, nurses, and patients can view or update records.

Secure Data Storage: Stores medical documents as encrypted files on IPFS, with immutable references stored on the blockchain.

Patient Data Ownership: Patients can grant or revoke access to their medical records at any time.

Audit Trail: Every action—record creation, update, or access—is logged immutably on the blockchain for transparency.

Tamper-Proof Records: Ensures that no medical record can be modified or deleted without proper authorization.

Technologies Used:

Blockchain Platform: Ethereum

Smart Contract Language: Solidity

Tools: Remix IDE, Ganache, MetaMask, Hardhat

Frontend (optional): React.js + Ethers.js

Off-chain Storage: IPFS (InterPlanetary File System)

Encryption: AES / RSA (for securing medical data before IPFS upload)
