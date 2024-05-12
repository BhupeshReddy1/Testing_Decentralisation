// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileVerification {
    struct Upload {
        address uploader;
        string filename;
        string encryptedHash;
        bool approved;
    }

    mapping(uint256 => Upload) public uploads;
    uint256 public uploadCount;

    event FileUploaded(uint256 indexed id, address indexed uploader, string filename, string encryptedHash);
    event ApprovalStatusChanged(uint256 indexed id, bool approved);

    modifier onlyAdmin {
        // Implement logic to check if the sender is an admin
        require(isAdmin(msg.sender), "Only admin can call this function.");
        _;
    }

    function isAdmin(address _address) private view returns (bool) {
        // Implement logic to check if the address is an admin
        // You can store admin addresses in a list or define a separate role for admins
        // For simplicity, let's assume admin addresses are hardcoded
        //|| _address == 0x84F8dEb6D6EAa4951DbFA4e17c59F82A1dF0CAd5 can be used as 2nd admin address
        if (_address == 0x2D9ED4Dc358419BcE8949Ac08AeefE11845E42EB ) {
            return true;
        } else {
            return false;
        }
    }

    function uploadFile(string memory _filename, string memory _encryptedHash) public {
        require(bytes(_filename).length > 0 && bytes(_encryptedHash).length > 0, "Filename and encrypted hash must not be empty.");
        
        uploadCount++;
        uploads[uploadCount] = Upload(msg.sender, _filename, _encryptedHash, false);
        emit FileUploaded(uploadCount, msg.sender, _filename, _encryptedHash);
    }

    function approveUpload(uint256 _id) public onlyAdmin {
        require(_id > 0 && _id <= uploadCount, "Invalid upload ID.");

        uploads[_id].approved = true;
        emit ApprovalStatusChanged(_id, true);
    }

    function rejectUpload(uint256 _id) public onlyAdmin {
        require(_id > 0 && _id <= uploadCount, "Invalid upload ID.");

        delete uploads[_id];
        emit ApprovalStatusChanged(_id, false);
    } }
