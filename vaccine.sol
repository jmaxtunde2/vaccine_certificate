// SPDX-License-Identifier: MIT
pragma solidity >=0.8.2 <0.9.0;
library CryptoSuite {
    function splitSignature(bytes memory sig) internal pure returns(uint8 v, bytes32 r, bytes32 s){
        require(sig.length == 65);

        assembly{
            // get the first 32 byte
            r := mload(add(sig,32))

            // get the next 32 bytes
            s := mload(add(sig,64))

            // get the first 32 byte
            v:= byte(0, mload(add(sig,96)))
        }

        return (v,r,s);
    }

    function recoverSigner(bytes32 message, bytes memory sig) internal pure returns(address){
            bytes memory prefix ="\x19Ethereum Signed Message:\n32";
            bytes32 prefixedHash = keccak256(abi.encodePacked(prefix,message));
            (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);

        return ecrecover(prefixedHash, v, r, s);
    }
}

contract ColdChain{

    enum Mode {ISSUER, PROVER, VERIFIER} // Entity role
    enum Status { MANUFACTURED, DELIVERING_INTERNATIONAL, STORED, DELIVERING_LOCAL, DELIVERED} // certificate status
    
    // state variable
    uint public constant MAXIMUM_CERTIFICATIONS = 2; // limit to 2
    uint[] public certificatesIds;
    uint[] public vaccineBatchIds;

    // mapping 
    mapping(uint => VaccineBatch) public vaccineBatches;
    mapping(uint => Certificate) public certificates;
    mapping(address => Entity) public entities;

    // definition of event
    event AddEntity(address entityId, string entityType);
    event AddVaccineBatch(uint id, address indexed manufacturer);
    event IssueCertificate(address indexed entityId, address indexed prover, uint certificateIds);

    // entity declaration (Prover,issuer)
    struct Entity {
        address id;
        Mode mode; // type of entity
        uint[] certificateIds; 
    }

    //Certificate declaration
    struct Certificate {
        uint id;
        Entity issuer;
        Entity prover;
        bytes signature;
        Status status;
    }
    // vaccine batch
    struct VaccineBatch{
        uint id;
        string brand;
        address manufacturer;
        uint[] certificateIds;
    }

    // functions 
    function addEntity(address _id, string memory _mode) public {
        Mode mode = unmarchaleMode(_mode);
        uint[] memory _certificateIds = new uint[](MAXIMUM_CERTIFICATIONS);
        Entity memory entity = Entity(_id, mode, _certificateIds);
        entities[_id] = entity;
        emit AddEntity(entity.id, _mode);
    }

    function unmarchaleMode(string memory _mode) private pure returns(Mode mode){
        bytes32 encodeMode = keccak256(abi.encodePacked(_mode));
        bytes32 encodeMode0 = keccak256(abi.encodePacked("ISSUER"));
        bytes32 encodeMode1 = keccak256(abi.encodePacked("PROVER"));
        bytes32 encodeMode2 = keccak256(abi.encodePacked("VERIFIER"));

        if(encodeMode == encodeMode0){
            return Mode.ISSUER;
        }else if(encodeMode == encodeMode1){
            return Mode.PROVER;
        }else if(encodeMode == encodeMode2){
            return Mode.VERIFIER;
        }

        revert ("received invalid entity mode");
    }

    function addVaccineBatch(string memory brand, address manufacturer) public returns(uint) {
        uint[] memory _cerificateIds = new uint[] (MAXIMUM_CERTIFICATIONS);
        uint id = vaccineBatchIds.length;
        VaccineBatch memory batch = VaccineBatch(id, brand, manufacturer, _cerificateIds);
        vaccineBatches[id] = batch;
        vaccineBatchIds.push(id);
        
        emit AddVaccineBatch(batch.id, batch.manufacturer);
        return id;
    }

    function issueCertificate(address _issuer, address _prover, string memory _status, /*uint vaccineBatchId,*/ bytes memory signature) public returns(uint)
    {
            Entity memory issuer = entities[_issuer];
            require(issuer.mode == Mode.ISSUER);

            Entity memory prover = entities[_prover];
            require(prover.mode == Mode.PROVER);

            Status status = unMarshalStatus(_status);

            uint id = certificatesIds.length;
            Certificate memory certificate = Certificate(id, issuer, prover, signature, status);
            certificatesIds.push(certificatesIds.length);
            certificates[certificatesIds.length -1] = certificate;

            emit IssueCertificate(_issuer, _prover, certificatesIds.length-1);
            return certificatesIds.length-1;
    }

    function unMarshalStatus(string memory _status) private pure returns(Status status){
        bytes32 encodeStatus = keccak256(abi.encodePacked(_status));
        bytes32 encodeStatus0 = keccak256(abi.encodePacked("MANUFACTURED"));
        bytes32 encodeStatus1 = keccak256(abi.encodePacked("DELIVERING_INTERNATIONAL"));
        bytes32 encodeStatus2 = keccak256(abi.encodePacked("DELIVERING_LOCAL"));
        bytes32 encodeStatus3 = keccak256(abi.encodePacked("DELIVERED"));
        bytes32 encodeStatus4 = keccak256(abi.encodePacked("STORED"));

        if(encodeStatus == encodeStatus0){
            return Status.MANUFACTURED;
        }else if(encodeStatus == encodeStatus1){
            return Status.DELIVERING_INTERNATIONAL;
        }else if(encodeStatus == encodeStatus2){
            return Status.DELIVERING_LOCAL;
        }else if(encodeStatus == encodeStatus3){
            return Status.DELIVERED;
        }else if(encodeStatus == encodeStatus4){
            return Status.STORED;
        }

        revert ("received invalid entity Status");
    }

    function isMatchingSignature(bytes32 message, uint id, address issuer) public view returns(bool){
        Certificate memory cert = certificates[id];

        require(cert.issuer.id == issuer);

        address recoveredSigner = CryptoSuite.recoverSigner(message, cert.signature);

        return recoveredSigner == cert.issuer.id;
    }

}