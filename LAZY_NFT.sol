//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;
pragma abicoder v2; // required to accept structs as function parameters

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract LivinLikeLarryNFT is ERC721, EIP712, Ownable {
  using Strings for uint256;

  address payable private _minter;
  string private constant SIGNING_DOMAIN = "LivinLikeLarryNFT-Voucher";
  string private constant SIGNATURE_VERSION = "1";
  string private constant reservedUri = "ipfs://Qmd52XEVD878gQL6o3cAVbz5tWyhNHQ6iWGFTpg1hNPm2j/";
  string private constant mainUri = "ipfs://Qmd52XEVD878gQL6o3cAVbz5tWyhNHQ6iWGFTpg1hNPm2j/";
  uint256 private constant maxPublicSupply = 4900;
  uint256 private constant maxReservedSupply = 100;
  uint256 private publicMintedCount = 0;
  uint256 private reservedMintedCount = 0;
  uint256[] private redeemedVouchers;

  constructor(address payable startingMinter)
    ERC721("LivinLikeLarry", "LLL") 
    EIP712(SIGNING_DOMAIN, SIGNATURE_VERSION) {
      _minter = startingMinter;
    }
  /// @notice Represents an un-minted NFT, which has not yet been recorded into the blockchain. A signed voucher can be redeemed for a real NFT using the redeem function.
  struct NFTVoucher {
    /// @notice Voucher ID, used to keep track of which vouchers have been claimed, and prevent them from being used more than once.
    uint256 id;

    /// @notice The number of tokens to mint. 
    uint256 numberToMint;

    /// @notice the EIP-712 signature of all other fields in the NFTVoucher struct. For a voucher to be valid, it must be signed by an account with the MINTER_ROLE.
    bytes signature;
  }

  function minter() public view returns (address payable) {
    return _minter;
  }

  function setMinter(address payable newMinter) public onlyOwner {
    _minter = newMinter;
  }

  /// @notice Redeems an NFTVoucher for an actual NFT, creating it in the process.
  /// @param voucher A signed NFTVoucher that describes the NFT to be redeemed.
  function redeem(NFTVoucher calldata voucher) public payable {
    // make sure signature is valid and get the address of the signer
    address signer = _verify(voucher);

    // make sure that the signer is authorized to mint NFTs
    require(minter() == signer, "Signature invalid or unauthorized");

    // cant mint more than max
    require(publicMintedCount + voucher.numberToMint <= maxPublicSupply, "max supply reached");

    // make sure that the redeemer is paying enough to cover the buyer's cost
    require(msg.value == 0.05 ether * voucher.numberToMint, "Insufficient funds to redeem");

    // make sure they didn't put in a negative number somehow...
    require(voucher.numberToMint > 0, "Must mint at least one NFT");

    // Make sure they can't mint more then 10 at once
    require(voucher.numberToMint <= 10, "Can't mint more than ten NFTs at a time");

    require(!hasBeenRedeemed(voucher.id), "Voucher has already been redeemed.");

    redeemedVouchers.push(voucher.id);

    // Set the tokenID to the last tokenID, we'll increment it before creating a new one in the loop below.
    uint256 tokenID = publicMintedCount;

    for (uint256 i = 0; i < voucher.numberToMint; i++) {
      tokenID++;

      // first assign the token to the signer, to establish provenance on-chain
      _mint(signer, tokenID);
      publicMintedCount += 1;
      
      // transfer the token to the redeemer
      _transfer(signer, msg.sender, tokenID);
    }
  }

  function tokenURI(uint256 tokenId) public view override returns (string memory) {
    require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");
    if (tokenId <= maxPublicSupply) {
      return string(abi.encodePacked(mainUri, tokenId.toString(), ".json"));
    }
    else {
      return string(abi.encodePacked(reservedUri, tokenId.toString(), ".json"));
    }
  }

  // Checks the list of redeemed voucher IDs to see if the voucherID specified is in there.
  function hasBeenRedeemed(uint256 voucherID) public view returns (bool) {
    for (uint256 i = 0; i < redeemedVouchers.length; i++) {
      if (redeemedVouchers[i] == voucherID) {
        return true;
      }
    }

    return false;
  }

  /// @notice Transfers all pending withdrawal balance to the caller. Reverts if the caller is not an authorized minter.
  function withdraw() public onlyOwner {
    payable(_msgSender()).transfer(address(this).balance);
  }

  function mintReserved() public onlyOwner returns (uint256)
  {
    require(reservedMintedCount < maxReservedSupply, "Max reserved supply reached.");

    uint256 tokenID = 4900 + reservedMintedCount + 1;

    _mint(owner(), tokenID);

    reservedMintedCount += 1;
    
    return tokenID;
  }

  /// @notice Returns a hash of the given NFTVoucher, prepared using EIP712 typed data hashing rules.
  /// @param voucher An NFTVoucher to hash.
  function _hash(NFTVoucher calldata voucher) internal view returns (bytes32) {
    return _hashTypedDataV4(keccak256(abi.encode(
      keccak256("NFTVoucher(uint256 id,uint256 numberToMint)"),
      voucher.id,
      voucher.numberToMint
    )));
  }

  /// @notice Returns the chain id of the current blockchain.
  /// @dev This is used to workaround an issue with ganache returning different values from the on-chain chainid() function and
  ///  the eth_chainId RPC method. See https://github.com/protocol/nft-website/issues/121 for context.
  function getChainID() external view returns (uint256) {
    uint256 id;
    assembly {
        id := chainid()
    }
    return id;
  }

  /// @notice Verifies the signature for a given NFTVoucher, returning the address of the signer.
  /// @dev Will revert if the signature is invalid. Does not verify that the signer is authorized to mint NFTs.
  /// @param voucher An NFTVoucher describing an unminted NFT.
  function _verify(NFTVoucher calldata voucher) internal view returns (address) {
    bytes32 digest = _hash(voucher);
    return ECDSA.recover(digest, voucher.signature);
  }
}
