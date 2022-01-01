//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;
pragma abicoder v2; // required to accept structs as function parameters

import "hardhat/console.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract LazyNFT is ERC721URIStorage, EIP712, AccessControl, Ownable {

  bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
  bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
  string private constant SIGNING_DOMAIN = "LazyNFT-Voucher";
  string private constant SIGNATURE_VERSION = "1";
  string private constant oneOfOneReservedUri = "";
  string private constant mainUri = "";
  uint256 private constant maxSupply = 5000;
  uint256 private mintedCount = 0;
  uint256[] private redeemedVouchers;

  constructor(address payable minter)
    ERC721("LazyNFT", "LAZ") 
    EIP712(SIGNING_DOMAIN, SIGNATURE_VERSION) {
      _setupRole(MINTER_ROLE, minter);
      _setupRole(ADMIN_ROLE, msg.sender);
      _setRoleAdmin(MINTER_ROLE, ADMIN_ROLE);
    }
  /// @notice Represents an un-minted NFT, which has not yet been recorded into the blockchain. A signed voucher can be redeemed for a real NFT using the redeem function.
  struct NFTVoucher {
    /// @notice Voucher ID, used to keep track of which vouchers have been claimed, and prevent them from being used more than once.
    uint256 id;

    /// @notice The number of tokens to mint. 
    uint256 numberToMint;

    /// @notice The minimum price (in wei) that must be paid to mint EACH NFT. Total price will be minPrice * numberToMint
    uint256 minPrice;

    /// @notice the EIP-712 signature of all other fields in the NFTVoucher struct. For a voucher to be valid, it must be signed by an account with the MINTER_ROLE.
    bytes signature;
  }

  /// @notice Redeems an NFTVoucher for an actual NFT, creating it in the process.
  /// @param redeemer The address of the account which will receive the NFT upon success.
  /// @param voucher A signed NFTVoucher that describes the NFT to be redeemed.
  function redeem(address redeemer, NFTVoucher calldata voucher) public payable {
    // make sure signature is valid and get the address of the signer
    address signer = _verify(voucher);

    // make sure that the signer is authorized to mint NFTs
    require(hasRole(MINTER_ROLE, signer), "Signature invalid or unauthorized");

    // cant mint more than max
    require(mintedCount + voucher.numberToMint <= maxSupply, "max supply reached");

    // make sure that the redeemer is paying enough to cover the buyer's cost
    require(msg.value >= voucher.minPrice * voucher.numberToMint, "Insufficient funds to redeem");

    // make sure they didn't put in a negative number somehow...
    require(voucher.numberToMint > 0, "Must mint at least one NFT");

    // Make sure they can't mint more then 10 at once
    require(voucher.numberToMint <= 10, "Can't mint more than ten NFTs at a time");

    require(!hasBeenRedeemed(voucher.id), "Voucher has already been redeemed.");

    redeemedVouchers.push(voucher.id);

    // Set the tokenID to the last tokenID, we'll increment it before creating a new one in the loop below.
    uint256 tokenID = mintedCount;

    for (uint256 i = 0; i < voucher.numberToMint; i++) {
      tokenID++;

      // first assign the token to the signer, to establish provenance on-chain
      _mint(signer, tokenID);
      mintedCount += 1;
      _setTokenURI(tokenID, mainUri);
      
      // transfer the token to the redeemer
      _transfer(signer, redeemer, tokenID);
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
    payable(msg.sender).transfer(address(this).balance);
  }

  /// @notice Retuns the amount of Ether available to the caller to withdraw.
  function availableToWithdraw() public view returns (uint256) {
    return address(this).balance;
  }

  function addMinter(address account) public onlyOwner {
    grantRole(MINTER_ROLE, account);
  }

  function removeMinter(address account) public onlyOwner {
    revokeRole(MINTER_ROLE, account);
  }

  function mintOneOfOneReserved(uint256 tokenId) public onlyOwner returns (uint256)
  {
      _mint(owner(), tokenId);
      _setTokenURI(tokenId, oneOfOneReservedUri);
      return tokenId;
  }

  /// @notice Returns a hash of the given NFTVoucher, prepared using EIP712 typed data hashing rules.
  /// @param voucher An NFTVoucher to hash.
  function _hash(NFTVoucher calldata voucher) internal view returns (bytes32) {
    return _hashTypedDataV4(keccak256(abi.encode(
      keccak256("NFTVoucher(uint256 id, uint256 numberToMint,uint256 minPrice,string uri)"),
      voucher.id,
      voucher.numberToMint,
      voucher.minPrice
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

  function supportsInterface(bytes4 interfaceId) public view virtual override (AccessControl, ERC721) returns (bool) {
    return ERC721.supportsInterface(interfaceId) || AccessControl.supportsInterface(interfaceId);
  }
}
