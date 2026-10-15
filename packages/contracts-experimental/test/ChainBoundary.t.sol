// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
import {ExperimentalFactory} from '../src/ExperimentalFactory.sol';
import {ExperimentalC10Owner} from '../src/ExperimentalOwner.sol';
interface VmBoundary { function chainId(uint256) external; function expectRevert() external; function etch(address,bytes calldata) external; }
contract ChainBoundaryTest {
 VmBoundary constant vm=VmBoundary(address(uint160(uint256(keccak256('hevm cheat code')))));
 function testFactoryRejectsMainnetAndResearchChain() public {
  ExperimentalFactory.Dependency memory d=ExperimentalFactory.Dependency(address(1),bytes32(0));
  vm.chainId(1);vm.expectRevert();new ExperimentalFactory(d,d,d,d,d,d,bytes32(0));
  vm.chainId(31337);vm.expectRevert();new ExperimentalFactory(d,d,d,d,d,d,bytes32(0));
 }
 function testBoundOwnerStopsWorkingIfChainChanges() public {
  vm.chainId(11155111);vm.etch(address(0x1234),hex'00');
  ExperimentalC10Owner owner=new ExperimentalC10Owner(bytes32(uint256(1)<<128),bytes32(uint256(2)<<128),address(0x1234),address(0x1234).codehash,0);
  require(owner.dependenciesIntact());vm.chainId(1);require(!owner.dependenciesIntact());vm.chainId(31337);require(!owner.dependenciesIntact());
 }
}
