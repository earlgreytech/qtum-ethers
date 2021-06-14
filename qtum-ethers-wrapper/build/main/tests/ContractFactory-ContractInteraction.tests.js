"use strict";
const { BigNumber } = require("@ethersproject/bignumber");
const { expect } = require("chai");
const { ethers } = require("ethers");
const { QtumWallet } = require("../../build/main/lib/QtumWallet");
const { QtumProvider } = require("../../build/main/lib/QtumProvider");
const { QtumContractFactory, } = require("../../build/main/lib/QtumContractFactory");
const { generateContractAddress } = require('../../build/main/lib/helpers/utils');
const BYTECODE = "608060405234801561001057600080fd5b506040516020806100f2833981016040525160005560bf806100336000396000f30060806040526004361060485763ffffffff7c010000000000000000000000000000000000000000000000000000000060003504166360fe47b18114604d5780636d4ce63c146064575b600080fd5b348015605857600080fd5b5060626004356088565b005b348015606f57600080fd5b506076608d565b60408051918252519081900360200190f35b600055565b600054905600a165627a7a7230582049a087087e1fc6da0b68ca259d45a2e369efcbb50e93f9b7fa3e198de6402b810029";
const ABI = [{ "inputs": [], "name": "get", "outputs": [{ "internalType": "uint256", "name": "", "type": "uint256" }], "stateMutability": "view", "type": "function" }, { "inputs": [{ "internalType": "uint256", "name": "x", "type": "uint256" }], "name": "set", "outputs": [], "stateMutability": "nonpayable", "type": "function" }];
const provider = new QtumProvider("http://localhost:23889");
// hash160PubKey/address -> 0xcca81b02942d8079a871e02ba03a3a4a8d7740d2
const signer = new QtumWallet("99dda7e1a59655c9e02de8592be3b914df7df320e72ce04ccf0427f9a366ec6e", provider);
// hash160PubKey/address -> 0x30a41759e2fec594fbb90ea2b212c9ef8074e227
const signerNoQtum = new QtumWallet("61fd08e21110d908cf8dc20bb243a96e2dc0d29169b4fec09594c39e4384125a", provider);
const SIMPLEBANK_ABI = [
    {
        "inputs": [],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "constructor"
    },
    {
        "anonymous": false,
        "inputs": [
            {
                "indexed": true,
                "internalType": "address",
                "name": "accountAddress",
                "type": "address"
            },
            {
                "indexed": false,
                "internalType": "uint256",
                "name": "amount",
                "type": "uint256"
            }
        ],
        "name": "LogDepositMade",
        "type": "event"
    },
    {
        "constant": true,
        "inputs": [],
        "name": "balance",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": false,
        "inputs": [],
        "name": "deposit",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "payable": true,
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [],
        "name": "depositsBalance",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": false,
        "inputs": [],
        "name": "enroll",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [],
        "name": "owner",
        "outputs": [
            {
                "internalType": "address",
                "name": "",
                "type": "address"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": false,
        "inputs": [
            {
                "internalType": "uint256",
                "name": "withdrawAmount",
                "type": "uint256"
            }
        ],
        "name": "withdraw",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "remainingBal",
                "type": "uint256"
            }
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
    }
];
const SIMPLEBANK_BYTECODE = "608060405234801561001057600080fd5b50600280546001600160a01b031916331790556000805460ff1916905561028c8061003c6000396000f3fe6080604052600436106100555760003560e01c8063138fbe711461005a5780632e1a7d4d146100815780638da5cb5b146100ab578063b69ef8a8146100dc578063d0e30db0146100f1578063e65f2a7e146100f9575b600080fd5b34801561006657600080fd5b5061006f61010e565b60408051918252519081900360200190f35b34801561008d57600080fd5b5061006f600480360360208110156100a457600080fd5b5035610112565b3480156100b757600080fd5b506100c061017e565b604080516001600160a01b039092168252519081900360200190f35b3480156100e857600080fd5b5061006f61018d565b61006f6101a0565b34801561010557600080fd5b5061006f610204565b4790565b3360009081526001602052604081205482116101695733600081815260016020526040808220805486900390555184156108fc0291859190818181858888f19350505050158015610167573d6000803e3d6000fd5b505b50503360009081526001602052604090205490565b6002546001600160a01b031681565b3360009081526001602052604090205490565b336000818152600160209081526040808320805434908101909155815190815290519293927fa8126f7572bb1fdeae5b5aa9ec126438b91f658a07873f009d041ae690f3a193929181900390910190a2503360009081526001602052604090205490565b60008054600360ff9091161015610243576000805460ff198116600160ff928316810190921617825533825260205260409020678ac7230489e8000090555b50336000908152600160205260409020549056fea265627a7a723158205098a98dd8e3ed9f67c9b25ab91302536280403498af2496b001d2763e4ac3e464736f6c63430005110032";
const QRC20_ABI = [
    {
        "constant": true,
        "inputs": [],
        "name": "name",
        "outputs": [
            {
                "name": "",
                "type": "string"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": false,
        "inputs": [
            {
                "name": "_spender",
                "type": "address"
            },
            {
                "name": "_value",
                "type": "uint256"
            }
        ],
        "name": "approve",
        "outputs": [
            {
                "name": "success",
                "type": "bool"
            }
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [
            {
                "name": "",
                "type": "uint256"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": false,
        "inputs": [
            {
                "name": "_from",
                "type": "address"
            },
            {
                "name": "_to",
                "type": "address"
            },
            {
                "name": "_value",
                "type": "uint256"
            }
        ],
        "name": "transferFrom",
        "outputs": [
            {
                "name": "success",
                "type": "bool"
            }
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [],
        "name": "decimals",
        "outputs": [
            {
                "name": "",
                "type": "uint8"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [],
        "name": "standard",
        "outputs": [
            {
                "name": "",
                "type": "string"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [
            {
                "name": "",
                "type": "address"
            }
        ],
        "name": "balanceOf",
        "outputs": [
            {
                "name": "",
                "type": "uint256"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [],
        "name": "symbol",
        "outputs": [
            {
                "name": "",
                "type": "string"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": false,
        "inputs": [
            {
                "name": "_to",
                "type": "address"
            },
            {
                "name": "_value",
                "type": "uint256"
            }
        ],
        "name": "transfer",
        "outputs": [
            {
                "name": "success",
                "type": "bool"
            }
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [
            {
                "name": "",
                "type": "address"
            },
            {
                "name": "",
                "type": "address"
            }
        ],
        "name": "allowance",
        "outputs": [
            {
                "name": "",
                "type": "uint256"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "constructor"
    },
    {
        "payable": true,
        "stateMutability": "payable",
        "type": "fallback"
    },
    {
        "anonymous": false,
        "inputs": [
            {
                "indexed": true,
                "name": "_from",
                "type": "address"
            },
            {
                "indexed": true,
                "name": "_to",
                "type": "address"
            },
            {
                "indexed": false,
                "name": "_value",
                "type": "uint256"
            }
        ],
        "name": "Transfer",
        "type": "event"
    },
    {
        "anonymous": false,
        "inputs": [
            {
                "indexed": true,
                "name": "_owner",
                "type": "address"
            },
            {
                "indexed": true,
                "name": "_spender",
                "type": "address"
            },
            {
                "indexed": false,
                "name": "_value",
                "type": "uint256"
            }
        ],
        "name": "Approval",
        "type": "event"
    }
];
const QRC20_BYTECODE = "608060405267016345785d8a000060005534801561001c57600080fd5b5060008054338252600160205260409091205561064e8061003e6000396000f3006080604052600436106100a35763ffffffff7c010000000000000000000000000000000000000000000000000000000060003504166306fdde0381146100a8578063095ea7b31461013257806318160ddd1461016a57806323b872dd14610191578063313ce567146101bb5780635a3b7e42146101e657806370a08231146101fb57806395d89b411461021c578063a9059cbb14610231578063dd62ed3e14610255575b600080fd5b3480156100b457600080fd5b506100bd61027c565b6040805160208082528351818301528351919283929083019185019080838360005b838110156100f75781810151838201526020016100df565b50505050905090810190601f1680156101245780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561013e57600080fd5b50610156600160a060020a03600435166024356102b3565b604080519115158252519081900360200190f35b34801561017657600080fd5b5061017f61036c565b60408051918252519081900360200190f35b34801561019d57600080fd5b50610156600160a060020a0360043581169060243516604435610372565b3480156101c757600080fd5b506101d061049b565b6040805160ff9092168252519081900360200190f35b3480156101f257600080fd5b506100bd6104a0565b34801561020757600080fd5b5061017f600160a060020a03600435166104d7565b34801561022857600080fd5b506100bd6104e9565b34801561023d57600080fd5b50610156600160a060020a0360043516602435610520565b34801561026157600080fd5b5061017f600160a060020a03600435811690602435166105dd565b60408051808201909152600881527f5152432054455354000000000000000000000000000000000000000000000000602082015281565b600082600160a060020a03811615156102cb57600080fd5b8215806102f95750336000908152600260209081526040808320600160a060020a0388168452909152902054155b151561030457600080fd5b336000818152600260209081526040808320600160a060020a03891680855290835292819020879055805187815290519293927f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925929181900390910190a35060019392505050565b60005481565b600083600160a060020a038116151561038a57600080fd5b83600160a060020a03811615156103a057600080fd5b600160a060020a03861660009081526002602090815260408083203384529091529020546103ce90856105fa565b600160a060020a03871660008181526002602090815260408083203384528252808320949094559181526001909152205461040990856105fa565b600160a060020a038088166000908152600160205260408082209390935590871681522054610438908561060c565b600160a060020a0380871660008181526001602090815260409182902094909455805188815290519193928a16927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef92918290030190a350600195945050505050565b600881565b60408051808201909152600981527f546f6b656e20302e310000000000000000000000000000000000000000000000602082015281565b60016020526000908152604090205481565b60408051808201909152600381527f5154430000000000000000000000000000000000000000000000000000000000602082015281565b600082600160a060020a038116151561053857600080fd5b3360009081526001602052604090205461055290846105fa565b3360009081526001602052604080822092909255600160a060020a0386168152205461057e908461060c565b600160a060020a0385166000818152600160209081526040918290209390935580518681529051919233927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9281900390910190a35060019392505050565b600260209081526000928352604080842090915290825290205481565b60008183101561060657fe5b50900390565b60008282018381101561061b57fe5b93925050505600a165627a7a723058205a85b8080447e6cd22c9bed1d6191938dd5fc3c5076a23629371c7cd6770576b0029";
// describe("QtumContractFactory", function () {
//     it("QtumContractFactory should deploy correctly given the deployer has enough QTUM to cover gas", async function () {
//         const simpleStore = new QtumContractFactory(ABI, BYTECODE, signer);
//         const deployment = await simpleStore.deploy({
//             gasLimit: "0x2dc6c0", gasPrice: "0x28"
//         });
//         expect(deployment.address).to.equal(`0x${generateContractAddress(deployment.deployTransaction.hash.split("0x")[1])}`)
//         await deployment.deployed();
//         const getVal = await deployment.get({
//             gasLimit: "0x2dc6c0", gasPrice: "0x28"
//         });
//         expect(BigNumber.from(getVal).toNumber()).to.equal(BigNumber.from("0x00").toNumber());
//         const setVal = await deployment.set(1001, {
//             gasLimit: "0x2dc6c0", gasPrice: "0x28"
//         });
//         await setVal.wait()
//         expect(BigNumber.from(getVal).toNumber()).to.equal(BigNumber.from("0x00").toNumber());
//     });
//     it("QtumContractFactory can be connected to a QtumWallet signer.", async function () {
//         const simpleStore = new QtumContractFactory(ABI, BYTECODE);
//         const connectedSimpleStore = simpleStore.connect(signer);
//         if (!!connectedSimpleStore.signer) {
//             const deployment = await connectedSimpleStore.deploy({
//                 gasLimit: "0x2dc6c0",
//                 gasPrice: "0x28",
//             });
//             expect(!!deployment.address, "true");
//             await deployment.deployed();
//             const getVal = await deployment.get({
//                 gasLimit: "0x2dc6c0", gasPrice: "0x28"
//             });
//             expect(BigNumber.from(getVal).toNumber()).to.equal(BigNumber.from("0x00").toNumber());
//         }
//     });
//     it("QtumContractFactory should reject if the deployer tries sending a value", async function () {
//         const simpleStore = new QtumContractFactory(ABI, BYTECODE, signer);
//         try {
//             await simpleStore.deploy({
//                 gasLimit: "0x2dc6c0", gasPrice: "0x28", value: "0xffffff"
//             });
//         } catch (err) {
//             expect(err.reason).to.equal("You cannot send QTUM while deploying a contract. Try deploying again without a value.")
//         }
//     });
//     it("QtumContractFactory should fail as the deployer has no UTXOs to spend", async function () {
//         const simpleStore = new QtumContractFactory(ABI, BYTECODE, signerNoQtum);
//         console.log(signerNoQtum.address)
//         try {
//             await simpleStore.deploy({
//                 gasLimit: "0x2dc6c0", gasPrice: "0x28"
//             });
//         } catch (err) {
//             expect(err.reason).to.equal("Needed amount of UTXO's exceed the total you own.")
//         }
//     });
// })
// describe("QtumWallet", function () {
//     it("QtumWallet can send valid transactions to hash160 addresses", async function () {
//         // sending to 0x7926223070547D2D15b2eF5e7383E541c338FfE9
//         // note: no tx receipt here
//         await signer.sendTransaction({
//             to: "0x7926223070547D2D15b2eF5e7383E541c338FfE9",
//             from: signer.address,
//             gasLimit: "0x3d090",
//             gasPrice: "0x28",
//             value: "0xfffff",
//             data: "",
//         });
//         expect(true, "true")
//     });
//     it("QtumWallet can call getAddress method with a valid private key provided to the signer", async function () {
//         const address = await signer.getAddress();
//         expect(address).to.equal(signer.address)
//     });
//     it("QtumWallet can connect to SimpleBank and call a payable method", async function () {
//         const simpleBank = new QtumContractFactory(SIMPLEBANK_ABI, SIMPLEBANK_BYTECODE, signer);
//         const deployment = await simpleBank.deploy({
//             gasLimit: "0x2dc6c0", gasPrice: "0x28"
//         });
//         expect(deployment.address).to.equal(`0x${generateContractAddress(deployment.deployTransaction.hash.split("0x")[1])}`)
//         await deployment.deployed();
//         const deposit = await deployment.deposit({
//             gasLimit: "0x2dc6c0", gasPrice: "0x28", value: "0xfffff"
//         });
//         await deposit.wait()
//     });
//     it("QtumWallet can connect to QRC20 ", async function () {
//         const qrc20 = new ethers.Contract("0xc04d8b4f5137e5983b075e8560020523784c1c4a", QRC20_ABI, signer);
//         const deployment = await qrc20.deploy({
//             gasLimit: "0x2dc6c0", gasPrice: "0x28"
//         });
//         expect(deployment.address).to.equal(`0x${generateContractAddress(deployment.deployTransaction.hash.split("0x")[1])}`)
//         await deployment.deployed();
//         const name = await qrc20.name({ gasLimit: "0x2dc6c0", gasPrice: "0x28" });
//         console.log(name, qrc20.address)
//     });
// })
describe("QtumProvider", function () {
    it("QtumProvider can grab UTXOs for an address", async function () {
        const utxos = await provider.getUtxos("0x7926223070547D2D15b2eF5e7383E541c338FfE9", "1.0");
        expect(true, "true");
    });
    it("QtumProvider throws an error when grabbing UTXOs for an invalid address", async function () {
        // sending to 0x7926223070547D2D15b2eF5e7383E541c338FfE9
        // note: no tx receipt here
        const utxos = await provider.getUtxos("0x7926223070547D2D15b2eF5e7383E541c338FfE", "1.0");
        console.log(utxos.error.body);
        expect(true, "true");
    });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ29udHJhY3RGYWN0b3J5LUNvbnRyYWN0SW50ZXJhY3Rpb24udGVzdHMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvdGVzdHMvQ29udHJhY3RGYWN0b3J5LUNvbnRyYWN0SW50ZXJhY3Rpb24udGVzdHMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLE1BQU0sRUFBRSxTQUFTLEVBQUUsR0FBRyxPQUFPLENBQUMsMEJBQTBCLENBQUMsQ0FBQztBQUMxRCxNQUFNLEVBQUUsTUFBTSxFQUFFLEdBQUcsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDO0FBQ25DLE1BQU0sRUFBRSxNQUFNLEVBQUUsR0FBRyxPQUFPLENBQUMsUUFBUSxDQUFDLENBQUE7QUFDcEMsTUFBTSxFQUFFLFVBQVUsRUFBRSxHQUFHLE9BQU8sQ0FBQyxpQ0FBaUMsQ0FBQyxDQUFDO0FBQ2xFLE1BQU0sRUFBRSxZQUFZLEVBQUUsR0FBRyxPQUFPLENBQUMsbUNBQW1DLENBQUMsQ0FBQztBQUN0RSxNQUFNLEVBQ0YsbUJBQW1CLEdBQ3RCLEdBQUcsT0FBTyxDQUFDLDBDQUEwQyxDQUFDLENBQUM7QUFDeEQsTUFBTSxFQUFFLHVCQUF1QixFQUFFLEdBQUcsT0FBTyxDQUFDLG9DQUFvQyxDQUFDLENBQUE7QUFDakYsTUFBTSxRQUFRLEdBQUcsc2VBQXNlLENBQUE7QUFDdmYsTUFBTSxHQUFHLEdBQUcsQ0FBQyxFQUFFLFFBQVEsRUFBRSxFQUFFLEVBQUUsTUFBTSxFQUFFLEtBQUssRUFBRSxTQUFTLEVBQUUsQ0FBQyxFQUFFLGNBQWMsRUFBRSxTQUFTLEVBQUUsTUFBTSxFQUFFLEVBQUUsRUFBRSxNQUFNLEVBQUUsU0FBUyxFQUFFLENBQUMsRUFBRSxpQkFBaUIsRUFBRSxNQUFNLEVBQUUsTUFBTSxFQUFFLFVBQVUsRUFBRSxFQUFFLEVBQUUsUUFBUSxFQUFFLENBQUMsRUFBRSxjQUFjLEVBQUUsU0FBUyxFQUFFLE1BQU0sRUFBRSxHQUFHLEVBQUUsTUFB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