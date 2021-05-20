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
const signer = new QtumWallet("99dda7e1a59655c9e02de8592be3b914df7df320e72ce04ccf0427f9a366ec6e", provider);
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
describe("QtumContractFactory", function () {
    it("QtumContractFactory should deploy correctly given the deployer has enough QTUM to cover gas", async function () {
        const simpleStore = new QtumContractFactory(ABI, BYTECODE, signer);
        const deployment = await simpleStore.deploy({
            gasLimit: "0x2dc6c0", gasPrice: "0x28"
        });
        expect(deployment.address).to.equal(`0x${generateContractAddress(deployment.deployTransaction.hash.split("0x")[1])}`);
        await deployment.deployed();
        const getVal = await deployment.get({
            gasLimit: "0x2dc6c0", gasPrice: "0x28"
        });
        expect(BigNumber.from(getVal).toNumber()).to.equal(BigNumber.from("0x00").toNumber());
        const setVal = await deployment.set(1001, {
            gasLimit: "0x2dc6c0", gasPrice: "0x28"
        });
        const result = await setVal.wait();
        console.log(setVal, 'setVal', result, 'result');
        expect(BigNumber.from(getVal).toNumber()).to.equal(BigNumber.from("0x00").toNumber());
    });
    it("QtumContractFactory can be connected to a QtumWallet signer.", async function () {
        const simpleStore = new QtumContractFactory(ABI, BYTECODE);
        const connectedSimpleStore = simpleStore.connect(signer);
        if (!!connectedSimpleStore.signer) {
            const deployment = await connectedSimpleStore.deploy({
                gasLimit: "0x2dc6c0",
                gasPrice: "0x28",
            });
            expect(!!deployment.address, "true");
            await deployment.deployed();
            const getVal = await deployment.get({
                gasLimit: "0x2dc6c0", gasPrice: "0x28"
            });
            expect(BigNumber.from(getVal).toNumber()).to.equal(BigNumber.from("0x00").toNumber());
        }
    });
    // it("QtumContractFactory should reject if the deployer tries sending a value", async function () {
    //     const simpleStore = new QtumContractFactory(ABI, BYTECODE, signer);
    //     try {
    //         await simpleStore.deploy({
    //             gasLimit: "0x2dc6c0", gasPrice: "0x28", value: "0xffffff"
    //         });
    //     } catch (err) {
    //         expect(err.reason).to.equal("You cannot send QTUM while deploying a contract. Try deploying again without a value.")
    //     }
    // });
    // it("QtumContractFactory should fail as the deployer has no UTXOs to spend", async function () {
    //     const simpleStore = new QtumContractFactory(ABI, BYTECODE, signerNoQtum);
    //     try {
    //         await simpleStore.deploy({
    //             gasLimit: "0x2dc6c0", gasPrice: "0x28"
    //         });
    //     } catch (err) {
    //         expect(err.reason).to.equal("Needed amount of UTXO's exceed the total you own.")
    //     }
    // });
});
describe("QtumWallet", function () {
    // it("QtumWallet can send valid transactions to hash160 addresses", async function () {
    //     // sending to 0x7926223070547D2D15b2eF5e7383E541c338FfE9
    //     // const simulateSendTo = await signer.sendTransaction({
    //     //     to: "0x7926223070547D2D15b2eF5e7383E541c338FfE9",
    //     //     from: signer.address,
    //     //     gasLimit: "0x3d090",
    //     //     gasPrice: "0x28",
    //     //     value: "0xfffff",
    //     //     data: "",
    //     // });
    //     expect(true, "true")
    //     // const result = await simulateSendTo.wait()
    //     // console.log(result)
    // });
    // it("QtumWallet can call getAddress method with a valid private key provided to the signer", async function () {
    //     const address = await signer.getAddress();
    //     expect(address).to.equal(signer.address)
    // });
    // it("QtumWallet can connect to SimpleBank and call a payable method", async function () {
    //     const simpleBank = new QtumContractFactory(SIMPLEBANK_ABI, SIMPLEBANK_BYTECODE, signer);
    //     const deployment = await simpleBank.deploy({
    //         gasLimit: "0x2dc6c0", gasPrice: "0x28"
    //     });
    //     expect(deployment.address).to.equal(`0x${generateContractAddress(deployment.deployTransaction.hash.split("0x")[1])}`)
    //     await deployment.deployed();
    //     // console.log(deployment)
    //     const deposit = await deployment.deposit({
    //         gasLimit: "0x2dc6c0", gasPrice: "0x28", value: "0xfffff"
    //     });
    //     await deposit.wait()
    //     console.log(deposit, 'deposit')
    // });
    // it("QtumWallet can connect to QRC20 ", async function () {
    //     const simpleBank = new QtumContractFactory(QRC20_ABI, QRC20_BYTECODE, signer);
    //     const deployment = await simpleBank.deploy({
    //         gasLimit: "0x2dc6c0", gasPrice: "0x28"
    //     });
    //     console.log(`0x${generateContractAddress(deployment.deployTransaction.hash.split("0x")[1])}`)
    //     expect(deployment.address).to.equal(`0x${generateContractAddress(deployment.deployTransaction.hash.split("0x")[1])}`)
    //     await deployment.deployed();
    //     // console.log(deployed.address)
    //     // console.log(deployment)
    //     const deposit = await deployment.name({ gasLimit: "0x2dc6c0", gasPrice: "0x28"});
    //     console.log(deposit)
    // });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ29udHJhY3RGYWN0b3J5LVdhbGxldC1Qcm92aWRlci50ZXN0cy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy90ZXN0cy9Db250cmFjdEZhY3RvcnktV2FsbGV0LVByb3ZpZGVyLnRlc3RzLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxNQUFNLEVBQUUsU0FBUyxFQUFFLEdBQUcsT0FBTyxDQUFDLDBCQUEwQixDQUFDLENBQUM7QUFDMUQsTUFBTSxFQUFFLE1BQU0sRUFBRSxHQUFHLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQztBQUNuQyxNQUFNLEVBQUUsTUFBTSxFQUFFLEdBQUcsT0FBTyxDQUFDLFFBQVEsQ0FBQyxDQUFBO0FBQ3BDLE1BQU0sRUFBRSxVQUFVLEVBQUUsR0FBRyxPQUFPLENBQUMsaUNBQWlDLENBQUMsQ0FBQztBQUNsRSxNQUFNLEVBQUUsWUFBWSxFQUFFLEdBQUcsT0FBTyxDQUFDLG1DQUFtQyxDQUFDLENBQUM7QUFDdEUsTUFBTSxFQUNGLG1CQUFtQixHQUN0QixHQUFHLE9BQU8sQ0FBQywwQ0FBMEMsQ0FBQyxDQUFDO0FBQ3hELE1BQU0sRUFBRSx1QkFBdUIsRUFBRSxHQUFHLE9BQU8sQ0FBQyxvQ0FBb0MsQ0FBQyxDQUFBO0FBQ2pGLE1BQU0sUUFBUSxHQUFHLHNlQUFzZSxDQUFBO0FBQ3ZmLE1BQU0sR0FBRyxHQUFHLENBQUMsRUFBRSxRQUFRLEVBQUUsRUFBRSxFQUFFLE1BQU0sRUFBRSxLQUFLLEVBQUUsU0FBUyxFQUFFLENBQUMsRUFBRSxjQUFjLEVBQUUsU0FBUyxFQUFFLE1BQU0sRUFBRSxFQUFFLEVBQUUsTUFBTSxFQUFFLFNBQVMsRUFBRSxDQUFDLEVBQUUsaUJBQWlCLEVBQUUsTUFBTSxFQUFFLE1BQU0sRUFBRSxVQUFVLEVBQUUsRUFBRSxFQUFFLFFBQVEsRUFBRSxDQUFDLEVBQUUsY0FBYyxFQUFFLFNBQVMsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLE1BQU0sRUFBRSxT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