declare const BigNumber: any;
declare const expect: any;
declare const ethers: any;
declare const QtumWallet: any;
declare const QtumProvider: any;
declare const QtumContractFactory: any;
declare const generateContractAddress: any;
declare const provider: any;
declare const signer: any;
declare const signerNoQtum: any;
declare const ADOPTION_ABI: ({
    inputs: {
        internalType: string;
        name: string;
        type: string;
    }[];
    name: string;
    outputs: {
        internalType: string;
        name: string;
        type: string;
    }[];
    stateMutability: string;
    type: string;
    constant: boolean;
} | {
    inputs: {
        internalType: string;
        name: string;
        type: string;
    }[];
    name: string;
    outputs: {
        internalType: string;
        name: string;
        type: string;
    }[];
    stateMutability: string;
    type: string;
    constant?: undefined;
})[];
declare const ADOPTION_BYTECODE = "0x608060405234801561001057600080fd5b5061021c806100206000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c80633de4eb171461004657806343ae80d3146100645780638588b2c51461008f575b600080fd5b61004e6100b0565b60405161005b919061017c565b60405180910390f35b6100776100723660046101b7565b6100f6565b6040516001600160a01b03909116815260200161005b565b6100a261009d3660046101b7565b610116565b60405190815260200161005b565b6100b861015d565b604080516102008101918290529060009060109082845b81546001600160a01b031681526001909101906020018083116100cf575050505050905090565b6000816010811061010657600080fd5b01546001600160a01b0316905081565b6000600f82111561012657600080fd5b336000836010811061013a5761013a6101d0565b0180546001600160a01b0319166001600160a01b03929092169190911790555090565b6040518061020001604052806010906020820280368337509192915050565b6102008101818360005b60108110156101ae5781516001600160a01b0316835260209283019290910190600101610186565b50505092915050565b6000602082840312156101c957600080fd5b5035919050565b634e487b7160e01b600052603260045260246000fdfea264697066735822122030627c28006c8c423df956d43c0dfe9d3942dc066cfba338ceedb7aea227c2d264736f6c63430008090033";
