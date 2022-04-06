import {
    resolveProperties,
    Logger,
} from "ethers/lib/utils";
import { Provider, TransactionRequest } from "@ethersproject/abstract-provider";
import { BigNumber } from "bignumber.js"
import { BigNumber as BigNumberEthers } from "ethers";
import { checkTransactionType, serializeTransaction } from './helpers/utils'
import { GLOBAL_VARS } from './helpers/global-vars'
import { IntermediateWallet } from './helpers/IntermediateWallet'
import { computeAddress} from "./helpers/utils"
import { defineReadOnly } from "@ethersproject/properties";
import { decryptJsonWallet, decryptJsonWalletSync, ProgressCallback } from "@ethersproject/json-wallets";
import { HDNode, entropyToMnemonic } from "@ethersproject/hdnode";
import { arrayify, Bytes, concat, hexDataSlice } from "@ethersproject/bytes";
import { randomBytes } from "@ethersproject/random";
import { keccak256 } from "@ethersproject/keccak256";
import { Wordlist } from "@ethersproject/wordlists";

const logger = new Logger("QtumWallet");
const forwardErrors = [
    Logger.errors.INSUFFICIENT_FUNDS
];

const minimumGasPriceInGwei = "0x9502f9000";
const minimumGasPriceInWei = "0x5d21dba000";

// Qtum core wallet and electrum use coin 88
export const QTUM_BIP44_PATH = "m/44'/88'/0'/0/0";
// Other wallets use coin 2301
// for more details, see: https://github.com/satoshilabs/slips/pull/196
export const SLIP_BIP44_PATH = "m/44'/2301'/0'/0/0";
export const defaultPath = SLIP_BIP44_PATH;

// @ts-ignore
function warn(a?, b?, c?, d?, e?, f?, g?) {
    try {
        // @ts-ignore
        console.warn.apply(this, arguments);
    } catch (e) {

    }
}

// @ts-ignore
function log(a?, b?, c?, d?, e?, f?, g?) {
    try {
        // @ts-ignore
        console.log.apply(this, arguments);
    } catch (e) {

    }
}

export class QtumWallet extends IntermediateWallet {

    constructor(privateKey: any, provider?: any) {
        super(privateKey, provider);
    }

    protected async serializeTransaction(utxos: Array<any>, neededAmount: string, tx: TransactionRequest, transactionType: number): Promise<string> {
        return await serializeTransaction(utxos, neededAmount, tx, transactionType, this.privateKey, this.compressedPublicKey);
    }

    /**
     * Override to build a raw QTUM transaction signing UTXO's
     */
    async signTransaction(transaction: TransactionRequest): Promise<string> {
        let gasBugFixed = true;
        // @ts-ignore
        if (this.provider.isClientVersionGreaterThanEqualTo) {
            // @ts-ignore
            gasBugFixed = await this.provider.isClientVersionGreaterThanEqualTo(0, 2, 0);
        } else {
            throw new Error("Must use QtumProvider");
        }

        const augustFirst2022 = 1659330000000;
        const now = new Date().getTime();
        const requireFixedJanus = now > augustFirst2022;
        const message = "You are using an outdated version of Janus that has a bug that qtum-ethers-wrapper works around, " +
            "please upgrade your Janus instance and if you have hardcoded gas price in your dapp to update it to " +
            minimumGasPriceInWei + " - if you use eth_gasPrice then nothing else should be required other than updating Janus. " +
            "this message will become an error August 1st 2022 when using Janus instances lower than version 0.2.0";
        if (!gasBugFixed) {
            if (requireFixedJanus) {
                throw new Error(message);
            } else {
                warn(message);
            }
        } else {
            warn("gas bug is fixed in this janus release")
        }

        log("tx", transaction.gasPrice?.toString());

        if (!transaction.gasPrice) {
            log("no gas price....")
            let gasPrice = minimumGasPriceInWei;
            if (!gasBugFixed) {
                gasPrice = minimumGasPriceInGwei;
            }
            // 40 satoshi in WEI
            // 40 => 40000000000
            // transaction.gasPrice = "0x9502f9000";
            // 40 => 400000000000
            // transaction.gasPrice = "0x5d21dba000";
            transaction.gasPrice = gasPrice;
        } else if (gasBugFixed) {
            log("gas bug fixed...")
            if (requireFixedJanus) {
                log("require fixed janus....")
                // no work arounds after aug 1st 2022, worst case: this just means increased gas prices (10x) and shouldn't cause any other issues
                if (transaction.gasPrice  === minimumGasPriceInGwei) {
                    log("modifying gas price...")
                    // hardcoded 400 gwei gas price
                    // adjust it to be the proper amount and log an error
                    transaction.gasPrice = minimumGasPriceInWei;
                    warn("Corrected gas price from 400 gwei to 40 wei, update your dapp to use the correct gas price");
                }
            }
        } else {
            log("gas supplied: ", transaction.gasPrice, " no fix required")
        }

        const gasPriceExponent = gasBugFixed ? 'e-10' : 'e-9'
        // convert gasPrice into satoshi
        let gasPrice = new BigNumber(BigNumberEthers.from(transaction.gasPrice).toString() + gasPriceExponent);
        transaction.gasPrice = gasPrice.toNumber();
        log("tx.gasPrice = ", transaction.gasPrice)

        const tx = await resolveProperties(transaction);

        // Refactored to check TX type (call, create, p2pkh, deploy error) and calculate needed amount
        const { transactionType, neededAmount } = checkTransactionType(tx);

        // Check if the transactionType matches the DEPLOY_ERROR, throw error else continue
        if (transactionType === GLOBAL_VARS.DEPLOY_ERROR) {
            return logger.throwError(
                "You cannot send QTUM while deploying a contract. Try deploying again without a value.",
                Logger.errors.NOT_IMPLEMENTED,
                {
                    error: "You cannot send QTUM while deploying a contract. Try deploying again without a value.",
                }
            );
        }

        let utxos = [];
        try {
            // @ts-ignore
            utxos = await this.provider.getUtxos(tx.from, neededAmount);
            // Grab vins for transaction object.
        } catch (error: any) {
            if (forwardErrors.indexOf(error.code) >= 0) {
                throw error;
            }
            return logger.throwError(
                "Needed amount of UTXO's exceed the total you own.",
                Logger.errors.INSUFFICIENT_FUNDS,
                {
                    error: error,
                }
            );
        }

        return await this.serializeTransaction(utxos, neededAmount, tx, transactionType);
    }

    connect(provider: Provider): IntermediateWallet {
        return new QtumWallet(this, provider);
    }

    /**
     *  Static methods to create Wallet instances.
     */
    static createRandom(options?: any): IntermediateWallet {
        let entropy: Uint8Array = randomBytes(16);

        if (!options) { options = { }; }

        if (options.extraEntropy) {
            entropy = arrayify(hexDataSlice(keccak256(concat([ entropy, options.extraEntropy ])), 0, 16));
        }

        const mnemonic = entropyToMnemonic(entropy, options.locale);
        return QtumWallet.fromMnemonic(mnemonic, options.path, options.locale);
    }

    static fromEncryptedJson(json: string, password: Bytes | string, progressCallback?: ProgressCallback): Promise<IntermediateWallet> {
        return decryptJsonWallet(json, password, progressCallback).then((account) => {
            return new QtumWallet(account);
        });
    }

    static fromEncryptedJsonSync(json: string, password: Bytes | string): IntermediateWallet {
        return new QtumWallet(decryptJsonWalletSync(json, password));
    }

    /**
     * Create a QtumWallet from a BIP44 mnemonic
     * @param mnemonic
     * @param path QTUM uses two different derivation paths and recommends SLIP_BIP44_PATH for external wallets, core wallets use QTUM_BIP44_PATH
     * @param wordlist
     * @returns
     */
    static fromMnemonic(mnemonic: string, path?: string, wordlist?: Wordlist): IntermediateWallet {
        if (!path) { path = defaultPath; }
        const hdnode = HDNode.fromMnemonic(mnemonic, "", wordlist).derivePath(path)
        // QTUM computes address from the public key differently than ethereum, ethereum uses keccak256 while QTUM uses ripemd160(sha256(compressedPublicKey))
        // @ts-ignore
        defineReadOnly(hdnode, "qtumAddress", computeAddress(hdnode.publicKey, true));
        return new QtumWallet(hdnode);
    }
}