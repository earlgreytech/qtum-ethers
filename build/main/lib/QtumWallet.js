"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.QtumWallet = exports.defaultPath = exports.SLIP_BIP44_PATH = exports.QTUM_BIP44_PATH = void 0;
const utils_1 = require("ethers/lib/utils");
const bignumber_js_1 = require("bignumber.js");
const ethers_1 = require("ethers");
const utils_2 = require("./helpers/utils");
const global_vars_1 = require("./helpers/global-vars");
const IntermediateWallet_1 = require("./helpers/IntermediateWallet");
const utils_3 = require("./helpers/utils");
const properties_1 = require("@ethersproject/properties");
const json_wallets_1 = require("@ethersproject/json-wallets");
const hdnode_1 = require("@ethersproject/hdnode");
const bytes_1 = require("@ethersproject/bytes");
const random_1 = require("@ethersproject/random");
const keccak256_1 = require("@ethersproject/keccak256");
const logger = new utils_1.Logger("QtumWallet");
const forwardErrors = [
    utils_1.Logger.errors.INSUFFICIENT_FUNDS
];
const minimumGasPriceInGwei = "0x9502f9000";
const minimumGasPriceInWei = "0x5d21dba000";
// Qtum core wallet and electrum use coin 88
exports.QTUM_BIP44_PATH = "m/44'/88'/0'/0/0";
// Other wallets use coin 2301
// for more details, see: https://github.com/satoshilabs/slips/pull/196
exports.SLIP_BIP44_PATH = "m/44'/2301'/0'/0/0";
exports.defaultPath = exports.SLIP_BIP44_PATH;
// @ts-ignore
function warn(a, b, c, d, e, f, g) {
    try {
        // @ts-ignore
        console.warn.apply(this, arguments);
    }
    catch (e) {
    }
}
// @ts-ignore
function log(a, b, c, d, e, f, g) {
    try {
        // @ts-ignore
        console.log.apply(this, arguments);
    }
    catch (e) {
    }
}
class QtumWallet extends IntermediateWallet_1.IntermediateWallet {
    constructor(privateKey, provider) {
        super(privateKey, provider);
    }
    async serializeTransaction(utxos, neededAmount, tx, transactionType) {
        return await utils_2.serializeTransaction(utxos, neededAmount, tx, transactionType, this.privateKey, this.compressedPublicKey);
    }
    /**
     * Override to build a raw QTUM transaction signing UTXO's
     */
    async signTransaction(transaction) {
        var _a;
        let gasBugFixed = true;
        // @ts-ignore
        if (this.provider.isClientVersionGreaterThanEqualTo) {
            // @ts-ignore
            gasBugFixed = await this.provider.isClientVersionGreaterThanEqualTo(0, 2, 0);
        }
        else {
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
            }
            else {
                warn(message);
            }
        }
        else {
            warn("gas bug is fixed in this janus release");
        }
        log("tx", (_a = transaction.gasPrice) === null || _a === void 0 ? void 0 : _a.toString());
        if (!transaction.gasPrice) {
            log("no gas price....");
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
        }
        else if (gasBugFixed) {
            log("gas bug fixed...");
            if (requireFixedJanus) {
                log("require fixed janus....");
                // no work arounds after aug 1st 2022, worst case: this just means increased gas prices (10x) and shouldn't cause any other issues
                if (transaction.gasPrice === minimumGasPriceInGwei) {
                    log("modifying gas price...");
                    // hardcoded 400 gwei gas price
                    // adjust it to be the proper amount and log an error
                    transaction.gasPrice = minimumGasPriceInWei;
                    warn("Corrected gas price from 400 gwei to 40 wei, update your dapp to use the correct gas price");
                }
            }
        }
        else {
            log("gas supplied: ", transaction.gasPrice, " no fix required");
        }
        const gasPriceExponent = gasBugFixed ? 'e-10' : 'e-9';
        // convert gasPrice into satoshi
        let gasPrice = new bignumber_js_1.BigNumber(ethers_1.BigNumber.from(transaction.gasPrice).toString() + gasPriceExponent);
        transaction.gasPrice = gasPrice.toNumber();
        log("tx.gasPrice = ", transaction.gasPrice);
        const tx = await utils_1.resolveProperties(transaction);
        // Refactored to check TX type (call, create, p2pkh, deploy error) and calculate needed amount
        const { transactionType, neededAmount } = utils_2.checkTransactionType(tx);
        // Check if the transactionType matches the DEPLOY_ERROR, throw error else continue
        if (transactionType === global_vars_1.GLOBAL_VARS.DEPLOY_ERROR) {
            return logger.throwError("You cannot send QTUM while deploying a contract. Try deploying again without a value.", utils_1.Logger.errors.NOT_IMPLEMENTED, {
                error: "You cannot send QTUM while deploying a contract. Try deploying again without a value.",
            });
        }
        let utxos = [];
        try {
            // @ts-ignore
            utxos = await this.provider.getUtxos(tx.from, neededAmount);
            // Grab vins for transaction object.
        }
        catch (error) {
            if (forwardErrors.indexOf(error.code) >= 0) {
                throw error;
            }
            return logger.throwError("Needed amount of UTXO's exceed the total you own.", utils_1.Logger.errors.INSUFFICIENT_FUNDS, {
                error: error,
            });
        }
        return await this.serializeTransaction(utxos, neededAmount, tx, transactionType);
    }
    connect(provider) {
        return new QtumWallet(this, provider);
    }
    /**
     *  Static methods to create Wallet instances.
     */
    static createRandom(options) {
        let entropy = random_1.randomBytes(16);
        if (!options) {
            options = {};
        }
        if (options.extraEntropy) {
            entropy = bytes_1.arrayify(bytes_1.hexDataSlice(keccak256_1.keccak256(bytes_1.concat([entropy, options.extraEntropy])), 0, 16));
        }
        const mnemonic = hdnode_1.entropyToMnemonic(entropy, options.locale);
        return QtumWallet.fromMnemonic(mnemonic, options.path, options.locale);
    }
    static fromEncryptedJson(json, password, progressCallback) {
        return json_wallets_1.decryptJsonWallet(json, password, progressCallback).then((account) => {
            return new QtumWallet(account);
        });
    }
    static fromEncryptedJsonSync(json, password) {
        return new QtumWallet(json_wallets_1.decryptJsonWalletSync(json, password));
    }
    /**
     * Create a QtumWallet from a BIP44 mnemonic
     * @param mnemonic
     * @param path QTUM uses two different derivation paths and recommends SLIP_BIP44_PATH for external wallets, core wallets use QTUM_BIP44_PATH
     * @param wordlist
     * @returns
     */
    static fromMnemonic(mnemonic, path, wordlist) {
        if (!path) {
            path = exports.defaultPath;
        }
        const hdnode = hdnode_1.HDNode.fromMnemonic(mnemonic, "", wordlist).derivePath(path);
        // QTUM computes address from the public key differently than ethereum, ethereum uses keccak256 while QTUM uses ripemd160(sha256(compressedPublicKey))
        // @ts-ignore
        properties_1.defineReadOnly(hdnode, "qtumAddress", utils_3.computeAddress(hdnode.publicKey, true));
        return new QtumWallet(hdnode);
    }
}
exports.QtumWallet = QtumWallet;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUXR1bVdhbGxldC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9saWIvUXR1bVdhbGxldC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSw0Q0FHMEI7QUFFMUIsK0NBQXdDO0FBQ3hDLG1DQUFzRDtBQUN0RCwyQ0FBNEU7QUFDNUUsdURBQW1EO0FBQ25ELHFFQUFpRTtBQUNqRSwyQ0FBK0M7QUFDL0MsMERBQTJEO0FBQzNELDhEQUF5RztBQUN6RyxrREFBa0U7QUFDbEUsZ0RBQTZFO0FBQzdFLGtEQUFvRDtBQUNwRCx3REFBcUQ7QUFHckQsTUFBTSxNQUFNLEdBQUcsSUFBSSxjQUFNLENBQUMsWUFBWSxDQUFDLENBQUM7QUFDeEMsTUFBTSxhQUFhLEdBQUc7SUFDbEIsY0FBTSxDQUFDLE1BQU0sQ0FBQyxrQkFBa0I7Q0FDbkMsQ0FBQztBQUVGLE1BQU0scUJBQXFCLEdBQUcsYUFBYSxDQUFDO0FBQzVDLE1BQU0sb0JBQW9CLEdBQUcsY0FBYyxDQUFDO0FBRTVDLDRDQUE0QztBQUMvQixRQUFBLGVBQWUsR0FBRyxrQkFBa0IsQ0FBQztBQUNsRCw4QkFBOEI7QUFDOUIsdUVBQXVFO0FBQzFELFFBQUEsZUFBZSxHQUFHLG9CQUFvQixDQUFDO0FBQ3ZDLFFBQUEsV0FBVyxHQUFHLHVCQUFlLENBQUM7QUFFM0MsYUFBYTtBQUNiLFNBQVMsSUFBSSxDQUFDLENBQUUsRUFBRSxDQUFFLEVBQUUsQ0FBRSxFQUFFLENBQUUsRUFBRSxDQUFFLEVBQUUsQ0FBRSxFQUFFLENBQUU7SUFDcEMsSUFBSTtRQUNBLGFBQWE7UUFDYixPQUFPLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxJQUFJLEVBQUUsU0FBUyxDQUFDLENBQUM7S0FDdkM7SUFBQyxPQUFPLENBQUMsRUFBRTtLQUVYO0FBQ0wsQ0FBQztBQUVELGFBQWE7QUFDYixTQUFTLEdBQUcsQ0FBQyxDQUFFLEVBQUUsQ0FBRSxFQUFFLENBQUUsRUFBRSxDQUFFLEVBQUUsQ0FB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