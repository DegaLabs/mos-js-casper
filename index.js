const CaspSDK = require("casper-js-sdk")
const blake2b = require("blake2b")
const secp256k1 = require('ethereum-cryptography/secp256k1')
const { sha256 } = require('ethereum-cryptography/sha256')
const nacl = require('tweetnacl-ts')
const {
    CLPublicKey,
    RuntimeArgs,
    CLValueBuilder,
    CLValueParsers } = CaspSDK
const {
    utils,
    helpers,
    CasperContractClient,
} = require("casper-js-client-helper");
const { ERC20Client } = require('casper-erc20-js-client')
const axios = require('axios')
const { default: BigNumber } = require("bignumber.js")
const { contractSimpleGetter } = helpers;

const MOSJS = class {
    constructor() { }

    static async createInstance(contractPackageHash, nodeAddress, middlewareAPI, networkName) {
        const instance = new MOSJS()
        const contractHash = await MOSJS.getActiveContractHash(nodeAddress, middlewareAPI, contractPackageHash)
        instance.contractHash = contractHash
        instance.nodeAddress = nodeAddress;
        instance.chainName = networkName;
        instance.contractClient = new CasperContractClient(nodeAddress, networkName);
        instance.namedKeysList = [
            "contract_owner",
            "market_fee",
            "payment_token"
        ];

        instance.contractPackageHash = contractPackageHash;
        instance.contractClient.chainName = instance.chainName
        instance.contractClient.contractHash = instance.contractHash
        instance.contractClient.contractPackageHash = instance.contractPackageHash
        instance.contractClient.nodeAddress = instance.nodeAddress
        instance.namedKeys = instance.namedKeysList;
        const paymentTokenContractPackageHash = await contractSimpleGetter(instance.nodeAddress, instance.contractHash, ["payment_token"])
        instance.paymentToken = Buffer.from(paymentTokenContractPackageHash.data).toString('hex')
        instance.paymentTokenContractHash = await MOSJS.getActiveContractHash(nodeAddress, middlewareAPI, instance.paymentToken)
        instance.paymentTokenContract = await new ERC20Client(nodeAddress, networkName, '')
        await instance.paymentTokenContract.setContractHash(`hash-${instance.paymentTokenContractHash}`)
        return instance
    }

    parseKeyList(remainder) {
        let ret = new CaspSDK.CLU32BytesParser().fromBytesWithRemainder(remainder)
        let len = ret.result.val.value().toNumber()
        const keyList = []
        for (var i = 0; i < len; i++) {
            ret = new CaspSDK.CLKeyBytesParser().fromBytesWithRemainder(ret.remainder)
            keyList.push(Buffer.from(ret.result.val.value().data).toString("hex"))
        }
        return { keys: keyList, ret }
    }

    parseU256List(remainder) {
        let ret = new CaspSDK.CLU32BytesParser().fromBytesWithRemainder(remainder)
        let len = ret.result.val.value().toNumber()
        const u256List = []
        for (var i = 0; i < len; i++) {
            ret = new CaspSDK.CLU256BytesParser().fromBytesWithRemainder(ret.remainder)
            u256List.push(ret.result.val.value().toString())
        }
        return { u256s: u256List, ret }
    }

    async marketFee() {
        const v = await contractSimpleGetter(this.nodeAddress, this.contractHash, ["market_fee"])
        console.log("fee", v.toString())
        return v.toString()
    }

    async cancelOrder(
        {
            identifierMode,
            tokenIdentifier,
            nftPackageHash, // hex
            ownerPublicKey, // hex
            price,  // string
            isBid,
            expired,
            salt,   // hex
            signature,  // hex
            gasPrice = 1,
            paymentAmount = 4500000000,
            ttl = 1800000
        }
    ) {
        const contractHashAsByteArray = utils.contractHashToByteArray(this.contractHash)
        const publicKey = CLPublicKey.fromHex(ownerPublicKey)

        const runtimeArgs = RuntimeArgs.fromMap({
            modes: CLValueBuilder.list([CLValueBuilder.u64(identifierMode)]),
            token_identifiers: CLValueBuilder.list([CLValueBuilder.string(tokenIdentifier)]),
            nft_package_hashes: CLValueBuilder.list([CLValueBuilder.key(new CaspSDK.CLByteArray(Uint8Array.from(Buffer.from(nftPackageHash, 'hex'))))]),
            owners: CLValueBuilder.list([CLValueBuilder.key(publicKey)]),
            prices: CLValueBuilder.list([CLValueBuilder.u256(price)]),
            is_bids: CLValueBuilder.list([CLValueBuilder.bool(isBid)]),
            salts: CLValueBuilder.list([CLValueBuilder.key(new CaspSDK.CLByteArray(Uint8Array.from(Buffer.from(salt, 'hex'))))]),
            expireds: CLValueBuilder.list([CLValueBuilder.u64(expired)]),
            owner_public_keys: CLValueBuilder.list([CLValueBuilder.string(ownerPublicKey)]),
            signatures: CLValueBuilder.list([CLValueBuilder.string(signature)]),
        })

        const deploy = CaspSDK.DeployUtil.makeDeploy(
            new CaspSDK.DeployUtil.DeployParams(
                publicKey,
                this.chainName,
                gasPrice,
                ttl,
                [],
            ),
            CaspSDK.DeployUtil.ExecutableDeployItem.newStoredContractByHash(
                contractHashAsByteArray,
                "cancel_orders",
                runtimeArgs,
            ),
            CaspSDK.DeployUtil.standardPayment(paymentAmount),
        )
        return deploy
    }

    async acceptOrder(
        {
            identifierMode,
            tokenIdentifier,
            nftPackageHash, // hex
            ownerPublicKey, // hex
            price,  // string
            isBid,
            expired,
            salt,
            signature,  // hex
            gasPrice = 1,
            paymentAmount = 4500000000,
            ttl = 1800000
        }
    ) {
        const contractHashAsByteArray = utils.contractHashToByteArray(this.contractHash)
        const publicKey = CLPublicKey.fromHex(ownerPublicKey)

        const runtimeArgs = RuntimeArgs.fromMap({
            modes: CLValueBuilder.list([CLValueBuilder.u64(identifierMode)]),
            token_identifiers: CLValueBuilder.list([CLValueBuilder.string(tokenIdentifier)]),
            nft_package_hashes: CLValueBuilder.list([CLValueBuilder.key(new CaspSDK.CLByteArray(Uint8Array.from(Buffer.from(nftPackageHash, 'hex'))))]),
            owners: CLValueBuilder.list([CLValueBuilder.key(publicKey)]),
            prices: CLValueBuilder.list([CLValueBuilder.u256(price)]),
            is_bids: CLValueBuilder.list([CLValueBuilder.bool(isBid)]),
            salts: CLValueBuilder.list([CLValueBuilder.key(new CaspSDK.CLByteArray(Uint8Array.from(Buffer.from(salt, 'hex'))))]),
            expireds: CLValueBuilder.list([CLValueBuilder.u64(expired)]),
            owner_public_keys: CLValueBuilder.list([CLValueBuilder.string(ownerPublicKey)]),
            signatures: CLValueBuilder.list([CLValueBuilder.string(signature)]),
        })

        const deploy = CaspSDK.DeployUtil.makeDeploy(
            new CaspSDK.DeployUtil.DeployParams(
                publicKey,
                this.chainName,
                gasPrice,
                ttl,
                [],
            ),
            CaspSDK.DeployUtil.ExecutableDeployItem.newStoredContractByHash(
                contractHashAsByteArray,
                "accept_orders",
                runtimeArgs,
            ),
            CaspSDK.DeployUtil.standardPayment(paymentAmount),
        )
        return deploy
    }

    static async getPackageInfo(nodeAddress, middlewareAPI, contractPackageHash, stateRootHash) {
        stateRootHash = stateRootHash ? stateRootHash : (await utils.getStateRootHash(nodeAddress))
        const data = await axios.get(`${middlewareAPI}state_root_hash=${stateRootHash}&key=hash-${contractPackageHash}`)
        const packageInfo = data.data.result.stored_value.ContractPackage
        return packageInfo
    }

    static async getActiveContractHash(nodeAddress, middlewareAPI, contractPackageHash) {
        const packageInfo = await MOSJS.getPackageInfo(nodeAddress, middlewareAPI, contractPackageHash)
        const versions = packageInfo.versions
        let lastVersion = {};
        versions.forEach(e => {
            if (!lastVersion.contract_version || e.contract_version > lastVersion.contract_version) {
                lastVersion = e
            }
        })
        return lastVersion.contract_hash.substring("contract-".length)
    }

    static generateSalt(ownerPublicKey) {
        const publicKey = CLPublicKey.fromHex(ownerPublicKey)
        const keyBytes = CLValueParsers.toBytes(CLValueBuilder.key(publicKey)).val
        const first20 = keyBytes.slice(0, 20)
        const random = [...Array(12)].map(() => Math.floor(Math.random() * 256))
        return Buffer.from([...first20, ...random]).toString('hex')
    }

    static computeOrderHash({
        identifierMode,
        tokenIdentifier,
        nftPackageHash, // hex
        ownerPublicKey, // hex
        price,  // string
        isBid,
        expired,
        salt,
        networkName = "casper" | "casper-test"
    }) {
        // first serialize it
        let ret = []
        const publicKey = CLPublicKey.fromHex(ownerPublicKey)
        const pubkeyBytes = Uint8Array.from(Buffer.from(ownerPublicKey, 'hex'))
        ret = [...ret, ...CLValueParsers.toBytes(CLValueBuilder.u64(identifierMode))]
        ret = [...ret, ...CLValueParsers.toBytes(CLValueBuilder.string(tokenIdentifier))]
        ret = [...ret, ...Uint8Array.from(Buffer.from(nftPackageHash, 'hex'))]
        ret = [...ret, ...CLValueParsers.toBytes(CLValueBuilder.key(publicKey))]
        ret = [...ret, ...CLValueParsers.toBytes(CLValueBuilder.u256(price))]
        ret = [...ret, ...CLValueParsers.toBytes(CLValueBuilder.bool(isBid))]
        ret = [...ret, ...Uint8Array.from(Buffer.from(salt, 'hex'))]
        ret = [...ret, ...CLValueParsers.toBytes(CLValueBuilder.u64(expired))]
        ret = [...ret, ...CLValueParsers.toBytes(CLValueBuilder.u32(pubkeyBytes.length))]
        ret = [...ret, ...CLValueParsers.toBytes(CLValueBuilder.string(networkName))]
        ret = [...ret, ...pubkeyBytes]

        const blaked = blake2b(32).update(Uint8Array.from(ret)).digest()
        return blaked
    }

    static toCasperSignedMessage(message) {
        return Uint8Array.from(Buffer.from(`Casper Message:\n` + message))
    }

    static async getNFTIdentifierMode({ nodeAddress, contractPackageHash, networkName, middlewareAPI }) {
        const stateRootHash = await utils.getStateRootHash(nodeAddress)
        let data = await axios.get(`${middlewareAPI}?state_root_hash=${stateRootHash}&key=hash-${contractPackageHash}`)
        data = data.data.result.stored_value
        let namedKeys = []
        let entryPoints = []
        let retPackageHash = ''
        let retContractHashes = []
        if (data.Contract) {
            // contractPackageHash is actually a contract hash
            const contractInfo = data.Contract
            retPackageHash = contractInfo.contract_package_hash.substring("contract-package-wasm".length)
            namedKeys = contractInfo.named_keys
            entryPoints = contractInfo.entry_points
            retContractHashes.push(contractPackageHash)
        } else {
            const packageInfo = data.ContractPackage
            const versions = packageInfo.versions
            let lastVersion = {}
            versions.forEach(e => {
                if (!lastVersion.contract_version || e.contract_version > lastVersion.contract_version) {
                    lastVersion = e
                }
                retContractHashes.push(e.contract_hash.substring("contract-".length))
            })
            retPackageHash = contractPackageHash
            const activeContractHash = lastVersion.contract_hash.substring("contract-".length)
            let activeContractData = await axios.get(`${middlewareAPI}?state_root_hash=${stateRootHash}&key=hash-${activeContractHash}`)
            activeContractData = activeContractData.data.result.stored_value.Contract
            namedKeys = activeContractData.named_keys
            entryPoints = activeContractData.entry_points
        }

        // first search if there is named key identifier_mode
        const identifierModeItem = namedKeys.find((e) => {
            return e.name == `identifier_mode`
        })
        let identifierMode = 0
        if (identifierModeItem) {
            const im = await contractSimpleGetter(nodeAddress, retContractHashes[retContractHashes.length - 1], ["identifier_mode"])
            identifierMode = im.toNumber()
        } else {
            const entryPointTransfer = entryPoints.find(e => e.name == "transfer")
            console.log('entryPointTransfer', entryPointTransfer)
            const arg = entryPointTransfer.args.find(e => e.name == "token_ids")
            identifierMode = arg.cl_type.List == 'String' ? 3 : 2
        }

        return {
            namedKeys,
            entryPoints,
            contractPackageHash: retPackageHash,
            contractHashes: retContractHashes,
            networkName,
            identifierMode
        }
    }

    static isOrderSignatureValid({
        identifierMode,
        tokenIdentifier,
        nftPackageHash, // hex
        ownerPublicKey, // hex
        price,  // string
        isBid,
        expired,
        salt,
        networkName,
        signature
    }) {
        //verify signature
        const orderHash = Buffer.from(MOSJS.computeOrderHash({
            identifierMode,
            tokenIdentifier,
            nftPackageHash,
            ownerPublicKey,
            price,
            isBid,
            expired,
            salt,
            networkName
        })).toString('hex')

        let verifyResult = false
        const msg = MOSJS.toCasperSignedMessage(orderHash)
        const signatureRaw = Uint8Array.from(Buffer.from(signature, 'hex'))
        const publicKeyCL = CaspSDK.CLPublicKey.fromHex(ownerPublicKey)
        if (publicKeyCL.isEd25519()) {
            verifyResult = nacl.sign_detached_verify(msg, signatureRaw, publicKeyCL.value());
        } else {
            verifyResult = secp256k1.ecdsaVerify(
                signatureRaw,
                sha256(Buffer.from(msg)),
                publicKeyCL.value()
            );
        }
        return verifyResult
    }

    async isOrderAcceptable({
        identifierMode,
        tokenIdentifier,
        nftPackageHash, // hex
        ownerPublicKey, // hex
        price,  // string
        isBid,
        expired,
        salt,
        networkName,
        signature,  // hex
    }) {
        // first, check if signature valid
        if (!MOSJS.isOrderSignatureValid({ identifierMode, tokenIdentifier, nftPackageHash, ownerPublicKey, price, isBid, expired, salt, signature, networkName })) {
            return { error: "invalid signature" }
        }
        if (expired < Date.now()) {
            return { error: "expired" }
        }

        // check if payment token or nft approved
        if (isBid) {
            // check whether the owner already approved payment token for market place
            try {
                const allowance = await this.paymentTokenContract.allowances(
                    CLPublicKey.fromHex(ownerPublicKey),
                    new CaspSDK.CLByteArray(Uint8Array.from(Buffer.from(this.contractPackageHash, 'hex')))
                );
                if (new BigNumber(allowance).comparedTo(price) < 0) {
                    return { error: "insufficient allowance" }
                }
            } catch (e) {
                return { error: "not approved for payment token" }
            }
        } else {

        }

        // valid
        return null
    }
}

module.exports = MOSJS
