const CaspSDK = require("casper-js-sdk")
const blake = require("blakejs")

const {
    CLPublicKey,
    RuntimeArgs,
    CLValueBuilder,
    CLValueParsers} = CaspSDK
const {
    utils,
    helpers,
    CasperContractClient,
} = require("casper-js-client-helper");
const { ERC20Client } = require('casper-erc20-js-client')
const axios = require('axios')
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
        ];

        instance.contractPackageHash = contractPackageHash;
        instance.contractClient.chainName = instance.chainName
        instance.contractClient.contractHash = instance.contractHash
        instance.contractClient.contractPackageHash = instance.contractPackageHash
        instance.contractClient.nodeAddress = instance.nodeAddress
        instance.namedKeys = instance.namedKeysList;

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

    static async getActiveContractHash(nodeAddress, middlewareAPI, contractPackageHash) {
        const stateRootHash = await utils.getStateRootHash(nodeAddress);
        const data = await axios(`${middlewareAPI}state_root_hash=${stateRootHash}&key=hash-${contractPackageHash}`)
        const packageInfo = data.data.result.stored_value.ContractPackage
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
        const blaked = blake.blake2b(Uint8Array.from(ret), undefined, 32);
        return blaked
    }

    static toCasperSignedMessage(message) {
        return Uint8Array.from(Buffer.from(`Casper Message:\n` + message))
    }
}

module.exports = { MOSJS }