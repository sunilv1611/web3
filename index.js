/* eslint-disable no-underscore-dangle */
/* eslint-disable @typescript-eslint/no-explicit-any */
const Web3 = require('web3');
const Tx = require('ethereumjs-tx');
const EthUtil = require('ethereumjs-util');
const Bip39 = require('bip39');
const Hdkey = require('hdkey');
const { EncryptedKeystoreV3Json } = require('web3-core');
// const { IAccount, INodeRecord } from '~/redux/account/types';
const keythereum = require('keythereum');
const BigInt = require('big-integer');
const { contractFunctions } = require('./constants');

const REACT_APP_API_URL_WEB3 = 'https://rpc.fantom.network/'
const REACT_APP_API_URL_FANTOM = 'https://api.fantom.network/api/v1/'
const { API_URL_FANTOM, KEY_INFURA } = process.env;
// export const DEFAULT_PROVIDERS: INodeRecord[] = [
//   { address: REACT_APP_API_URL_WEB3 || '' },
//   { address: 'ws://18.189.195.64:4501' },
//   { address: 'ws://18.191.96.173:4502' },
//   { address: 'ws://3.15.138.107:4500' },
// ];

// const Web3 = require("web3");
// const Tx = require("ethereumjs-tx");
// type Transfer = {
// 	from: string;
// 	to: string;
// 	value: string;
// 	memo: string;
// 	privateKey: string;
// 	gasLimit?: number;
// 	web3Delegate?: any;
// 	cb?: () => {};
// };
const URL_FANTOM = API_URL_FANTOM;
const URL_ETHEREUM = `https://rinkeby.infura.io/v3/${KEY_INFURA}`;

// export interface ITransfer {
// 	from: string;
// 	to: string;
// 	value: string;
// 	memo: string;
// 	privateKey: string;
// 	gasLimit?: number;
// 	// eslint-disable-next-line @typescript-eslint/no-explicit-any
// 	web3Delegate?: any;
// }
// const web3 = new Web3(new Web3.providers.HttpProvider(API_URL_FANTOM));
// const code = web3.eth
//   .getCode("0xfa00face00fc0000000000000000000000000100")
//   .then(res => console.log("code res: ", res))
//   .catch(e => console.log("code e: ", e));
// console.log("code: ", code);




let web3 = new Web3(new Web3.providers.HttpProvider(REACT_APP_API_URL_WEB3 || ''));
let sfc = null;

// class Web3Agent {
// constructor() {
// 	this.web3 = new Web3(new Web3.providers.HttpProvider(REACT_APP_API_URL_WEB3 || ''));
// }


const getBalance = async (address) => {
	const res = await web3.eth.getBalance(address);
	return res;
}

const isConnected = async () => {
	if (!web3) return false;
	return !!await web3.eth.getNodeInfo();
}

const setProvider = async () => {
	const prov = new Web3.providers.HttpProvider(REACT_APP_API_URL_WEB3 || '');
	if (!web3) {
		web3 = new Web3(prov);
	} else {
		web3.setProvider(prov);
	}
}

const getKeystore = (privateKey, password) => {
	if (!web3) throw new Error('not inialized');

	return web3.eth.accounts.encrypt(privateKey, password);
};
// Get info on delegator

const getDelegate = (from, delegateAddress, sfc) => {
	return new Promise(resolve => {
		sfc.methods.delegations(delegateAddress).call({ from }, function (error, result) {
			if (!error) resolve(result);
			console.log(error, 'errorerror getDelegate');
		});
	});
}

const validateKeystore = (keystore, password) => {
	if (!web3) throw new Error('not inialized');

	return web3.eth.accounts.decrypt(keystore, password);
};

const getPrivateKey = (keystore, password) =>
	new Promise(resolve =>
		keythereum.recover(password, keystore, dataRes => {
			resolve(dataRes instanceof Buffer ? EthUtil.bufferToHex(dataRes) : null);
		})
	);
// Get current epoch

const getCurrentEpoch = (from, sfc) => {
	return new Promise(resolve => {
		sfc.methods.currentEpoch().call({ from }, function (error, result) {
			if (!error) {
				resolve(result);
			}
			console.log(error, 'errorerror getCurrentEpoch');
		});
	});
}

// async deligateUnstake({ publicKey }) {
//   const web3 = new Web3(
//     new Web3.providers.HttpProvider(REACT_APP_API_URL_WEB3 || '')
//   );

//   const sfc = new web3.eth.Contract(
//     contractFunctions,
//     '0xfc00face00000000000000000000000000000000'
//   );
//   sfc.methods
//     .prepareToWithdrawDelegation()
//     .call({ from: publicKey }, function(error, result) {
//       console.log(result, '***sdfksfsd');
//       console.log(error, '***sdfksfsd1');
//       if (result) {
//         return true;
//       }
//       return false;
//     });
// }

const estimateFee = async ({ from, to, value, memo }) => {
	// if (!this.web3 || !(await this.isConnected()))
	//   throw new Error('Not connected');

	const gasPrice = await web3.eth.getGasPrice();
	const gasLimit = await web3.eth.estimateGas({
		from,
		to,
		value: Web3.utils.toHex(Web3.utils.toWei(value, 'ether')),
		data: Web3.utils.asciiToHex(memo)
	});

	const fee = Web3.utils.fromWei(
		BigInt(gasPrice.toString())
			.multiply(BigInt(gasLimit.toString()))
			.toString()
	);

	return fee;
}
// Get info on delegator

const getDelegationPendingRewards = async (from, delegateAddress) => {
	const web3 = new Web3(new Web3.providers.HttpProvider(REACT_APP_API_URL_WEB3 || ''));
	const sfc = new web3.eth.Contract(contractFunctions, '0xfc00face00000000000000000000000000000000');
	// sfc.methods
	//   .delegations("0x2210BE0bDba6daC30c4023Ea22b4235E420178bE")
	//   .call({ from: "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe" }, function(
	//     error,
	//     result
	//   ) {
	//     console.log("hello", error);
	//     console.log(result);
	//   });
	// Get delegator info and current epoch - 1 (i.e the previous sealed epoch)
	const info = await Promise.all([
		getCurrentEpoch(from, sfc),
		getDelegate(from, delegateAddress, sfc) || {}
	]);
	const maxEpochs = Number(info[0]) - 1;
	const fromEpoch = info[1].paidUntilEpoch;
	return new Promise(resolve => {
		sfc.methods
			.calcDelegationRewards(delegateAddress, fromEpoch, maxEpochs)
			.call({ from }, function (error, result) {
				if (result) {
					resolve({
						pendingRewards: parseFloat(result['0']) / Math.pow(10, 18),
						data: info[1]
					});
				} else {
					resolve({ pendingRewards: 0, data: info[1] });
				}
			});
	});
}

const delegateStake = ({ amount, publicKey, privateKey, validatorId, isWeb = false }) => {
	console.log(amount, publicKey, privateKey, validatorId, '******8amount, publicKey, privateKey, validatorId');

	const web3 = new Web3(new Web3.providers.HttpProvider(REACT_APP_API_URL_WEB3 || ''));

	const web3Sfc = new web3.eth.Contract(contractFunctions, '0xfc00face00000000000000000000000000000000');

	// Assign contract functions to sfc variable
	// tx = this.sfc.createDelegation("1", {
	//   from: "0x2122ecA57D8F5Ca902363CbA9d256A66C7664332",
	//   value: "1"
	// });
	// const sfc = new this.web3.eth.Contract(
	//   abi,
	//   "0xfc00face00000000000000000000000000000000"
	// );
	// const am = Number(amount)

	return transfer({
		from: publicKey,
		to: '0xfc00face00000000000000000000000000000000',
		value: amount,
		memo: web3Sfc.methods.createDelegation(validatorId).encodeABI(),
		privateKey,
		gasLimit: 200000,
		web3Delegate: web3,
		isWeb
		// cb: data,
	});
	// this.sfc.stakersNum(); // if everything is all right, will return non-zero value
}

const restoreWallet = async (privateKey) => {
	const wallet = web3.eth.accounts.privateKeyToAccount(privateKey);
	return wallet;
}

const getTransactionFee = async (gasLimit) => {
	const gasPrice = await web3.eth.getGasPrice();
	// const gasLimit = 200000;
	const fee = Web3.utils.fromWei(
		BigInt(gasPrice.toString())
			.multiply(BigInt(gasLimit.toString()))
			.toString()
	);
	return fee;
}

const transfer = async ({
	from,
	to,
	value,
	memo = '',
	privateKey,
	gasLimit = 44000,
	web3Delegate = '',
	isWeb
}) => {
	const useWeb3 = web3Delegate || web3;
	const nonce = await useWeb3.eth.getTransactionCount(from);
	const gasPrice = await useWeb3.eth.getGasPrice();
	// const amount = parseFloat(value)

	const rawTx = {
		from,
		to,
		value: Web3.utils.toHex(Web3.utils.toWei(value, 'ether')),
		gasLimit: Web3.utils.toHex(gasLimit),
		gasPrice: Web3.utils.toHex(gasPrice),
		nonce: Web3.utils.toHex(nonce),
		data: memo
	};
	console.log(new Buffer(privateKey), '****sdkksdfk')


	console.log('*****privateKey', privateKey, typeof privateKey)

	const bufferData = EthUtil.addHexPrefix(privateKey)
	console.log(bufferData, '****sdjasdj')
	const privateKeyBuffer = EthUtil.toBuffer(privateKey);
	console.log(privateKeyBuffer, '****privateKeyBuffer')
	const tx = new Tx(rawTx);
	tx.sign(privateKeyBuffer);
	const serializedTx = tx.serialize();
	const res = await useWeb3.eth.sendSignedTransaction(`0x${serializedTx.toString('hex')}`);
	if (isWeb) {
		localStorage.setItem('txHash', res.transactionHash);


	}
	// if (cb) {
	//   cb(res.transactionHash || '')
	// }
	return res;
}

const delegateUnstake = async (publicKey, privateKey, isWeb = false) => {
	const web3 = new Web3(new Web3.providers.HttpProvider(REACT_APP_API_URL_WEB3 || ''));
	const web3Sfc = new web3.eth.Contract(contractFunctions, '0xfc00face00000000000000000000000000000000');
	return transfer({
		from: publicKey,
		to: '0xfc00face00000000000000000000000000000000',
		value: '0',
		memo: web3Sfc.methods.prepareToWithdrawDelegation().encodeABI(),
		privateKey,
		gasLimit: 200000,
		web3Delegate: web3,
		isWeb
		// cb: () => '',
	});
}

const withdrawDelegateAmount = async (publicKey, privateKey, isWeb = false) => {
	const web3 = new Web3(new Web3.providers.HttpProvider(REACT_APP_API_URL_WEB3 || ''));

	const web3Sfc = new web3.eth.Contract(contractFunctions, '0xfc00face00000000000000000000000000000000');
	return transfer({
		from: publicKey,
		to: '0xfc00face00000000000000000000000000000000',
		value: '0',
		memo: web3Sfc.methods.withdrawDelegation().encodeABI(),
		privateKey,
		gasLimit: 200000,
		web3Delegate: web3,
		isWeb,
		// cb: () => '',
	});
}

const mnemonicToKeys = async (mnemonic) => {
	const seed = await Bip39.mnemonicToSeed(mnemonic);
	const root = Hdkey.fromMasterSeed(seed);

	const addrNode = root.derive("m/44'/60'/0'/0/0");
	const pubKey = EthUtil.privateToPublic(addrNode._privateKey);
	const addr = EthUtil.publicToAddress(pubKey).toString('hex');
	const publicAddress = EthUtil.toChecksumAddress(addr);
	const privateKey = EthUtil.bufferToHex(addrNode._privateKey);

	return { publicAddress, privateKey };
};

const privateKeyToKeys = (privateKey) => {
	const privateKeyBuffer = EthUtil.toBuffer(privateKey);

	const pubKey = EthUtil.privateToPublic(privateKeyBuffer);
	const addr = EthUtil.publicToAddress(pubKey).toString('hex');
	const publicAddress = EthUtil.toChecksumAddress(addr);

	return { publicAddress, privateKey };
};

const getAccount = async (address) => {
	// eslint-disable-next-line no-return-await
	return await fetch(`${REACT_APP_API_URL_FANTOM}api/v1/get-account?address=${address}`);
}

const estimateFeeMobile = async (value) => {
	let fee;
	if (web3 && web3.eth) {
		const gasPrice = await web3.eth.getGasPrice();
		const gasLimit = value;
		fee = Web3.utils.fromWei(
			BigInt(gasPrice.toString())
				.multiply(BigInt(gasLimit.toString()))
				.toString()
		);
	}
	return fee;
}

// from debug network
/* eslint-disable no-undef */
// $FlowFixMe
// GLOBAL.XMLHttpRequest = GLOBAL.originalXMLHttpRequest || GLOBAL.XMLHttpRequest;
// export const  {
//   Fantom: new Web3Agent(),
// };

// console.log(web3, '*****asdjasdweb3')

// const Fantom = new Web3Agent();

// module.exports.Fantom = Fantom;
module.exports.estimateFeeMobile = estimateFeeMobile
module.exports.getBalance = getBalance
module.exports.getKeystore = getKeystore
module.exports.privateKeyToKeys = privateKeyToKeys
module.exports.delegateUnstake = delegateUnstake
module.exports.isConnected = isConnected
module.exports.setProvider = setProvider
module.exports.getDelegate = getDelegate
module.exports.validateKeystore = validateKeystore
module.exports.getPrivateKey = getPrivateKey
module.exports.getCurrentEpoch = getCurrentEpoch
module.exports.estimateFee = estimateFee
module.exports.getDelegationPendingRewards = getDelegationPendingRewards
module.exports.delegateStake = delegateStake
module.exports.restoreWallet = restoreWallet
module.exports.getTransactionFee = getTransactionFee
module.exports.transfer = transfer
module.exports.delegateUnstake = delegateUnstake
module.exports.withdrawDelegateAmount = withdrawDelegateAmount
module.exports.mnemonicToKeys = mnemonicToKeys
module.exports.getAccount = getAccount


