import TronWeb from "tronweb";

// console.log(TronWeb.utils);

let account_key = TronWeb.utils.accounts.generateAccount();
console.log("key: %o", account_key);

// let message_data = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
let message_data = [0x00, 0x11, 0x22, 0x33, 0x444, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x444, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,]

let msg_hash = TronWeb.utils.message.hashMessage(message_data);
console.log("msg data: %s", message_data.map(item => item.toString(16)).join(''));
console.log("msg hash: %s", msg_hash);

let sign_data = TronWeb.utils.message.signMessage(message_data, account_key.privateKey);
console.log("sign: %s", sign_data);

// verify
let ret_address = TronWeb.utils.message.verifyMessage(message_data, sign_data);

console.log("verify ret pubkey address: %s", ret_address);
console.log("\n");

if (ret_address == account_key.address.base58) {
  console.log("Success");
} else {
  console.log("Failed");
}
