import express, { json } from "express";
import bodyParser from "body-parser";
import { randomBytes, createCipheriv, createDecipheriv } from "crypto";
import { DirectSecp256k1Wallet, DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { toBech32 } from "@cosmjs/encoding";
import swaggerJsdoc from "swagger-jsdoc";
import { serve, setup } from "swagger-ui-express";
import { StargateClient } from '@cosmjs/stargate';
import axios from 'axios';
import  { CosmWasmClient} from "@cosmjs/cosmwasm-stargate";

import pkg from "@cosmjs/cosmwasm-stargate";
const { SigningCosmWasmClient, GasPrice } = pkg;

import morgan from "morgan";
import { url } from "inspector";
const app = express();
// app.use(bodyParser.json());
// Use morgan middleware for logging
app.use(morgan("combined"));

app.use(json()); // Built-in middleware to parse JSON
app.use(morgan("dev")); // Log requests with concise colored logs

// Custom logging middleware
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    if (Object.keys(req.body).length > 0) {
        console.log(`Body: ${JSON.stringify(req.body)}`);
    }
    next();
});




// Encryption settings
const ALGORITHM = "aes-256-cbc";
const ENCRYPTION_KEY = randomBytes(32); // Replace with a secure key in production
const IV_LENGTH = 16;

// Helper functions for encryption
function encrypt(text) {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
    return {
        iv: iv.toString("hex"),
        data: encrypted.toString("hex"),
    };
}

function decrypt(encryptedText, iv) {
    const decipher = createDecipheriv(ALGORITHM, ENCRYPTION_KEY, Buffer.from(iv, "hex"));
    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(encryptedText, "hex")),
        decipher.final(),
    ]);
    return decrypted.toString();
}



// Swagger setup
const swaggerOptions = {
    definition: {
        openapi: "3.0.0",
        info: {
            title: "Wallet Service API",
            version: "1.0.0",
            description: "API for generating, recovering, and managing Xion wallets.",
        },
        servers: [
            {
                url: "https://xionwallet-8inr.onrender.com",
                // url: "http://127.0.0.1:3000",
            },
        ],
    },
    apis: ["./src/index.js"], 
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use("/docs", serve, setup(swaggerSpec));

/**
 * @swagger
 * /generate-wallet:
 *   post:
 *     summary: Generate a new wallet
 *     description: Generates a new Xion wallet with a mnemonic and encrypted private key.
 *     responses:
 *       200:
 *         description: Wallet generated successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 address:
 *                   type: string
 *                   example: xion1....
 *                 mnemonic:
 *                   type: string
 *                   example: "your mnemonic phrase"
 *                 encryptedPrivateKey:
 *                   type: string
 *                   example: "encrypted private key"
 *                 iv:
 *                   type: string
 *                   example: "encryption IV"
 */

// Generate wallet endpoint
app.post("/generate-wallet", async (req, res) => {
    try {
        // Generate a random private key (32 bytes in hexadecimal)
        const privateKey = randomBytes(32).toString("hex");

        // Create wallet from private key
        const wallet = await DirectSecp256k1Wallet.fromKey(Buffer.from(privateKey, "hex"), "xion");
        const [account] = await wallet.getAccounts(); // Get the wallet's address

        // Encrypt the private key for secure storage
        const encryptedKey = encrypt(privateKey);

        // Debugging: Log wallet details
        console.log("Generated Wallet Details:");
        console.log(`Private Key: ${privateKey}`);
        console.log(`Encrypted Private Key: ${encryptedKey.data}`);
        console.log(`Initialization Vector (IV): ${encryptedKey.iv}`);
        console.log(`Wallet Address: ${account.address}`);
        console.log(`Public Key: ${account.pubkey.toString("hex")}`);

        res.status(200).json({
            address: account.address, // Wallet address
            encryptedPrivateKey: encryptedKey.data, // Encrypted private key
            iv: encryptedKey.iv, // Initialization vector for decryption
            publicKey: account.pubkey.toString("hex"), // Optional: public key
        });

    } catch (error) {
        console.error("Error generating wallet:", error.message);
        res.status(500).json({ error: "Failed to generate wallet" });
    }
});


/**
 * @swagger
 * /generate-wallet-service:
 *   post:
 *     summary: Generate a wallet from a private key
 *     description: Creates a new wallet using the provided private key and returns encrypted wallet details
 *     tags:
 *       - Wallet
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - privateKey
 *             properties:
 *               privateKey:
 *                 type: string
 *                 description: The private key in hexadecimal format
 *                 example: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
 *     responses:
 *       200:
 *         description: Wallet generated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 address:
 *                   type: string
 *                   description: The wallet address
 *                   example: "xion1abc..."
 *                 encryptedPrivateKey:
 *                   type: string
 *                   description: The encrypted private key
 *                   example: "encrypted-data-string"
 *                 iv:
 *                   type: string
 *                   description: Initialization vector used for encryption
 *                   example: "initialization-vector"
 *                 publicKey:
 *                   type: string
 *                   description: The public key in hexadecimal format
 *                   example: "0x1234..."
 *       400:
 *         description: Bad request - Private key is missing
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Private key is required"
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Failed to generate wallet"
 */

app.post("/generate-wallet-service", async (req, res) => {
    try {
        const { privateKey } = req.body;

        if (!privateKey) {
            return res.status(400).json({ error: "Private key is required" });
        }

        // Create wallet from provided private key
        const wallet = await DirectSecp256k1Wallet.fromKey(Buffer.from(privateKey, "hex"), "xion");
        const [account] = await wallet.getAccounts();

        // Encrypt the private key
        const encryptedKey = encrypt(privateKey);

        res.status(200).json({
            address: account.address,
            encryptedPrivateKey: encryptedKey.data,
            iv: encryptedKey.iv,
            publicKey: account.pubkey.toString("hex"),
        });

    } catch (error) {
        console.error("Error generating wallet:", error.message);
        res.status(500).json({ error: "Failed to generate wallet" });
    }
});


/**
 * @swagger
 * /recover-wallet:
 *   post:
 *     summary: Recover a wallet
 *     description: Recovers a wallet using a provided mnemonic.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               mnemonic:
 *                 type: string
 *                 description: The mnemonic phrase of the wallet.
 *                 example: "your mnemonic phrase"
 *     responses:
 *       200:
 *         description: Wallet recovered successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 address:
 *                   type: string
 *                   example: xion1....
 *       400:
 *         description: Mnemonic is missing.
 */
app.post("/recover-wallet", async (req, res) => {
    const { mnemonic } = req.body;
    if (!mnemonic) {
        return res.status(400).json({ error: "Mnemonic is required" });
    }

    try {
        const wallet = await DirectSecp256k1Wallet.fromMnemonic(mnemonic, "xion");
        const [account] = await wallet.getAccounts();

        res.status(200).json({
            address: account.address,
        });
    } catch (error) {
        console.error("Error recovering wallet:", error);
        res.status(500).json({ error: "Failed to recover wallet" });
    }
});






const RPC_ENDPOINT = "https://api.xion-testnet-2.burnt.com";

// Add this before the get-balance endpoint

/**
 * @swagger
 * /get-balance/{address}:
 *   get:
 *     summary: Get wallet balance
 *     description: Retrieves the balance of a Xion wallet address
 *     parameters:
 *       - in: path
 *         name: address
 *         required: true
 *         description: Xion wallet address
 *         schema:
 *           type: string
 *         example: xion1...
 *     responses:
 *       200:
 *         description: Balance retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 address:
 *                   type: string
 *                   description: The wallet address
 *                   example: xion1...
 *                 balance:
 *                   type: string
 *                   description: The wallet balance with denomination
 *                   example: 1000 uxion
 *       500:
 *         description: Error fetching balance
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Failed to fetch balance. Ensure the address is correct.
 */

// Endpoint to get wallet balance using Xion's REST API
app.get("/get-balance/:address", async (req, res) => {
    const { address } = req.params;
    const denom = "uxion"; // Token denomination

    try {
        // Construct API URL
        const apiUrl = `${RPC_ENDPOINT}/cosmos/bank/v1beta1/balances/${address}/by_denom?denom=${denom}`;

        // Fetch balance from Xion API using axios
        const response = await axios.get(apiUrl);
        const balanceData = response.data.balance;

        // Respond with balance details
        res.status(200).json({
            address,
            balance: balanceData ? `${balanceData.amount} ${balanceData.denom}` : `0 ${denom}`,
        });
    } catch (error) {
        console.error("Error fetching balance:", error.message);
        res.status(500).json({ error: "Failed to fetch balance. Ensure the address is correct." });
    }
});


const rpcUrl = "https://rpc.xion-testnet-2.burnt.com:443";
const rpcEndpoint = rpcUrl;
const client = await StargateClient.connect(rpcUrl); 

// Query smart contract function
/**
 * @swagger
 * /contracts/{contract_address}/query:
 *   post:
 *     summary: Query a smart contract
 *     description: Retrieve information from a contract without executing any transaction.
 *     parameters:
 *       - name: contract_address
 *         in: path
 *         required: true
 *         description: The contract address to query.
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               msg:
 *                 type: object
 *                 description: The query message to fetch data from the contract.
 *     responses:
 *       200:
 *         description: Contract queried successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 result:
 *                   type: object
 *       500:
 *         description: Query failed.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 */
app.post('/contracts/:contract_address/query', async (req, res) => {
    try {
        const { msg } = req.body;
        const contractAddress = req.params.contract_address;

        const client = await CosmWasmClient.connect(rpcUrl);
        const result = await client.queryContractSmart(contractAddress, msg);

        res.json({ success: true, result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * @swagger
 *   /contracts/{contractAddress}/execute:
 *     post:
 *       summary: Execute smart contract
 *       description: Executes a contract transaction on the Xion blockchain.
 *       parameters:
 *         - in: path
 *           name: contractAddress
 *           required: true
 *           schema:
 *             type: string
 *           description: The address of the smart contract
 *       requestBody:
 *         required: true
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               required: ["senderMnemonic", "msg"]
 *               properties:
 *                 senderMnemonic:
 *                   type: string
 *                   description: Mnemonic of sender
 *                 msg:
 *                   type: object
 *                   description: Execute message
 *                 gasLimit:
 *                   type: integer
 *                   description: Gas limit (optional)
 *                   example: 200000
 *                 gasPrice:
 *                   type: string
 *                   description: Gas price (optional)
 *                   example: "0.025uxion"
 *       responses:
 *         "200":
 *           description: Successful execution
 *           content:
 *             application/json:
 *               schema:
 *                 type: object
 *                 properties:
 *                   success:
 *                     type: boolean
 *                   result:
 *                     type: object
 *                     description: Execution result
 *         "400":
 *           description: Bad Request
 *         "500":
 *           description: Server Error
 */
app.post('/contracts/:contractAddress/execute', async (req, res) => {
    try {
        const { senderMnemonic, msg, gasLimit, gasPrice } = req.body;
        const { contractAddress } = req.params;

        if (!senderMnemonic || typeof senderMnemonic !== 'string') {
            return res.status(400).json({ success: false, error: "Invalid senderMnemonic. It must be a non-empty string." });
        }

        const finalGasLimit = gasLimit || 200000;
        const finalGasPrice = gasPrice || "0.025uxion";

        const result = await executeContract(senderMnemonic, contractAddress, msg, finalGasLimit, finalGasPrice);
        
        // Convert any BigInt values to string before sending the response
        const formattedResult = JSON.parse(
            JSON.stringify(result, (key, value) =>
                typeof value === "bigint" ? value.toString() : value
            )
        );

        res.json({ success: true, result: formattedResult });
        res.json({ success: true, result });

    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

async function executeContract(senderMnemonic, contractAddress, msg, gasLimit, gasPrice) {
    const wallet = await DirectSecp256k1HdWallet.fromMnemonic(senderMnemonic, { prefix: "xion" });
    const [firstAccount] = await wallet.getAccounts();

    // Check sender's balance before execution
    const client = await CosmWasmClient.connect(rpcEndpoint);
    const balance = await client.getBalance(firstAccount.address, "uxion");
    console.log(balance)
    if (Number(balance.amount) < 100) {
        throw new Error(`Insufficient funds: You have ${balance.amount} uxion but need at least 100 uxion.`);
    }

    // Execute transaction
    const signingClient = await SigningCosmWasmClient.connectWithSigner(rpcEndpoint, wallet, { gasPrice });
    const result = await signingClient.execute(firstAccount.address, contractAddress, msg, "auto", "", []);
    
    return result;
}



async function getBalance(address) {
    const client = await CosmWasmClient.connect(rpcEndpoint);
    const balance = await client.getBalance(address, "uxion");
    console.log(`Balance: ${balance.amount} uxion`);
    return balance.amount;
}





// /**
//  * @swagger
//  * /contracts/{contractAddress}/query:
//  *   post:
//  *     summary: Query a smart contract
//  *     description: Retrieve information from a contract without executing any transaction.
//  *     parameters:
//  *       - name: contractAddress
//  *         in: path
//  *         required: true
//  *         description: The contract address to query.
//  *         schema:
//  *           type: string
//  *     requestBody:
//  *       required: true
//  *       content:
//  *         application/json:
//  *           schema:
//  *             type: object
//  *             properties:
//  *               queryMsg:
//  *                 type: object
//  *                 description: The query message to fetch data from the contract.
//  *     responses:
//  *       200:
//  *         description: Contract queried successfully.
//  *         content:
//  *           application/json:
//  *             schema:
//  *               type: object
//  *               properties:
//  *                 success:
//  *                   type: boolean
//  *                 result:
//  *                   type: object
//  *       500:
//  *         description: Query failed.
//  *         content:
//  *           application/json:
//  *             schema:
//  *               type: object
//  *               properties:
//  *                 success:
//  *                   type: boolean
//  *                 error:
//  *                   type: string
//  */
// // API endpoint to query contract
// app.post('/contracts/:contractAddress/query', async (req, res) => {
//     try {
//         const { queryMsg } = req.body;
//         const { contractAddress } = req.params;  // Extract contract address from URL parameter

//         // Query the contract with the provided query message
//         const result = await queryContract(contractAddress, queryMsg);

//         // Respond with the result of the query
//         res.json({ success: true, result });
//     } catch (error) {
//         res.status(500).json({ success: false, error: error.message });
//     }
// });




// import { DirectSecp256k1Wallet } from "@cosmjs/proto-signing";
// import { toBech32 } from "@cosmjs/encoding";
// import { rawSecp256k1PubkeyToRawAddress } from "@cosmjs/amino";
// import { coins, makeSignDoc, makeStdTx } from "@cosmjs/stargate";




// const DENOM = "uxion";
// const GAS_LIMIT = "200000";
// const GAS_PRICE = "5000"; // Set an appropriate fee



// Transfer Xion tokens
// app.post("/transfer", async (req, res) => {
//     const { recipient, amount } = req.body;
//     const privateKey = process.env.PRIVATE_KEY;

//     if (!privateKey) {
//         return res.status(400).json({ error: "Missing PRIVATE_KEY in environment variables." });
//     }
//     if (!recipient || !amount) {
//         return res.status(400).json({ error: "Recipient address and amount are required." });
//     }

//     try {
//         // Create wallet from private key
//         const wallet = await DirectSecp256k1Wallet.fromKey(Buffer.from(privateKey, "hex"), "xion");
//         const [account] = await wallet.getAccounts();
//         const sender = toBech32("xion", rawSecp256k1PubkeyToRawAddress(account.pubkey));

//         // Fetch account details (account_number & sequence)
//         const accountInfoUrl = `${RPC_ENDPOINT}/cosmos/auth/v1beta1/accounts/${sender}`;
//         const accountResponse = await axios.get(accountInfoUrl);
//         const accountData = accountResponse.data.account;

//         const accountNumber = accountData.account_number;
//         const sequence = accountData.sequence;

//         // Construct transaction message
//         const msgSend = {
//             typeUrl: "/cosmos.bank.v1beta1.MsgSend",
//             value: {
//                 fromAddress: sender,
//                 toAddress: recipient,
//                 amount: coins(amount, DENOM),
//             },
//         };

//         // Create transaction body
//         const txBody = {
//             messages: [msgSend],
//             memo: "Xion token transfer",
//         };

//         // Create signing document
//         const signDoc = makeSignDoc(
//             txBody.messages,
//             { gas: GAS_LIMIT, amount: coins(GAS_PRICE, DENOM) }, // Fee
//             "xion-testnet-1",
//             txBody.memo,
//             accountNumber,
//             sequence
//         );

//         // Sign the transaction
//         const { signature, signed } = await wallet.signDirect(sender, signDoc);

//         // Construct the final transaction
//         const signedTx = makeStdTx(signed, [signature]);

//         // Broadcast the transaction to the Xion REST API
//         const broadcastUrl = `${RPC_ENDPOINT}/cosmos/tx/v1beta1/txs`;
//         const broadcastResponse = await axios.post(broadcastUrl, {
//             tx_bytes: Buffer.from(signedTx).toString("base64"),
//             mode: "BROADCAST_MODE_SYNC",
//         });

//         return res.status(200).json({
//             message: "Transaction broadcasted successfully",
//             transaction: broadcastResponse.data,
//         });
//     } catch (error) {
//         console.error("Error sending transaction:", error.message);
//         return res.status(500).json({ error: "Failed to send transaction", details: error.message });
//     }
// });




// Run the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Wallet service running on port ${PORT}`);
    console.log(`Swagger docs available at http://localhost:${PORT}/docs`);
});
