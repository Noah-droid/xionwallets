const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const { DirectSecp256k1Wallet } = require("@cosmjs/proto-signing");
const { toBech32 } = require("@cosmjs/encoding");
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");
const { StargateClient } = require("@cosmjs/stargate");

const morgan = require("morgan");
const app = express();
// app.use(bodyParser.json());
// Use morgan middleware for logging
app.use(morgan("combined"));

app.use(express.json()); // Built-in middleware to parse JSON
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
const ENCRYPTION_KEY = crypto.randomBytes(32); // Replace with a secure key in production
const IV_LENGTH = 16;

// Helper functions for encryption
function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
    return {
        iv: iv.toString("hex"),
        data: encrypted.toString("hex"),
    };
}

function decrypt(encryptedText, iv) {
    const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, Buffer.from(iv, "hex"));
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
            },
        ],
    },
    apis: ["./src/index.js"], 
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

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
        const privateKey = crypto.randomBytes(32).toString("hex");

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

/**
 * @swagger
 * /decrypt-key:
 *   post:
 *     summary: Decrypt an encrypted private key
 *     description: Decrypts a previously encrypted private key using the provided IV.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               encryptedKey:
 *                 type: string
 *                 description: The encrypted private key.
 *                 example: "encrypted private key"
 *               iv:
 *                 type: string
 *                 description: The initialization vector (IV) used during encryption.
 *                 example: "encryption IV"
 *     responses:
 *       200:
 *         description: Private key decrypted successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 privateKey:
 *                   type: string
 *                   example: "your decrypted private key"
 *       400:
 *         description: Missing parameters.
 */
app.post("/decrypt-key", (req, res) => {
    const { encryptedKey, iv } = req.body;
    if (!encryptedKey || !iv) {
        return res.status(400).json({ error: "Encrypted key and IV are required" });
    }

    try {
        const privateKey = decrypt(encryptedKey, iv);
        res.status(200).json({ privateKey });
    } catch (error) {
        console.error("Error decrypting private key:", error);
        res.status(500).json({ error: "Failed to decrypt private key" });
    }
});





const axios = require("axios");

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

        // Fetch balance from Xion API
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
