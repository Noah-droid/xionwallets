const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const { DirectSecp256k1Wallet } = require("@cosmjs/proto-signing");
const { toBech32 } = require("@cosmjs/encoding");
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");


const app = express();
app.use(bodyParser.json());

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
                url: "http://localhost:3000",
            },
        ],
    },
    apis: ["./index.js"], 
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

// Run the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Wallet service running on port ${PORT}`);
    console.log(`Swagger docs available at http://localhost:${PORT}/docs`);
});
