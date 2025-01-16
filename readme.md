# Xion Wallet Generation Service

This service is an Express.js application that allows the generation of Xion blockchain wallets. The wallet generation includes mnemonic phrases, addresses, and encrypted private keys for secure storage. You can check it out here: [Swagger Docs Guide](https://xionwallet.onrender.com/docs/)

---

## **Features**
- Generate wallets with a Xion-compatible prefix.
- Return a secure, encrypted private key alongside the mnemonic phrase and address.
- Protect sensitive data using AES encryption.

---

## **Requirements**
Ensure the following tools and dependencies are installed:

1. **Node.js** (v14+)
2. **NPM** or **Yarn**

Install required packages:
```bash
npm install express body-parser crypto bip39 @cosmjs/proto-signing
```

---

## **Endpoints**

### **POST /generate-wallet**
Generates a new wallet and returns the details.

**Request:**  
No body is required.

**Response:**  
Returns a JSON object with the following fields:
- `address`: The wallet address.
- `mnemonic`: A mnemonic phrase for wallet recovery.
- `encryptedPrivateKey`: The encrypted serialized wallet.
- `iv`: The initialization vector used for encryption.

**Example Response:**
```json
{
  "address": "xion1x5p8yxj8ueqt8hvsh2ff85knc7jwljp3wks59m",
  "mnemonic": "supply lobster torch magnet ocean frost ...",
  "encryptedPrivateKey": "f2c3a5d20...",
  "iv": "c812f57e45..."
}
```

---

## **How to Run**

1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the server:
   ```bash
   node app.js
   ```

4. Access the service:
   The server runs on `http://localhost:3000`.

---

## **Testing the Service**
Use a tool like Postman or curl to test the endpoint.

### **Using curl**
```bash
curl -X POST http://localhost:3000/generate-wallet
```

### **Using Postman**
1. Open Postman.
2. Create a new request:
   - Method: `POST`
   - URL: `http://localhost:3000/generate-wallet`
3. Click `Send`.

---

## **Encryption Details**
The service uses AES-256-CBC for encryption:
- **Key:** A randomly generated 32-byte encryption key.
- **IV:** A 16-byte initialization vector generated per encryption.

### **Decryption**
Use the `encryptedPrivateKey` and `iv` to decrypt the private key when needed.

---

## **License**
This project is licensed under the MIT License. Feel free to use, modify, and distribute it as needed.