const crypto = require("crypto");

const encrypt = (userPass) => {
    // 1. Generate 16 random bytes
    const iv = crypto.randomBytes(16);
    // 2. Convert to 32-character hex string (NO SLICE!)
    const ivstring = iv.toString('hex'); 

    // 3. Create cipher using the Buffer directly
    const cipher = crypto.createCipheriv(
        "aes-256-cbc", 
        Buffer.from(process.env.CRYPTO_SECRET_KEY), 
        iv
    );

    let encrypted = cipher.update(userPass, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    return {
        iv: ivstring,
        encryptedPassword: encrypted
    };
}

const decrypt = (encrypted, ivstring) => {
    try {
        // 4. Convert the hex string back to a 16-byte Buffer
        const ivBuffer = Buffer.from(ivstring, 'hex');

        const decipher = crypto.createDecipheriv(
            "aes-256-cbc", 
            Buffer.from(process.env.CRYPTO_SECRET_KEY), 
            ivBuffer
        );

        let decrypted = decipher.update(encrypted, "base64", "utf8");
        decrypted += decipher.final("utf8");

        return decrypted;
    } catch (error) {
        console.error("Decryption Error:", error.message);
        return "Decryption Failed";
    }
}

module.exports = { encrypt, decrypt };