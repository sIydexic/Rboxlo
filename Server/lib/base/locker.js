var exports = module.exports = {}

const argon2 = require("argon2")
const { StringProvider, CipherSweet, BlindIndex, EncryptedField } = require("ciphersweet-js")
const crypto = require("crypto")

if (global.rboxlo.env.ENCRYPTION_KEY.length != 32) {
    // Will result in buffer exceptions if not EXACTLY thirty-two characters
    throw `Invalid env.ENCRYPTION_KEY length (expected 32, got ${global.rboxlo.env.ENCRYPTION_KEY.length})`
}

if (global.rboxlo.env.CIPHERSWEET_KEY.length != 64) {
    throw `Invalid env.CIPHERSWEET_KEY length (expected 64, got ${global.rboxlo.env.CIPHERSWEET_KEY.length})`
}

// Set up ciphersweet
var provider = new StringProvider(global.rboxlo.env.CIPHERSWEET_KEY)
var engine = new CipherSweet(provider)

/**
 * Encrypts a string
 * 
 * @param {string} text Text to encode
 * 
 * @returns {string} Ciphertext
 */
exports.encrypt = (text) => {
    let iv = crypto.randomBytes(16)
    let cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(global.rboxlo.env.ENCRYPTION_KEY), iv)
    let encrypted = cipher.update(text)

    encrypted = Buffer.concat([encrypted, cipher.final()])

    return `${iv.toString("hex")}:${encrypted.toString("hex")}`
}

/**
 * Decrypts a ciphertext to get its original stored text
 * 
 * @param {string} text Ciphertext to decrypt
 * 
 * @returns {string} Decrypted text
 */
exports.decrypt = (text) => {
    // .pop() and .shift() scare me
    let parts = text.split(":")
    let iv = Buffer.from(parts[0], "hex")
    let ciphertext = Buffer.from(parts[1], "hex")

    let decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(global.rboxlo.env.ENCRYPTION_KEY), iv)
    let decrypted = decipher.update(ciphertext)
    decrypted = Buffer.concat([decrypted, decipher.final()])

    return decrypted.toString()
}

/**
 * Gets a blind index of a given text
 * 
 * @param {string} text Text to blind
 * 
 * @returns {string} Blind index of text
 */
exports.blind = async (text) => {
    let row = (new EncryptedField(engine, "content")).addBlindIndex(new BlindIndex("content", [], 64))
    let result = (await row.prepareForStorage(text))[1].content

    return result
}

/**
 * Hashes a password using Argon2
 * 
 * @param {string} password Cleartext password
 * 
 * @returns {string} Password hash
 */
exports.passwordHash = async (password) => {
    let hash = await argon2.hash(password, { type: argon2.argon2id })

    return hash
}

/**
 * Compares a given cleartext password against an Argon2 password hash to verify a password
 * 
 * @param {string} hash Argon2 password hash
 * @param {string} cleartext Cleartext password to compare against
 * 
 * @returns {boolean} If the verification was successful
 */
exports.passwordVerify = async (hash, cleartext) => {
    let result = await argon2.verify(hash, cleartext, { type: argon2.argon2id })

    return result
}