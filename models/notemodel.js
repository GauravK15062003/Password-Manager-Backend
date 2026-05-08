const mongoose = require('mongoose');

const noteSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'user-datas', required: true }, // Links note to user
    title: { type: String, required: true },
    encryptedContent: { type: String, required: true }, // Encrypted note body[span_4](end_span)
    iv: { type: String, required: true } // Required for AES decryption
}, { timestamps: true });

module.exports = mongoose.model('Note', noteSchema);