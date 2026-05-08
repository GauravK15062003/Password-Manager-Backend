const express = require("express");
const router = express.Router();
const User = require("../models/schema");
const bcrypt = require("bcrypt");
const authenticate = require("../middlewares/authenticate");
const { encrypt, decrypt } = require("../models/EncDecManager");
const Note = require('../models/notemodel')

// routing.js mein /register route ko aise update karein
router.post("/register", async (req, res) => {
    const { name, email, password, cpassword } = req.body;

    // Case 1: Khali fields
    if (!name || !email || !password || !cpassword) {
        return res.status(422).json({ error: "Please fill all the details." });
    }

    // Case 2: Password mismatch
    if (password !== cpassword) {
        return res.status(422).json({ error: "Passwords do not match." });
    }

    try {
        const userExist = await User.findOne({ email: email });

        // Case 3: User already exists
        if (userExist) {
            return res.status(422).json({ error: "Email already exists." });
        }

        const newUser = new User({ name, email, password, cpassword });
        await newUser.save();

        res.status(201).json({ message: "User created successfully." });

    } catch (err) {
        console.log(err);
        res.status(500).json({ error: "Failed to register. Server error." });
    }
});

// Inside routing.js
router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    // Case 1: Empty Fields
    if (!email || !password) {
        return res.status(422).json({ error: "Please fill all the details." });
    }

    try {
        const userExist = await User.findOne({ email: email });

        // Case 2: Wrong Email
        if (!userExist) {
            return res.status(401).json({ error: "Invalid Credentials." });
        }

        const isMatch = await bcrypt.compare(password, userExist.password);
        
        // Case 3: Wrong Password
        if (!isMatch) {
            return res.status(401).json({ error: "Invalid Credentials." });
        }

        // Successful Login
        const token = await userExist.generateAuthToken();
        res.cookie("jwtoken", token, {
            expires: new Date(Date.now() + 2592000000),
            httpOnly: true,
            secure: true,
            sameSite: "none"
        });

        res.status(200).json({ message: "User login successfully." });

    } catch (err) {
        res.status(500).json({ error: "Internal Server Error" });
    }
});

router.get("/authenticate", authenticate, async (req, res) =>
{
    res.send(req.rootUser);
})

router.post("/addnewpassword", authenticate, async (req, res) =>
{
    const { platform, userPass, userEmail, platEmail } = req.body;

    if (!platform || !userPass || !userEmail || !platEmail)
    {
        return res.status(400).json({ error: "Please fill the form properly" });
    }

    try
    {
        const rootUser = req.rootUser;


        const { iv, encryptedPassword } = encrypt(userPass);

        const isSaved = await rootUser.addNewPassword(encryptedPassword, iv, platform, platEmail);

        if (isSaved)
        {
            return res.status(200).json({ message: "Successfully added your password." })
        }
        else
        {
            return res.status(400).json({ error: "Could not save the password." })
        }
    }
    catch (error)
    {
        console.log(error)
    }

    return res.status(400).json({ error: "An unknown error occured." })
})

router.post("/deletepassword", authenticate, async (req, res) =>
{
    const { id } = req.body;

    if (!id)
    {
        return res.status(400).json({ error: "Could not find data" })
    }

    try
    {
        const rootUser = req.rootUser;

        const isDeleted = await User.updateOne({ email: rootUser.email }, { $pull: { passwords: { _id: id } } });

        if (!isDeleted)
        {
            return res.status(400).json({ error: "Could not delete the password." })
        }

        return res.status(200).json({ "message": "Successfully deleted your password." })
    }
    catch (err)
    {
        console.log(err);
    }
})

router.get("/logout", (req, res) =>
{
    res.clearCookie("jwtoken", { path: "/" });
    res.status(200).send("Logout");
})

router.post("/decrypt", (req, res) => {
    // Debugging ke liye ye log zarur rakhein
    // console.log("Body received:", req.body); 

    const { iv, encrypted, encryptedPassword } = req.body;
    
    // Notes ke liye 'encrypted' use hoga, Passwords ke liye 'encryptedPassword'
    const dataToDecrypt = encrypted || encryptedPassword;

    if (!dataToDecrypt || !iv) {
        console.log("Error: Data or IV is missing");
        return res.status(400).send("Missing data for decryption");
    }

    try {
        const decryptedData = decrypt(dataToDecrypt, iv);
        return res.status(200).send(decryptedData);
    } catch (err) {
        console.error("Decryption Error:", err.message);
        return res.status(500).send("Decryption failed");
    }
});

// Route to Save a Note
router.post('/add-note', authenticate, async (req, res) => {
    try {
        const { title, content } = req.body;

        // Verify content exists before encrypting
        if (!content) {
            return res.status(400).json({ error: "Content is required" });
        }

        const encryptedData = encrypt(content); 

        const newNote = new Note({
            user: req.rootUser._id,
            title: title,
            // Check if your encrypt function returns .password or .encryptedData
            encryptedContent: encryptedData.encryptedPassword, 
            iv: encryptedData.iv
        });

        await newNote.save();
        res.status(201).json({ message: "Note secured successfully" });
    } catch (err) {
        console.error(err); 
        res.status(500).json({ error: "Failed to store note" });
    }
});
// Route to fetch all secure notes for the logged-in user
router.get('/get-all-notes', authenticate, async (req, res) => {
    try {
        // We use req.rootUser._id because that matches the 'user' field in your MongoDB screenshot
        const notes = await Note.find({ user: req.rootUser._id });
        
        // This log will help you verify in your VS Code terminal
        console.log(`Found ${notes.length} notes for user ${req.rootUser._id}`);
        
        res.status(200).json(notes);
    } catch (err) {
        console.error("Fetch error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// Add this specific route for notes
router.post('/delete-note', authenticate, async (req, res) => {
    try {
        const { id } = req.body;
        
        // Use your Note model here
        const deletedNote = await Note.findByIdAndDelete(id);

        if (!deletedNote) {
            return res.status(404).json({ error: "Note not found" });
        }

        res.status(200).json({ message: "Note deleted successfully" });
    } catch (err) {
        console.error("Delete Error:", err);
        res.status(500).json({ error: "Server error during deletion" });
    }
});

module.exports = router;