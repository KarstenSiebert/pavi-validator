import express from "express";
import * as snarkjs from "snarkjs";
import fs from "fs";

const app = express();
app.use(express.json());

let vKey = {};
try {
    const data = fs.readFileSync("/var/www/vote/storage/app/private/build/verification_key.json", "utf-8");
    vKey = JSON.parse(data);
} catch (e) {
    console.warn("No verification_key.json found, unable to verify");
}

app.post("/verify-proof", async (req, res) => {
    try {
        const { proof, publicSignals } = req.body;

        if (!vKey || Object.keys(vKey).length === 0) {
            return res.json({ valid: false });
        }

        // console.log(JSON.stringify(publicSignals) + ' ' + JSON.stringify(proof));

        // console.log("Request occured");

        const result = await snarkjs.groth16.verify(
            vKey,
            publicSignals,
            proof
        );

        res.json({ valid: result });
    } catch (err) {
        console.error(err);
        res.status(500).json({ valid: false });
    }
});

app.listen(3009, () => {
    console.log("🚀 ZK Verifier running on http://localhost:3009");
});
