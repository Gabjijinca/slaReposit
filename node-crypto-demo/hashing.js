const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const senha = "Mazini@Anderson123";


const sha256Hash = crypto.createHash('sha256').update(senha).digest('hex');
console.log("SHA-256 Hash:", sha256Hash);

const saltRounds = 10;
bcrypt.hash(senha, saltRounds, (err, bcryptHash) => {
    if (err) throw err;
    console.log("Bcrypt Hash:", bcryptHash);

    bcrypt.compare(senha, bcryptHash, (err, result) => {
        console.log("A senha está correta?", result);
    });
});
