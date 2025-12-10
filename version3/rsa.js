const readline = require('node:readline'); // https://nodejs.org/api/readline.html

// Euklids algoritme fra: https://www.geeksforgeeks.org/dsa/eulers-totient-function/
function gcd(a, b){
    if (a === 0n){
        return b;
    }
    return gcd(b % a, a)
}

// Modifiseret udgave af kodestykket fra: https://www.geeksforgeeks.org/dsa/multiplicative-inverse-under-modulo-m/ 
function extendedEuclidean(a, b){

    // Base case
    if (a === 0n) 
    {
        return [b, 0n, 1n];
    }

    // Rekursivt kald til at finde største fælles divisor, og fremskaffe værdierne for tidligere x og y.
    const [gcd, x1, y1] = extendedEuclidean(b % a, a);

    // Recurssive substitution for extended euclidian methoer.
    const x = y1 - ((b / a) | 0n) * x1;
    const y = x1;

    return [gcd, x, y];
};

// Modifiseret udgave af kodestykket fra: https://www.geeksforgeeks.org/dsa/multiplicative-inverse-under-modulo-m/ 
function modInverse(a, m) {  
    // Executes extended euclidian method, to find value of X.
    const [gcd, x, _] = extendedEuclidean(a, m);

    if (gcd !== 1n) {
        throw new Error("The modular inverse does not exist.");
    }
    
    return (x % m + m) % m;
}

// Credit: https://www.geeksforgeeks.org/computer-networks/rsa-algorithm-cryptography/
function power(base, expo, m) {
    let res = 1n; 
    base = base % m; 
    while (expo > 0) {
        if (expo & 1n) {
            res = (res * base) % m;
        };
        base = (base * base) % m; 
        expo >>= 1n; //Division by 2, by bitwise shift. 
    };
    return res;
};

// Skabelse af krypteringsnøgler, ud fra primtal p og q
function generateKeys(p, q){
    const n = p * q;
    const phi = (p - 1n) * (q - 1n);

    let e = 2n;
    while (e < phi) {
        if (gcd(e, phi) === 1n) break;
        e++;
    };

    const d = modInverse(e, phi);
    return { e, d, n };
};

function encrypt(M, e, n){ // Kryptering af M med Public Key
    return power(M, e, n); 
};

function decrypt(C, d, n){ // Dekryptering af C med Private Key
    return power(C, d, n); 
};

var current_info = {
    p: 99563n,
    q: 15647n,
    M: 123n,
}

function executeRSA(){
    const { e, d, n } = generateKeys(current_info.p, current_info.q) // Fremskaffer krypteringsnøgler
    console.log(`Public Key = (${n}, ${e})`)
    console.log(`Private Key = (${n}, ${d})`)

    console.log(`Plaintext = ${current_info.M}`)
    const C = encrypt(current_info.M, e, n) // Udregner cipherteksten for M
    console.log(`Chipertext = ${C}`)
    const M2 = decrypt(C, d, n)
    console.log(`Decrypted plaintext = ${M2}`)

    if (current_info.M === M2){
        console.log(`SUCCESS: Decrypted text matches the plaintext`)
    }else{
        console.log(`FAIL: Decrypted text does not match plaintext`)
    }

    rl.close() // Lukker readline interface fra NodeJS, så programmet kan stoppe.
}

function requestEncryptionValue(){
    rl.question(`\nHvilken talværdi vil du kryptere? (Default: ${current_info.M}) \n`, val => {
        if (val.includes(" ") || val === ""){ 
            requestPValue();
            return;
         }

        if (val.includes(".")){
            console.log("FEJL. Skal være et heltal")
            requestEncryptionValue()
            return;
        }

        var num = Number(val)
        if (isNaN(num)){ 
            console.log("FEJL. Kan ikke være andet end tal")
            requestEncryptionValue()
            return;
        }
        current_info.M = BigInt(num)
        requestPValue()
    })
}

function requestPValue(){
    rl.question(`\nHvilket primtal skal p være? (Default: ${current_info.p}) \n`, val => {
        if (val.includes(" ") || val === ""){
            requestQValue();
            return;
        }

        if (val.includes(".")){
            console.log("FEJL. Skal være et heltal")
            requestPValue()
            return;
        }

        var num = Number(val)
        if (isNaN(num)){ 
            console.log("FEJL. Kan ikke være andet end tal")
            requestPValue() 
            return;
        }

        current_info.p = BigInt(num)
        requestQValue()
    })
}


function requestQValue(){
    rl.question(`\nHvilket primtal skal q være? (Default: ${current_info.q}) \n`, val => {
        if (val.includes(" ") || val === ""){
            executeRSA()
            return;
        }

        if (val.includes(".")){
            console.log("FEJL. Skal være et heltal")
            requestQValue()
            return;
        }

        var num = Number(val)
        if (isNaN(num)){ 
            console.log("FEJL. Kan ikke være andet end tal")
            requestQValue() 
            return;
        }

        current_info.q = BigInt(num)
        executeRSA()
    })
}

const rl = readline.createInterface({ // Konsol input håndtering. Credit: https://nodejs.org/api/readline.html
    input : process.stdin,
    output : process.stdout
})

requestEncryptionValue()

module.exports = { encrypt, decrypt, generateKeys, power, gcd, modInverse, extendedEuclidean } // Exportering til anvendelse i benchmark.js
