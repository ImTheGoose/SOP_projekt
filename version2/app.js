const process = require('process')
const fs = require('node:fs');
const crypto = require('crypto');

// ----------------------------------
// 1. Generelle funktioner til anvendelse af RSA algoritmen.
// ----------------------------------


function gcd(a, b) {
    while (b !== 0n) {
        let t = b;
        b = a % b;
        a = t;
    }
    return a;
}

// Credit: https://github.com/AlienWashim/RSA-Encryption-Decryption-Algorithm/blob/main/java.js
function extendedEuclidean(a, b){

    // Base case where the divison results in a modulus of 0
    if (a === 0n) 
    {
        return [b, 0n, 1n];
    }

    // Recurssive call for finding createst common divisor
    const [gcd, x1, y1] = extendedEuclidean(b % a, a);

    // Recurssive substitution for extended euclidian methoer.
    const x = y1 - ((b / a) | 0n) * x1;
    const y = x1;

    return [gcd, x, y];
};

// Credit: https://github.com/AlienWashim/RSA-Encryption-Decryption-Algorithm/blob/main/java.js
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
        }
        base = (base * base) % m; 
        expo >>= 1n; //Division by 2, by bitwise shift. (Check test1 for clarrification)
    }
    return res;
}


// ----------------------------------
// 2. Udførsel af RSA algortimen.
// ----------------------------------

const min_bits = 6
const max_bits = 512
const pairs_with_bits = 24
var index = 0

var prime_pairs = [
]

const RSA = {
    generateKeys: () => {
        let primes = RSA.get_prime_pair()
        const p = primes[0];
        const q = primes[1];
        const n = p * q;
        const phi = (p - 1n) * (q - 1n);

        let e = 2n;
        while (e < phi) {
            if (gcd(e, phi) === 1n) break;
            e++;
        }

        const d = modInverse(e, phi);
        return { e, d, n };
    },

    recalculate_prime_pairs(){ // Udregner primtal indenfor max og minimum, ved brug af NodeJS crypto bibliotek
        prime_pairs = []

        for (let i = min_bits; i < max_bits; i++){
            for (let p = 0; p < pairs_with_bits; p++){
                let pair = []
                const bits = i
                pair.push(crypto.generatePrimeSync(bits, {"bigint": true}))
                pair.push(crypto.generatePrimeSync(bits, {"bigint": true}))
                prime_pairs.push(pair)
            }

        }
    },

    get_prime_pair(){ // Giver det næste primtal i rækken fra prime_pairs
        index++
        if (index >= prime_pairs.length){
            return prime_pairs[prime_pairs.length]
        }
        return prime_pairs[index]
    },

    encrypt: (m, e, n) => power(m, e, n), // Kryptering af M med Public Key
    decrypt: (c, d, n) => power(c, d, n) // Dekryptering af C med Private Key
};

// ----------------------------------
// 3. Brute force funktionalitet gennem faktorisering af n, for at finde p.
// ----------------------------------


// Javascript implementering af Pollards Rho algoritmen, basseret på python kode fra: https://www.numberanalytics.com/blog/pollards-rho-algorithm-guide
function pollardsRho(n, c = 1n) {
    if (n % 2n === 0n){
        return 2n;
    };

    let x = 2n;
    let y = 2n;
    let p = 1n; 
    
    while (p === 1n) {

        x = ((x * x) % n + c + n) % n;
        y = ((y * y) % n + c + n) % n;
        y = ((y * y) % n + c + n) % n;

        if (x > y){
            p = gcd(x - y, n);
        }else{
            p = gcd(y - x, n);
        }

        if (p === n) return pollardsRho(n, BigInt(Math.floor(Math.random() * 10))); // In case of failed, retries with a random seed.
    };
    return p;
}

function runFactorBenchmark(n, iterations = 2){ // Anvender pollards rho algoritme til at faktorisere n.
    const bitCount = n.toString(2).split('').filter(bit => bit === '1').length;
    let totalNanoSeconds = 0n;
    var p = 0;

    for (let i = 0; i < iterations; i++){ // Gentages for at finde en gennemsnitshastighed for faktorisering, som kan forbedre kvaliteten af data.
        const start = process.hrtime.bigint()
        const result = pollardsRho(n)
        const end = process.hrtime.bigint()

        totalNanoSeconds += (end - start);

        if (result && result !== n){
            p = result
            csv_data.brute_force.push({BitCount: bitCount, Time: (end - start)})
        }
    }

    if (!p || p === n){
        return { time: "Failed" };
    }

    const q = n / p

    const averageNanoSeconds = Number(totalNanoSeconds) / iterations
    csv_data.brute_force_average.push({BitCount: bitCount, Time: averageNanoSeconds})


    return {
        N: n, // n.toString().slice(0, 10) + "...", // Truncate for display
        BitCount: bitCount,
        AverageTime: (averageNanoSeconds / 1e6).toFixed(4),
        P : Number(p),
        Q : Number(q)
    };
}

function runEncryptionBenchmark( iterations = 5){
    const { e, d, n } = RSA.generateKeys()
    const plaintextBigInt = 123n
    const ModBitCount = n.toString(2).split('').filter(bit => bit === '1').length;
    var totalEncryptionTime = 0n;
    var totalDecryptionTime = 0n;
    var encryptedValue = 0n

    for (let i = 0; i < iterations; i++){
        const start1 = process.hrtime.bigint()
        encryptedValue = RSA.encrypt(plaintextBigInt, e, n)
        const end1 = process.hrtime.bigint()



        const start2 = process.hrtime.bigint()
        const decryptedValue = RSA.decrypt(encryptedValue, d, n)
        const end2 = process.hrtime.bigint()
        totalEncryptionTime += end1 - start1
        totalDecryptionTime += end2 - start2


    }

    const averageEncryptionTime = Number(totalEncryptionTime) / iterations
    const averageDecryptionTime = Number(totalDecryptionTime) / iterations

    csv_data.encryption.push({
        Time: averageEncryptionTime,
        ModBitCount: ModBitCount,
        PlaintextBitCount: plaintextBigInt.toString(2).split('').filter(bit => bit === '1').length,
        Eksponent: e,
    })

    csv_data.decryption.push({
        Time: averageDecryptionTime,
        ModBitCount : ModBitCount,
        CipherBitCount : encryptedValue.toString(2).split('').filter(bit => bit === '1').length,
    })


    return {
        N : n,
        NBitCount : ModBitCount,
        AvgEncTime : averageEncryptionTime,
        AvgDecTime : averageDecryptionTime
    }


}

const csvmaker = function (data) {
    let csvRows = [];

    const headers = Object.keys(data[0]);

    csvRows.push(headers.join(','));

    for (let i = 0; i < data.length; i++){
        const values = Object.values(data[i]).join(',');
        csvRows.push(values);
    }

    return csvRows.join('\n');
}



// ==========================================
// 5. MAIN EXECUTION
// ==========================================

var csv_data = {
    encryption : [],
    decryption : [],
    brute_force : [],
    brute_force_average : []
}

function main() {
    console.log("\nINITIAL: Generating prime values \n");
    RSA.recalculate_prime_pairs()
    console.log("Successfully generated desired primes")

    console.log("\nPART 1: RSA Encryption/Decryption Proof \n");
    
    const { e, d, n } = RSA.generateKeys();
    const message = 123n;
    const encrypted = RSA.encrypt(message, e, n);
    const decrypted = RSA.decrypt(encrypted, d, n);

    console.log("Public_key (" + n + ", " + e + ")")
    console.log("Private_key (" + n + ", " + d + ")")


    console.log(`Original:  ${message}`);
    console.log(`Encrypted: ${encrypted}`);
    console.log(`Decrypted: ${decrypted}`);
    console.log(decrypted === message ? "DECRYPTION SUCCESS" : "DECRYPTION FAILED");

    const start = process.hrtime.bigint()
    console.log("\nPART 2: RSA Encryption and Decryption Benchmark \n");
    index = -1
    const amount = prime_pairs.length

    for (let i = 0; i < amount; i++){
        runEncryptionBenchmark()
    }
    const end1 = process.hrtime.bigint()
    var time = (Number(end1 - start) / 1e9).toFixed(4)
    console.log("Finished encryption and decryption Benchmark in " + time + "s")

    console.log("\nPART 3: Brute force by factorisation Benchmark \n");

    index = -1
    for (let i = 0; i < 40 * pairs_with_bits; i++){
        runFactorBenchmark(RSA.generateKeys().n)
    }
    const end2 = process.hrtime.bigint()
    time = ((Number(end2 - start) / 1e9) - time).toFixed(4)

    console.log("Finished Brute Force Benchmark in " + time + "s")
    console.log("\n END: Saving data to CSV files \n");

    const file_index = 0

    for (let i = 0; i < Object.keys(csv_data).length; i++){
        const PATH = `/Users/david/desktop/sop_projekt/test_results/`
        const key = Object.keys(csv_data)[i]
        fs.writeFile(`${PATH}${key}${file_index}.csv`, csvmaker(csv_data[key]), err => {
            if (err) {
                console.error(err)
            }else{
                console.log(`* Successfully written ${key} data to csv`)
            }
        })
    }
    //console.table(results)

};

main()

