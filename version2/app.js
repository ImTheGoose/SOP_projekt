const process = require('process')

// ----------------------------------
// 1. Kildekoden for RSA algoritmen.
// ----------------------------------

// Greatest common divisor using Euklidian Algorithm, whilst also finding x and y using the Extended Euklidian Algorithm
function gcdExtended(a, b){
     
    // Base Case
    if (a == 0n)
    {
        x = 0n;
        y = 1n;
        return b;
    }
     
    // To store results of recursive call    
    let gcd = gcdExtended(b % a, a);
    let x1 = x;
    let y1 = y;

    // Update x and y using results of recursive
    // call
    x = y1 - (b / a) * x1;
    y = x1;
 
    return gcd;
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




// ==========================================
// 2. RSA IMPLEMENTATION
// ==========================================
let index = 0

const prime_pairs = [
    [31731677n, 12113251n],
    [158888063n, 752705693n],
    [7438438729n, 6895530373n],
    [10947530563n, 89726011433n],
    [314052540757n, 752964439301n]
]

const RSA = {
    generateKeys: () => {
        // Fixed small primes for demonstration
        var primes = RSA.get_prime_set()
        const p = primes[0];
        const q = primes[1];
        const n = p * q;
        const phi = (p - 1n) * (q - 1n);

        let e = 2n;
        while (e < phi) {
            const [gcd, _, __] = extendedEuclidean(e, phi)
            if (gcd === 1n) break;
            e++;
        }

        const d = modInverse(e, phi);
        return { e, d, n };
    },

    get_prime_set(){
        index++
        if (index >= prime_pairs.length){
            index = 0
        }
        return prime_pairs[index]
    },

    encrypt: (m, e, n) => power(m, e, n),
    decrypt: (c, d, n) => power(c, d, n)
};

// ==========================================
// 3. POLLARD'S RHO (FACTORIZATION)
// ==========================================

function pollardsRho(N) {
    if (N % 2n === 0n) return 2n;

    let x = 2n, y = 2n, d = 1n;
    const c = 1n;

    while (d === 1n) {
        // Tortoise (x) moves 1 step, Hare (y) moves 2 steps
        x = (x * x + c) % N;
        y = (y * y + c) % N;
        y = (y * y + c) % N;

        // Check for common factor
        const diff = (x > y) ? (x - y) : (y - x);
        const [gcd, _, __] = extendedEuclidean(diff, N)
        d = gcd;

        if (d === N) return null; // Failure (cycle detected)
    }
    return d;
}

// ==========================================
// 4. BENCHMARKING ENGINE (Node.js)
// ==========================================

function runBenchmark(label, N, iterations = 20) {
    let totalNs = 0n;
    let successCount = 0;

    // Warm-up run (optimizes JIT compiler)
    pollardsRho(N); 

    var p = 0

    for (let i = 0; i < iterations; i++) {
        const start = process.hrtime.bigint();
        const result = pollardsRho(N);
        const end = process.hrtime.bigint();

        if (result && result !== N) {
            totalNs += (end - start);
            p = result
            successCount++;
        }
    }

    if (successCount === 0) return { label, time: "Failed" };

    var q = N / p

    // Convert nanoseconds to milliseconds (float)
    const avgNs = Number(totalNs) / successCount;
    console.log("Finished benchmark of key with size: " + label + " with total time of " + totalNs + " (ms)")
    return {
        "Key Size": label,
        "Modulus (N)": N.toString().slice(0, 10) + "...", // Truncate for display
        "Digits": N.toString().length,
        "Time (ms)": (avgNs / 1e6).toFixed(4),
        "P" : p,
        "q" : q
    };
}


// ==========================================
// 5. MAIN EXECUTION
// ==========================================

function main() {
    console.log("\n🔹 PART 1: RSA Encryption/Decryption Proof\n");
    
    const { e, d, n } = RSA.generateKeys();
    const message = 123n;
    const encrypted = RSA.encrypt(message, e, n);
    const decrypted = RSA.decrypt(encrypted, d, n);

    console.log("Public_key (" + n + ", " + e + ")")
    console.log("Private_key (" + n + ", " + d + ")")


    console.log(`Original:  ${message}`);
    console.log(`Encrypted: ${encrypted}`);
    console.log(`Decrypted: ${decrypted}`);
    console.log(decrypted === message ? "✅ SUCCESS" : "❌ FAILED");

    console.log("\n" + "=".repeat(50));
    console.log("\n🔹 PART 2: Factorization Complexity Benchmark");
    console.log("   Measuring time to break keys of increasing size...\n");

    // Test Cases: N = p * q
    const testVectors = [
        { bits: "8-digit", N: n },
        
        // --- NEW, LARGER TEST CASES ---
        // 85-bit: Approx. 26 decimal digits
        { bits: "9-digit", N: RSA.generateKeys().n }, 
        
        // 90-bit: Approx. 28 decimal digits
        { bits: "10-digit", N: RSA.generateKeys().n }, 
        
        // 95-bit: Approx. 29 decimal digits
        { bits: "11-digit", N: RSA.generateKeys().n }, 
        
        // 100-bit: Approx. 31 decimal digits. This is the largest, demanding run.
        { bits: "12-digit", N: RSA.generateKeys().n }
    ];
    index = 9999
    const results = testVectors.map(v => runBenchmark(v.bits, v.N));
    
    // Display results in a clean table
    console.table(results);

};

main()