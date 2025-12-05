const process = require('process');

// ==========================================
// 1. MATHEMATICAL UTILITIES (BigInt)
// ==========================================

function gcd(a, b) {
    while (b !== 0n) {
        let t = b;
        b = a % b;
        a = t;
    }
    return a;
}

function power(base, expo, m) {
    let res = 1n;
    base %= m;
    while (expo > 0n) {
        if (expo & 1n) res = (res * base) % m;
        base = (base * base) % m;
        expo >>= 1n; // Bitwise shift (divide by 2)
    }
    return res;
}

function modInverse(e, phi) {
    for (let d = 2n; d < phi; d++) {
        if ((e * d) % phi === 1n) return d;
    }
    return -1n;
}

// ==========================================
// 2. RSA IMPLEMENTATION
// ==========================================

const RSA = {
    generateKeys: () => {
        // Fixed small primes for demonstration
        const p = 7919n;
        const q = 1009n;
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
        d = gcd(diff, N);

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

    for (let i = 0; i < iterations; i++) {
        const start = process.hrtime.bigint();
        const result = pollardsRho(N);
        const end = process.hrtime.bigint();

        if (result && result !== N) {
            totalNs += (end - start);
            successCount++;
        }
    }

    if (successCount === 0) return { label, time: "Failed" };

    // Convert nanoseconds to milliseconds (float)
    const avgNs = Number(totalNs) / successCount;
    return {
        "Key Size": label,
        "Modulus (N)": N.toString().slice(0, 10) + "...", // Truncate for display
        "Digits": N.toString().length,
        "Time (ms)": (avgNs / 1e6).toFixed(4)
    };
}

// ==========================================
// 5. MAIN EXECUTION
// ==========================================

(function main() {
    console.log("\n🔹 PART 1: RSA Encryption/Decryption Proof\n");
    
    const { e, d, n } = RSA.generateKeys();
    const message = 123n;
    const encrypted = RSA.encrypt(message, e, n);
    const decrypted = RSA.decrypt(encrypted, d, n);

    console.log(`Original:  ${message}`);
    console.log(`Encrypted: ${encrypted}`);
    console.log(`Decrypted: ${decrypted}`);
    console.log(decrypted === message ? "✅ SUCCESS" : "❌ FAILED");

    console.log("\n" + "=".repeat(50));
    console.log("\n🔹 PART 2: Factorization Complexity Benchmark");
    console.log("   Measuring time to break keys of increasing size...\n");

    // Test Cases: N = p * q
    const testVectors = [
        { bits: "40-bit", N: 998784013n },
        { bits: "50-bit", N: 1125899906842677n },
        { bits: "60-bit", N: 1152921504606846979n },
        { bits: "70-bit", N: 1180591620717411303423n },
        { bits: "80-bit", N: 12089258196146291747061761n }
    ];

    const results = testVectors.map(v => runBenchmark(v.bits, v.N));
    
    // Display results in a clean table
    console.table(results);

})();