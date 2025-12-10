const process = require('process');
const fs = require('node:fs');
const crypto = require('crypto');

const RSA = require('./rsa.js'); // RSA object with reference methods.

function generateNextKeys(){
    const [p, q] = get_next_prime_pair()
    return RSA.generateKeys(p, q)
}

var prime_pairs = []
var index = 0 

function get_next_prime_pair(){ // Giver det næste primtal i rækken fra prime_pairs
    index++
    if (index >= prime_pairs.length){
        return prime_pairs[prime_pairs.length]
    }
    return prime_pairs[index]
}

var min_bits = 6 // Mindste størrelse i bits for primtallende
var max_bits = 512 // Største størrelse i bits for primtallende
var pairs_with_bits = 24 // Hvor mange primtals par skal udregnes per inkrement mellem minimum og maksimum

function recalculate_prime_pairs(){ // Udregner primtal indenfor max og minimum, ved brug af NodeJS crypto bibliotek
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
}

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
            p = RSA.gcd(x - y, n);
        }else{
            p = RSA.gcd(y - x, n);
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
            csv_data.brute_force.push({BitCount: bitCount, Time: Math.round(Number(end - start))})
        }
    }

    if (!p || p === n){
        return { time: "Failed" };
    }

    const q = n / p

    const averageNanoSeconds = Math.round(Number(totalNanoSeconds) / iterations)
    csv_data.brute_force_average.push({BitCount: bitCount, Time: averageNanoSeconds})


    return {
        N: n,
        BitCount: bitCount,
        AverageTime: (averageNanoSeconds / 1e6).toFixed(4),
        P : Number(p),
        Q : Number(q)
    };
}


function runEncryptionBenchmark(iterations = 5){
    const { e, d, n } = generateNextKeys()
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
        EkpsonentBitSize : d.toString(2).split('').filter(bit => bit === '1').length,
    })

    return {
        N : n,
        NBitCount : ModBitCount,
        AvgEncTime : averageEncryptionTime,
        AvgDecTime : averageDecryptionTime
    }
}

function runEncDecTest(M = 0n, printToConsole = false){
    const { e, d, n } = generateNextKeys()
    const C = RSA.encrypt(M, e, n)
    const decryptedM = RSA.decrypt(C, d, n)

    if(printToConsole){
        console.log("Public_key (" + n + ", " + e + ")")
        console.log("Private_key (" + n + ", " + d + ")")
        console.log(`Original:  ${M}`);
        console.log(`Encrypted: ${C}`);
        console.log(`Decrypted: ${decryptedM}`);
    }

    if (decryptedM !== M){
        console.log("Decryption failed")
    }else{
        console.log("Encryption success")
    }

}

var csv_data = { // Objekt der indeholder arrays, som bliver gemt i seperate .csv filer
    encryption : [],
    decryption : [],
    brute_force : [],
    brute_force_average : []
}

const csvmaker = function (data) { // Omdanner et javascript array med js objekter, til et array der passer .csv formattet.
    let csvRows = [];

    const headers = Object.keys(data[0]);

    csvRows.push(headers.join(','));

    for (let i = 0; i < data.length; i++){
        const values = Object.values(data[i]).join(',');
        csvRows.push(values);
    }

    return csvRows.join('\n');
}

function main() {
    console.log("\nINITIAL: Generating prime values \n");
    recalculate_prime_pairs()
    console.log("Successfully generated desired primes")

    console.log("\nPART 1: RSA Encryption/Decryption Proof \n");
    
    runEncDecTest(123n, true)

    const start = process.hrtime.bigint()
    console.log("\nPART 2: RSA Encryption and Decryption Benchmark \n");
    index = -1

    for (let i = 0; i < prime_pairs.length; i++){
        runEncryptionBenchmark()
    }
    const end1 = process.hrtime.bigint()
    var time = (Number(end1 - start) / 1e9).toFixed(4)
    console.log("Finished encryption and decryption Benchmark in " + time + "s")

    console.log("\PPREWORK: Regenerating prime values for part 3\n");
    pairs_with_bits *= 8
    recalculate_prime_pairs()

    console.log("\nPART 3: Brute force by factorisation Benchmark \n");

    index = -1
    const full_run_time = process.hrtime.bigint()
    var run_time = process.hrtime.bigint()
    for (let i = 0; i < prime_pairs.length; i++){
        runFactorBenchmark(generateNextKeys().n)

        const current_time = process.hrtime.bigint()
        const diff = current_time - run_time
        if (Number(diff) / 1e9 >= auto_save_interval){
            run_time = current_time
            save_data_to_csv(auto_save_index)
            console.log(`STATUS: Automatically saved after running for ${Math.round(Number(current_time - full_run_time) / 1e9)} seconds. Current file index is ${auto_save_index}, and current prime increment is ${6 + i / pairs_with_bits}`)
        }
    }
    const end2 = process.hrtime.bigint()
    time = ((Number(end2 - start) / 1e9) - time).toFixed(4)

    console.log("Finished Brute Force Benchmark in " + time + "s")

    //return; //In place to stop file saving while testing
    console.log("\n END: Saving data to CSV files \n");

    save_data_to_csv()
    //console.table(results)
};


var auto_save_index = -2
const auto_save_interval = 300 // In seconds
const file_index = 4
function save_data_to_csv(index = file_index){
    for (let i = 0; i < Object.keys(csv_data).length; i++){
        const PATH = `/Users/david/desktop/sop_projekt/test_results/`
        const key = Object.keys(csv_data)[i]
        fs.writeFileSync(`${PATH}${key}${index}.csv`, csvmaker(csv_data[key]), err => {
            if (err) {
                console.error(err)
                if (index !== file_index){
                    auto_save_index--
                    save_data_to_csv(auto_save_index)
                }
            }else{
                console.log(`* Successfully written ${key} data to csv`)
            }
        })
    }
}




main()

