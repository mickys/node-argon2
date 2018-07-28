const bufferFile = "buffer.dat";
const argon2 = require('argon2');
var fs = require('fs');

const opt = {
    salt: Buffer.from("Satoshi_is_Finney"),
    timeCost: 2,
    memoryCost: 256,
    parallelism: 2,
    type: argon2.argon2d,
    hashLength: 32,
    raw: true,
};

let buffer;

function readFileAsync(path) {
    return new Promise(function (resolve, reject) {
        fs.readFile(path, function (error, result) {
            if (error) {
                reject(error);
            } else {
                resolve(result);
            }
        });
    });
}

const setup = async () => {
    buffer = await readFileAsync(bufferFile);
}

const doOne = async () => {
    try {
        let hash = await argon2.hash(buffer, opt);
        console.log(hash);
    }
    catch (error) {
        // Handle error
    }
};

let hashCounter = 0;
let seconds = 1;
let maxTime = 60;
let hashTable = [];

const doTest = async () => {

    let hashSolo = await argon2.hash(buffer, opt);
    console.log("solo:     ", hashSolo);

    let perBatch = 5;

    let b = await Buffer.from(buffer);
    let sendBuffers = Array();
    let i = 0;
    while(i < perBatch) {
        sendBuffers[i] = b;
        i++;
    }

    let hashes = await argon2.batch(sendBuffers, opt);
    console.log("multiple: ", hashes);

    let c = Buffer.from(buffer);
    c[0] = 1;
    let buffers2 = [c, b, b, c, c];
    let hashes2 = await argon2.batch(buffers2, opt);
    console.log("multiple: ", hashes2);


};


const doSolo = async (maxSeconds) => {

    while(seconds <= maxSeconds) {
        let hashSolo = await argon2.hash(buffer, opt);
        hashCounter++;
    }
};


const doOneInBatch = async (maxSeconds) => {

    let perBatch = 1;

    let b = await Buffer.from(buffer);
    let sendBuffers = [b];

    while(seconds <= maxSeconds) {
        let hashes2 = await argon2.batch(sendBuffers, opt);
        hashCounter+=perBatch;
    }
};


const doBatch = async (maxSeconds) => {

    let perBatch = 100;

    let b = await Buffer.from(buffer);
    let sendBuffers = Array();
    let i = 0;
    while(i < perBatch) {
        sendBuffers[i] = b;
        i++;
    }

    while(seconds <= maxSeconds) {
        let hashes2 = await argon2.batch(sendBuffers, opt);
        hashCounter+=perBatch;
    }
    console.log("done");
};



const showHashesPerSecond = () => {

    hashTable.push( hashCounter );
    // console.log(hashTable);
    var total = 0;

    for(var i = 0; i < hashTable.length; i++) {
        total+=hashTable[i];
    }
    var avg = total / hashTable.length;

    console.log("seconds[",seconds,"] current: "+hashCounter+" hashes. Average:", avg);
    hashCounter = 0;
    seconds++;

    if(seconds <= maxTime) {
        setTimeout(showHashesPerSecond, 1000);
    } else {
        console.log("Run complete");
    }
}


setup().then(function(){

    var time = 30;
    var mode = process.argv[2].split("=")[1];

    maxTime = time;
    console.log("Starting mode: "+mode+" / run seconds: "+time);

    if(mode === "solo") {
        doSolo(time);
    }
    else if(mode === "batchone") {
        doOneInBatch(time);
    }
    else if(mode === "batch") {
        doBatch(time);
    }
    else if(mode === "test") {
        doTest()
    }

    setTimeout(showHashesPerSecond, 1000);
});



