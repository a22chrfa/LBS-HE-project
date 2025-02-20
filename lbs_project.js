(async () => {
    process.stdout.write("\x1Bc");
    const fs = require('fs');
    const path = require('path');
    const outputFilePath = path.join(__dirname, 'results.csv');

    const GeographicLib = require("geographiclib");
    const geod = GeographicLib.Geodesic.WGS84;

    if (fs.existsSync(outputFilePath)) {
        fs.unlinkSync(outputFilePath);
        console.log(`Deleting existing file: ${outputFilePath}`);
    }
    console.log(`Creating new file: ${outputFilePath}`);

    const headers = `"Iteration","Encrypted time (ms)","Unencrypted time (ms)","Encrypted distance (km)","Unencrypted distance (km)","Karney distance ref (km)"\n`;
    fs.appendFileSync(outputFilePath, headers, 'utf8');

    /* ------ https://github.com/LenaSYS/Random-Number-Generator/blob/master/seededrandom.js ------ */
    // Jenkins small fast with replace .random() for deterministic random numbers
    function jsf32(a, b, c, d) {
        a |= 0; b |= 0; c |= 0; d |= 0;
        var t = a - (b << 23 | b >>> 9) | 0;
        a = b ^ (c << 16 | c >>> 16) | 0;
        b = c + (d << 11 | d >>> 21) | 0;
        b = c + d | 0;
        c = d + t | 0;
        d = a + t | 0;
        return (d >>> 0) / 4294967296;
    }

    Math.random = function () {
        let ran = jsf32(0xF1EA5EED, Math.randSeed + 6871, Math.randSeed + 1889, Math.randSeed + 56781);
        Math.randSeed += Math.floor(ran * 37237);
        return (ran)
    }

    Math.setSeed = function (seed) {
        Math.randSeed = seed;
        for (let i = 0; i < 7; i++) Math.random();
    }


    /* ------------------------------- Encryption settings and instance ------------------------------- */
    const SEAL = require('node-seal');
    const seal = await SEAL();

    // Set the scheme type and security level
    const schemeType = seal.SchemeType.ckks;
    const securityLevel = seal.SecurityLevel.tc192;
    const n_polyModulusDegree = 16384;
    const modulusChain = [60, 40, 30, 30, 30, 30];
    const scale = Math.pow(2, 20);

    const parms = seal.EncryptionParameters(schemeType);
    parms.setPolyModulusDegree(n_polyModulusDegree);
    parms.setCoeffModulus(seal.CoeffModulus.Create(n_polyModulusDegree, Int32Array.from(modulusChain)));
    console.log("\nInitializing context");
    const context = seal.Context(parms, false, securityLevel);

    if (!context.parametersSet()) {
        throw new Error(
            'Encryption parameters not valid'
        );
    }
    const ckksEncoder = seal.CKKSEncoder(context);
    const keyGenerator = seal.KeyGenerator(context);
    const publicKey = keyGenerator.createPublicKey();
    const secretKey = keyGenerator.secretKey();
    const encryptor = seal.Encryptor(context, publicKey);
    const decryptor = seal.Decryptor(context, secretKey);
    const evaluator = seal.Evaluator(context);

    /* ------------------------------- Client side data and conversions ------------------------------- */
    const R = 6371; // Earth's radius in km
    const max_iterations = 100;
    console.log('\nPerforming encryption and calculations...');

    for (let i = 0; i < max_iterations + 1; i++) {
        Math.setSeed(i);
        
        //CLIENT A
        //coordinates
        let client_A_latitude = (Math.random() * 180 - 90).toFixed(5); //phi
        let client_A_longitude = (Math.random() * 360 - 180).toFixed(5); //lambda

        //convert to radians
        let client_A_latitude_radian = client_A_latitude * (Math.PI / 180);
        let client_A_longitude_radian = client_A_longitude * (Math.PI / 180);

        //convert to cartesian
        let X_A = R * Math.cos(client_A_latitude_radian) * Math.cos(client_A_longitude_radian);
        let Y_A = R * Math.cos(client_A_latitude_radian) * Math.sin(client_A_longitude_radian);
        let Z_A = R * Math.sin(client_A_latitude_radian);

        // CLIENT B
        //coordinates
        let client_B_latitude = (Math.random() * 180 - 90).toFixed(5);
        let client_B_longitude = (Math.random() * 360 - 180).toFixed(5);

        //convert to radians
        let client_B_latitude_radian = client_B_latitude * (Math.PI / 180);
        let client_B_longitude_radian = client_B_longitude * (Math.PI / 180);

        //convert to cartesian
        let X_B = R * Math.cos(client_B_latitude_radian) * Math.cos(client_B_longitude_radian);
        let Y_B = R * Math.cos(client_B_latitude_radian) * Math.sin(client_B_longitude_radian);
        let Z_B = R * Math.sin(client_B_latitude_radian);

        //CLIENT A AND B ENCRYPTIONS
        //store in array
        let arr_X_A = Float64Array.from([X_A]);
        let arr_Y_A = Float64Array.from([Y_A]);
        let arr_Z_A = Float64Array.from([Z_A]);
        let arr_X_B = Float64Array.from([X_B]);
        let arr_Y_B = Float64Array.from([Y_B]);
        let arr_Z_B = Float64Array.from([Z_B]);

        //encode values
        let encoded_X_A = ckksEncoder.encode(arr_X_A, scale);
        let encoded_Y_A = ckksEncoder.encode(arr_Y_A, scale);
        let encoded_Z_A = ckksEncoder.encode(arr_Z_A, scale);
        let encoded_X_B = ckksEncoder.encode(arr_X_B, scale);
        let encoded_Y_B = ckksEncoder.encode(arr_Y_B, scale);
        let encoded_Z_B = ckksEncoder.encode(arr_Z_B, scale);

        //encrypt encoded values
        let encrypted_X_A = encryptor.encrypt(encoded_X_A);
        let encrypted_Y_A = encryptor.encrypt(encoded_Y_A);
        let encrypted_Z_A = encryptor.encrypt(encoded_Z_A);
        let encrypted_X_B = encryptor.encrypt(encoded_X_B);
        let encrypted_Y_B = encryptor.encrypt(encoded_Y_B);
        let encrypted_Z_B = encryptor.encrypt(encoded_Z_B);

        /* ------------------------------- Server side computations ------------------------------- */
        //ENCRYPTED COMPUTATIONS
        let encrypted_time_start = process.hrtime();
        let encrypted_delta_x = evaluator.sub(encrypted_X_A, encrypted_X_B);
        let encrypted_delta_y = evaluator.sub(encrypted_Y_A, encrypted_Y_B);
        let encrypted_delta_z = evaluator.sub(encrypted_Z_A, encrypted_Z_B);

        let encrypted_delta_x_sq = evaluator.multiply(encrypted_delta_x, encrypted_delta_x);
        let encrypted_delta_y_sq = evaluator.multiply(encrypted_delta_y, encrypted_delta_y);
        let encrypted_delta_z_sq = evaluator.multiply(encrypted_delta_z, encrypted_delta_z);
        let encrypted_sum_sq_1 = evaluator.add(encrypted_delta_x_sq, encrypted_delta_y_sq);
        let encrypted_sum_sq = evaluator.add(encrypted_sum_sq_1, encrypted_delta_z_sq);
        let decrypted_sum = decryptor.decrypt(encrypted_sum_sq);
        let decoded_sum = ckksEncoder.decode(decrypted_sum);
        let encrypted_distance_float = parseFloat(decoded_sum[0]);
        let encrypted_distance = Math.sqrt(encrypted_distance_float);
        let encrypted_time_stop = process.hrtime(encrypted_time_start);

        //UNENCRYPTED COMPUTATIONS FOR COMPARISON
        unencrypted_time_start = process.hrtime();
        let deltaX = X_A - X_B;
        let deltaY = Y_A - Y_B;
        let deltaZ = Z_A - Z_B;

        let squareSum = deltaX ** 2 + deltaY ** 2 + deltaZ ** 2;
        let unencrypted_distance = Math.sqrt(squareSum);
        let unencrypted_time_stop = process.hrtime(unencrypted_time_start);

        // Karney (geographiclib)
        let karney_result = geod.Inverse(
            parseFloat(client_A_latitude), 
            parseFloat(client_A_longitude), 
            parseFloat(client_B_latitude), 
            parseFloat(client_B_longitude)
        );

        //STORE DATA
        let encrypted_time = (encrypted_time_stop[0] * 1000 + (encrypted_time_stop[1] / 1000000));
        let unencrypted_time = (unencrypted_time_stop[0] * 1000 + (unencrypted_time_stop[1] / 1000000));

        if(i > 0) {
            if ((max_iterations + 1 - i) % 50 === 0) {
                console.log("Item: ", max_iterations + 1 - i);
            }
            const csvData = `${i},${encrypted_time},${unencrypted_time},${encrypted_distance.toFixed(5)},${unencrypted_distance.toFixed(5)},${((karney_result.s12 / 1000).toFixed(5))}\n`;
            fs.appendFileSync(outputFilePath, csvData, 'utf8');

        }

        //FREE UP MEMORY
        encrypted_X_A.delete();
        encrypted_Y_A.delete();
        encrypted_Z_A.delete();
        encrypted_X_B.delete();
        encrypted_Y_B.delete();
        encrypted_Z_B.delete();
        encrypted_delta_x.delete();
        encrypted_delta_y.delete();
        encrypted_delta_z.delete();
        encrypted_delta_x_sq.delete();
        encrypted_delta_y_sq.delete();
        encrypted_delta_z_sq.delete();
        encrypted_sum_sq_1.delete();
        encrypted_sum_sq.delete();
        decrypted_sum.delete();
        encoded_X_A.delete();
        encoded_Y_A.delete();
        encoded_Z_A.delete();
        encoded_X_B.delete();
        encoded_Y_B.delete();
        encoded_Z_B.delete();
    }

    context.delete();
    keyGenerator.delete();
    publicKey.delete();
    secretKey.delete();
    encryptor.delete();
    decryptor.delete();
    evaluator.delete();
    ckksEncoder.delete();
    parms.delete();

    console.log("\nDone!");
})();