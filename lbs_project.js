(async () => {
    console.clear();
    const SEAL = require('node-seal');
    const seal = await SEAL();

    // Set the scheme type and security level
    const schemeType = seal.SchemeType.ckks;
    const securityLevel = seal.SecurityLevel.tc128;
    const n_polyModulusDegree = 4096;
    const modulusChain = [36, 36, 37];
    const scale = Math.pow(2, 20);

    const parms = seal.EncryptionParameters(schemeType);
    parms.setPolyModulusDegree(n_polyModulusDegree);
    parms.setCoeffModulus(seal.CoeffModulus.Create(n_polyModulusDegree, Int32Array.from(modulusChain)));
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
    const R = 6371; // Earth's radius in km

    //CLIENT A
    let client_A_latitude = 32.92374; //phi
    let client_A_longitude = 32.03947; //lambda

    //to radians
    let client_A_latitude_radian = client_A_latitude * (Math.PI / 180);
    let client_A_longitude_radian = client_A_longitude * (Math.PI / 180);

    //convert to cartesian
    let X_A = R * Math.cos(client_A_latitude_radian) * Math.cos(client_A_longitude_radian);
    let Y_A = R * Math.cos(client_A_latitude_radian) * Math.sin(client_A_longitude_radian);
    let Z_A = R * Math.sin(client_A_latitude_radian);

    //CLIENT B
    let client_B_latitude = 18.03473; //phi
    let client_B_longitude = 24.08465; //lambda

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

    //encrypted computations and decryptions
    let encrypted_time_test_1 = process.hrtime(); //server side start
    let encrypted_delta_x = evaluator.sub(encrypted_X_A, encrypted_X_B);
    let encrypted_delta_y = evaluator.sub(encrypted_Y_A, encrypted_Y_B);
    let encrypted_delta_z = evaluator.sub(encrypted_Z_A, encrypted_Z_B);
    let encrypted_delta_x_sq = evaluator.multiply(encrypted_delta_x, encrypted_delta_x);
    let encrypted_delta_y_sq = evaluator.multiply(encrypted_delta_y, encrypted_delta_y);
    let encrypted_delta_z_sq = evaluator.multiply(encrypted_delta_z, encrypted_delta_z);
    let encrypted_sum_sq_1 = evaluator.add(encrypted_delta_x_sq, encrypted_delta_y_sq);
    let encrypted_sum_sq = evaluator.add(encrypted_sum_sq_1, encrypted_delta_z_sq);
    let encrypted_time_test_2 = process.hrtime(encrypted_time_test_1); //server side stop
    let encrypted_time = (encrypted_time_test_2[0] * 1000 + (encrypted_time_test_2[1] / 1000000));

    let decrypted_sum = decryptor.decrypt(encrypted_sum_sq);
    let decoded_sum = ckksEncoder.decode(decrypted_sum);

    let encrypted_distance_float = parseFloat(decoded_sum[0]);

    //after sent to client
    let encrypted_distance = Math.sqrt(encrypted_distance_float);

    //plaintext
    let deltaX = X_A - X_B;
    let deltaY = Y_A - Y_B;
    let deltaZ = Z_A - Z_B;

    let squareSum = deltaX ** 2 + deltaY ** 2 + deltaZ ** 2;
    let plaintext_root = Math.sqrt(squareSum);


    console.log("encrypted: ", encrypted_distance);
    console.log("plaintext: ", plaintext_root);
    console.log("Execution time: ", encrypted_time)
}

)();
