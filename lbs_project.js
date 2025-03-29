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

    let testValue_1 = 4.509812;
    let testValue_2 = 2.145675;
    let ref_value_multiply = testValue_1 ** 2;
    let ref_value_subtract = testValue_1 - testValue_2;
    let ref_value_add = testValue_1 + testValue_1;


    //encode and encrypt
    let arr_test_multiply = Float64Array.from([testValue_1]);
    let encoded_test_value_multiply = ckksEncoder.encode(arr_test_multiply, scale);
    let encrypted_test_value_multiply = encryptor.encrypt(encoded_test_value_multiply);

    let arr_test_subtract_1 = Float64Array.from([testValue_1]);
    let encoded_test_value_arr_test_subtract_1 = ckksEncoder.encode(arr_test_subtract_1, scale);
    let encrypted_test_value_arr_test_subtract_1 = encryptor.encrypt(encoded_test_value_arr_test_subtract_1);
    let arr_test_subtract_2 = Float64Array.from([testValue_2]);
    let encoded_test_value_arr_test_subtract_2 = ckksEncoder.encode(arr_test_subtract_2, scale);
    let encrypted_test_value_arr_test_subtract_2 = encryptor.encrypt(encoded_test_value_arr_test_subtract_2);


    let arr_test_add = Float64Array.from([testValue_1]);
    let encoded_test_value_arr_test_add = ckksEncoder.encode(arr_test_add, scale);
    let encrypted_test_value_arr_test_add = encryptor.encrypt(encoded_test_value_arr_test_add);


    //multiply
    let encrypted_test_multiply = evaluator.multiply(encrypted_test_value_multiply, encrypted_test_value_multiply);

    //subtract
    let encrypted_test_subtract = evaluator.sub(encrypted_test_value_arr_test_subtract_1, encrypted_test_value_arr_test_subtract_2);

    //add
    let encrypted_test_add = evaluator.add(encrypted_test_value_arr_test_add, encrypted_test_value_arr_test_add);

    //decode and decrypt
    let decrypted_test_value_multiply = decryptor.decrypt(encrypted_test_multiply);
    let decoded_test_value_multiply = ckksEncoder.decode(decrypted_test_value_multiply);

    let decrypted_test_value_subtract = decryptor.decrypt(encrypted_test_subtract);
    let decoded_test_value_subtract = ckksEncoder.decode(decrypted_test_value_subtract);

    let decrypted_test_value_add = decryptor.decrypt(encrypted_test_add);
    let decoded_test_value_add = ckksEncoder.decode(decrypted_test_value_add);


    console.log("ref multiply: ", ref_value_multiply);
    console.log("decoded multiply: ", decoded_test_value_multiply[0]);

    console.log("ref subtract: ", ref_value_subtract);
    console.log("decoded subtract: ", decoded_test_value_subtract[0]);

    console.log("ref add: ", ref_value_add);
    console.log("decoded add: ", decoded_test_value_add[0]);

}

)();
