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

    let testValue = 4.509812;
    let ref_value = testValue ** 2;

    let arr_test = Float64Array.from([testValue]);
    let encoded_test_value = ckksEncoder.encode(arr_test, scale);
    let encrypted_test_value = encryptor.encrypt(encoded_test_value);
    let squared_encrypted_test = evaluator.multiply(encrypted_test_value, encrypted_test_value);
    let decrypted_test_value = decryptor.decrypt(squared_encrypted_test);
    let decoded_test_value = ckksEncoder.decode(decrypted_test_value);

    console.log("ref: ", ref_value);
    console.log("decoded: ", decoded_test_value[0]);

}

)();
