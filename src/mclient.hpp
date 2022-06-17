/*
 * @Author: 贾根龙 
 * @Date: 2022-05-25 09:18:19
 * @LastEditors: jun1015 xx.19993.7@qq.com
 * @LastEditTime: 2022-06-15 11:11:24
 * @FilePath: /ljy/FastPIR/src/mclient.hpp
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#ifndef FASTPIR_CLIENT_H
#define FASTPIR_CLIENT_H

#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <unistd.h>
#include <bitset>

#include "seal/seal.h"
#include "mfastpirparams.hpp"

class Mclient
{

public:
    Mclient(FastPIRParams parms);
    Query gen_query(uint32_t index, const std::vector<int>& indexOffset = std::vector<int>(), const std::vector<int>& coeffIndex = std::vector<int>());
    std::vector<unsigned char> decode_response(std::vector<seal::Ciphertext> response, uint32_t index, size_t queryCount = 1);
    seal::GaloisKeys get_galois_keys();
    //std::vector<unsigned char> decode_multi_response(std::vector<seal::Ciphertext> response, std::vector<uint32_t> index, size_t count);
private:
    seal::SEALContext *context;
    seal::KeyGenerator *keygen;
    seal::SecretKey secret_key;
    seal::Encryptor *encryptor;
    seal::Decryptor *decryptor;
    seal::BatchEncoder *batch_encoder;
    seal::GaloisKeys gal_keys;
    uint32_t num_obj;
    uint32_t obj_size;
    uint32_t N; //poly modulus degree
    uint32_t plain_bit_count;
    uint32_t num_columns_per_obj;
    uint32_t num_query_ciphertext;
    uint32_t reply_ciphertext_num;

    std::vector<uint64_t> rotate_plain(std::vector<uint64_t> original, int index);
    std::vector<unsigned char> decode(std::vector<uint64_t> v, bool last);
};

#endif