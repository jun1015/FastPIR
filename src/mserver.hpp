

#ifndef FASTPIR_SERVER_H
#define FASTPIR_SERVER_H

#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <unistd.h>
#include <bitset>
#include<cassert>
#include "seal/seal.h"
#include "mfastpirparams.hpp"

class Mserver
{

public:
    
    Mserver(FastPIRParams parms);
    void set_client_galois_keys(uint32_t client_id, seal::GaloisKeys gal_keys);
    void set_db(std::vector<std::vector<unsigned char>> db);
    void preprocess_db();
    PIRReply get_response(uint32_t client_id, PIRQuery query);

    PIRReply get_multi_response(uint32_t client_id, const Query& query);

    PIRReply concat_response(uint32_t client_id, const std::vector<PIRReply>& replys, const std::vector<int>& coeffOffsets);

    void move_query(PIRQuery& query, int indexOffset, int coeffOffset, const seal::GaloisKeys& gal_key);
private:
    seal::SEALContext *context;
    seal::Evaluator *evaluator;
    seal::BatchEncoder *batch_encoder;
    std::map<uint32_t, seal::GaloisKeys> client_galois_keys;
    std::vector<seal::Plaintext> encoded_db;
    uint32_t num_obj;
    uint32_t obj_size;
    uint32_t num_columns_per_obj;
    uint32_t num_query_ciphertext;
    uint32_t N;
    uint32_t plain_bit_count;
    uint32_t db_rows;
    int32_t reply_ciphertext_num;
    bool db_preprocessed;

    void encode_db(std::vector<std::vector<uint64_t>> db);
    void preprocess_query(std::vector<seal::Ciphertext> &query);
    std::vector<uint64_t> encode(std::vector<unsigned char> str);
    seal::Ciphertext get_sum(std::vector<seal::Ciphertext> &query, seal::GaloisKeys &gal_keys, uint32_t start, uint32_t end);
    uint32_t get_next_power_of_two(uint32_t number);
    uint32_t get_number_of_bits(uint64_t number);
    uint32_t get_last_power_of_two(uint32_t number);
    void rotateCipher(seal::Ciphertext&, int step, const seal::GaloisKeys& gal_key);
public:
    int get_real_coeff_step(int step);
};

#endif