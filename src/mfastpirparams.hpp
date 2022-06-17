

#ifndef FASTPIR_PARAMS_H
#define FASTPIR_PARAMS_H

#include "bfvparams.h"
#include "seal/seal.h"

typedef  std::vector<seal::Ciphertext> PIRReply;
typedef  std::vector<seal::Ciphertext> PIRQuery;
typedef  seal::Ciphertext PIRResponse;

struct Query
{
    PIRQuery query;
    std::vector<int> indexOffset;
    std::vector<int> coeffOffset;
};

class FastPIRParams {
public:
    FastPIRParams(size_t num_obj, size_t obj_size, size_t polyDegree, size_t pmod);
    size_t get_num_obj();
    size_t get_obj_size();
    uint32_t get_num_query_ciphertext();
    uint32_t get_num_columns_per_obj();
    uint32_t get_db_rows();

    seal::EncryptionParameters get_seal_params();
    size_t get_poly_modulus_degree();
    size_t get_plain_modulus_size();
    size_t get_reply_ciphertext_num() const;
private:
    seal::EncryptionParameters seal_params;             //seal相关参数
    size_t num_obj;                                     //消息个数
    size_t obj_size;                                    //消息大小(受限制，需要修改)

    uint32_t num_query_ciphertext;                      //查询密文的个数(与消息个数相关，待优化，可能用查询扩展)
    uint32_t num_columns_per_obj;                       //每个消息占的系数个数，与消息大小相关
    uint32_t db_rows;                                   //总行数

    size_t reply_ciphertext_num;                        //返回的密文个数
};

#endif