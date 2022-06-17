
#include "mfastpirparams.hpp"
FastPIRParams::FastPIRParams(size_t num_obj, size_t obj_size, size_t polyDegree, size_t pmod)
{
    seal_params = seal::EncryptionParameters(seal::scheme_type::bfv);
    
    seal_params.set_poly_modulus_degree(POLY_MODULUS_DEGREE);                 
    seal_params.set_coeff_modulus(COEFF_MOD_ARR);
    seal_params.set_plain_modulus(seal::PlainModulus::Batching(POLY_MODULUS_DEGREE, PLAIN_BIT + 1));
    
    //4096
    /*
    seal_params.set_poly_modulus_degree(POLY_MODULUS_DEGREE);               
    //seal_params.set_coeff_modulus(COEFF_MOD_ARR);  
    seal_params.set_coeff_modulus(seal::CoeffModulus::Create(POLY_MODULUS_DEGREE, { 60, 49 }));
    seal_params.set_plain_modulus(seal::PlainModulus::Batching(POLY_MODULUS_DEGREE, PLAIN_BIT + 1));
    */
    this->num_obj = num_obj;
    this->obj_size = obj_size;

    //num_query_ciphertext = 2 * ceil(num_obj / (double)(POLY_MODULUS_DEGREE));
    num_query_ciphertext = ceil(num_obj / (double)(POLY_MODULUS_DEGREE/2));     //查询密文的数量,1、2列各一个所以*2, 这里和查询的大小无关，因为后续的明文也是用相同的查询密文计算

    num_columns_per_obj = 2 * (ceil(((obj_size/2) * 8) / (float)(PLAIN_BIT)));  //每条消息所占的系数数量，必须分为两个部分
    num_columns_per_obj += num_columns_per_obj % 2;                             //因为分成2部分，必须是2的倍数(这行似乎没有必要了)
    db_rows = ceil(num_obj / (double)POLY_MODULUS_DEGREE) * num_columns_per_obj;    //明文的总数

    reply_ciphertext_num = ceil(num_columns_per_obj / (double)POLY_MODULUS_DEGREE);
    //num_query_ciphertext * (num_columns_per_obj/2) 
                        
    return;
}


size_t FastPIRParams::get_num_obj()
{
    return num_obj;
}

size_t FastPIRParams::get_obj_size()
{
    return obj_size;
}

uint32_t FastPIRParams::get_num_query_ciphertext()
{
    return num_query_ciphertext;
}

uint32_t FastPIRParams::get_num_columns_per_obj()
{
    return num_columns_per_obj;
}

uint32_t FastPIRParams::get_db_rows()
{
    return db_rows;
}

seal::EncryptionParameters FastPIRParams::get_seal_params()
{
    return seal_params;
}

size_t FastPIRParams::get_poly_modulus_degree()
{
    return seal_params.poly_modulus_degree();
}

size_t FastPIRParams::get_plain_modulus_size()
{
    return seal_params.plain_modulus().bit_count();
}

size_t FastPIRParams::get_reply_ciphertext_num() const
{
    return reply_ciphertext_num;
}