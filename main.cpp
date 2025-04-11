#include <iostream>
#include <print>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>

#include "Matrix.hpp"

#include "seal/seal.h"

static std::vector<std::string> tokenize(std::ifstream &file) noexcept
{
    std::vector<std::string> returned;

    std::string line;

    const std::string expectedMagic = "comv";

    char buff[4];
    file.read(buff, sizeof(buff));

    if (file.gcount() < 4 || buff[0] != 'c' || buff[1] != 'o' || buff[2] != 'm' || buff[3] != 'v')
    {
        std::cerr << "Incorrect common file format\n";
        exit(EXIT_FAILURE);
    }

    while (std::getline(file, line))
    {
        std::istringstream stream(line);
        std::string word;

        while (stream >> word)
        {
            if (word.size() > 2 && word[0] == '$' && word[1] == 'F')
            {
                word = word.substr(2);
            }
            returned.emplace_back(word);
        }
    }

    return returned;
}

bool functionIf(std::string_view str1, std::string_view str2) noexcept
{
    return str1 == str2;
}

template <typename T>
T functionAdd(T elem1, T elem2) noexcept
{
    return elem1 + elem2;
}

// Statements = ori au conditie si actiune
//              ori au doar actiune

sas::Matrix<std::string> getFileValues(std::ifstream &file) noexcept
{

    sas::Matrix<std::string> elems;
    std::string line;

    std::getline(file, line);

    size_t i = 0, j = 0;
    while (std::getline(file, line))
    {
        std::stringstream ss(line);
        std::string cell;

        while (std::getline(ss, cell, ','))
        {
            
            elems.pushElem(i, j, cell);
            ++j;
        }
        j = 0;

        ++i;
    }

    return elems;
}

std::vector<size_t> indiciesToNotEncrypt(const std::vector<std::string>& tokens) noexcept
{
    std::vector<size_t> result;
    size_t size = tokens.size();
    for(size_t i = 0; i < size; ++i)
    {
        if(tokens[i] == "if" && size - i > 3)
        {   
            result.push_back(std::stoull(tokens[i+1]) - 1);
        }
    }

    return result;
}

std::tuple<sas::Matrix<std::string>, sas::Matrix<seal::Ciphertext>> getParameters(const std::vector<size_t>& publicIndicies, const sas::Matrix<std::string>& valuesFile, const seal::Encryptor& encryptor) noexcept
{

    sas::Matrix<std::string> publicFields;
    sas::Matrix<seal::Ciphertext> encFields;

    size_t rows = valuesFile.getRows();
    size_t cols = valuesFile.getCols();

    size_t indicies = 0;
    size_t maxPublic = publicIndicies.size();

    for(size_t i = 0; i < rows; ++i)
    {
        
        for(size_t j = 0; j < cols; ++j)
        {
            if(indicies < maxPublic && publicIndicies[indicies] == j)
            {
                ++indicies;
                publicFields.pushElem(i, j, valuesFile(i, j));

            }
            else
            {
                seal::Plaintext pt(std::stoull(valuesFile(i, j)));
                seal::Ciphertext cf;

                encryptor.encrypt(pt, cf);
                encFields.pushElem(i, j, cf);
            }
        }
        indicies = 0;
    }

    return std::make_tuple(publicFields, encFields);
} 

int main(int argc, const char **argv)
{
    if (argc < 4)
    {
        std::cerr << "Not enough files provided.\nUsage: File1, File2, ..., File N, algorithm.common";
        return 1;
    }

    std::filesystem::path path1 = argv[1];
    std::filesystem::path path2 = argv[2];
    std::filesystem::path common = argv[3];

    std::ifstream file1(path1);
    std::ifstream file2(path2);
    std::ifstream commonFile(common);

    if (!file1.is_open())
    {
        std::cerr << "Cannot open file1\n";
        return 1;
    }

    if (!file2.is_open())
    {
        std::cerr << "Cannot open file2\n";
        return 1;
    }

    if (!commonFile.is_open())
    {
        std::cerr << "Cannot open common file\n";
        return 1;
    }

    const auto &elems = tokenize(commonFile);
    const auto& publicFields = indiciesToNotEncrypt(elems);

    seal::EncryptionParameters params(seal::scheme_type::bfv);
    size_t polyModulusDegree = 8192;

    params.set_poly_modulus_degree(polyModulusDegree);
    params.set_coeff_modulus(seal::CoeffModulus::BFVDefault(polyModulusDegree));
    params.set_plain_modulus(seal::PlainModulus::Batching(polyModulusDegree, 20));

    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);

    const auto privateKey = keyGen.secret_key();

    seal::RelinKeys rl;
    seal::PublicKey pk;
    keyGen.create_public_key(pk);
    keyGen.create_relin_keys(rl);

    seal::Encryptor encryptor(context, pk);
    seal::Decryptor decryptor(context, privateKey);
    seal::Evaluator evaluator(context);
    seal::BatchEncoder encoder(context);

    const auto& valuesFile1 = getFileValues(file1);
    const auto& valuesFile2 = getFileValues(file2);

    const auto&[publicFile1, encFile1] = getParameters(publicFields, valuesFile1, encryptor);
    const auto&[publicFile2, encFile2] = getParameters(publicFields, valuesFile2, encryptor);

    std::print("Public fields size = {}\n", publicFields.size());
    for(const auto elem : publicFields)
    {
        std::print("Elems = {} ", elem);
    }
    std::print("\n");
    

    std::cout << publicFile1;
    std::cout << publicFile2;
}