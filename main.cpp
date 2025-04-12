#include <iostream>
#include <print>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <ranges>

#include "Matrix.hpp"

#include "seal/seal.h"
#include "operations.hpp"

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

std::vector<size_t> indiciesToNotEncrypt(const std::vector<std::string> &tokens) noexcept
{
    std::vector<size_t> result;
    size_t size = tokens.size();
    for (size_t i = 0; i < size; ++i)
    {
        if (tokens[i] == "if" && size - i > 3)
        {
            result.push_back(std::stoull(tokens[i + 1]) - 1);
        }
    }

    return result;
}

std::tuple<sas::Matrix<seal::Plaintext>, sas::Matrix<seal::Ciphertext>> getParameters(const std::vector<size_t> &publicIndicies, const sas::Matrix<std::string> &valuesFile, const seal::Encryptor &encryptor, const seal::Decryptor &dec) noexcept
{

    sas::Matrix<seal::Plaintext> publicFields;
    sas::Matrix<seal::Ciphertext> encFields;

    size_t rows = valuesFile.getRows();
    size_t cols = valuesFile.getCols();

    size_t indicies = 0;
    size_t maxPublic = publicIndicies.size();

    size_t rowPublic = 0, colPublic = 0;
    size_t rowEnc = 0, colEnc = 0;

    for (size_t i = 0; i < rows; ++i)
    {

        for (size_t j = 0; j < cols; ++j)
        {
            seal::Plaintext pt(valuesFile(i, j));
            if (indicies < maxPublic && publicIndicies[indicies] == j)
            {
                ++indicies;
                publicFields.pushElem(rowPublic, colPublic, pt);
                ++colPublic;
            }
            else
            {
                seal::Ciphertext cf;
                encryptor.encrypt(pt, cf);

                encFields.pushElem(rowEnc, colEnc, cf);
                ++colEnc;
            }
        }
        colPublic = 0;
        colEnc = 0;

        ++rowPublic;
        ++rowEnc;
        indicies = 0;
    }

    return std::make_tuple(publicFields, encFields);
}

struct File
{
    sas::Matrix<seal::Plaintext> publicFields;
    sas::Matrix<seal::Ciphertext> encrpiptedFields;
};

std::vector<seal::Ciphertext> handleCondition(const std::vector<File>& files, auto (*predicate)(const seal::Plaintext &p1, const seal::Plaintext &p2)->bool, Operations op, const seal::Evaluator &eval) noexcept
{
    size_t sizeF1Rows = f1.publicFields.getRows();
    size_t sizeF2Rows = f2.publicFields.getRows();
    size_t sizeF1Cols = f1.publicFields.getCols();
    size_t sizeF2Cols = f2.publicFields.getCols();
    seal::Ciphertext result;
    std::vector<seal::Ciphertext> results;

    for (size_t i = 0; i < sizeF1Rows; ++i)
    {
        for (size_t j = 0; j < sizeF1Cols; ++j)
        {
            for (size_t k = 0; k < sizeF2Rows; ++k)
            {
                if (predicate(f1.publicFields(i, j), f2.publicFields(k, j)))
                {
                    switch (op)
                    {
                    case Operations::ADD:
                        eval.add(f1.encrpiptedFields(i, j), f2.encrpiptedFields(k, j), result);
                        results.push_back(result);
                        break;

                    case Operations::SUB:
                        eval.sub(f1.encrpiptedFields(i, j), f2.encrpiptedFields(k, j), result);
                        results.push_back(result);
                        break;

                    default:
                        std::cerr << "Unreachable, how did we get here??\n";
                        exit(EXIT_FAILURE);
                    }
                }
            }
        }
    }

    return results;
}

seal::Ciphertext handleOperation(const File &f1, const File &f2, Operations op, const seal::Evaluator &eval, seal::Decryptor &dec) noexcept
{
    seal::Ciphertext result = f1.encrpiptedFields(0);

    // Skip first elem
    for (const auto &elem : f1.encrpiptedFields | std::ranges::views::drop(1))
    {
        switch (op)
        {
        case Operations::ADD:

            eval.add_inplace(result, elem);
            break;
        case Operations::SUB:
            eval.sub_inplace(result, elem);

        default:
            std::cerr << "Unreachable, how did we get here??\n";
            exit(EXIT_FAILURE);
        }
    }

    for (const auto &elem : f2.encrpiptedFields)
    {
        switch (op)
        {
        case Operations::ADD:

            eval.add_inplace(result, elem);
            break;

        default:
            break;
        }
    }

    return result;
}

// This function assumes
// The script is well formated
// TODO: add script formating checking
std::vector<std::vector<seal::Ciphertext>> performOperations(const std::vector<std::string> &tokens, const std::vector<File> files, const seal::Evaluator &eval, seal::Decryptor &dec) noexcept
{
    size_t size = tokens.size();

    // Supports multiple lines and operations
    std::vector<std::vector<seal::Ciphertext>> results;

    for (size_t i = 0; i < size; ++i)
    {
        if (tokens[i] == "if")
        {
            results.emplace_back(handleCondition(files, mappingElems.at(tokens[i + 2]), operationMapping.at(tokens[i + 3]), eval));
            i = i + 4;
        }
        else
        {
            std::vector<seal::Ciphertext> vecTrick;
            vecTrick.emplace_back(handleOperation(f1, f2, operationMapping.at(tokens[i]), eval, dec));
            results.emplace_back(vecTrick);
            i = i + 1;
        }
    }

    return results;
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
    const auto &publicFields = indiciesToNotEncrypt(elems);

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

    const auto &valuesFile1 = getFileValues(file1);
    const auto &valuesFile2 = getFileValues(file2);

    const auto &[publicFile1, encFile1] = getParameters(publicFields, valuesFile1, encryptor, decryptor);
    const auto &[publicFile2, encFile2] = getParameters(publicFields, valuesFile2, encryptor, decryptor);

    File f1{publicFile1, encFile1};
    File f2{publicFile2, encFile2};

    const auto &results = performOperations(elems, f1, f2, evaluator, decryptor);

    for (const auto &resultVec : results)
    {
        for (const auto &result : resultVec)
        {

            seal::Plaintext plainResult;
            decryptor.decrypt(result, plainResult);

            std::print("Sum of salaries {}\n", plainResult.to_string());
        }
    }
}