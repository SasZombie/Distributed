#pragma once
#include "seal/seal.h"
#include <unordered_map>

bool isEqual(const seal::Plaintext &p1, const seal::Plaintext &p2) noexcept
{
    return p1 == p2;
}

bool isLess(const seal::Plaintext &p1, const seal::Plaintext &p2) noexcept
{
    return p1.to_string() < p2.to_string();
}

bool isLessEqual(const seal::Plaintext &p1, const seal::Plaintext &p2) noexcept
{
    return p1.to_string() <= p2.to_string();
}

bool isGreater(const seal::Plaintext &p1, const seal::Plaintext &p2) noexcept
{
    return p1.to_string() > p2.to_string();
}

bool isGreaterEqual(const seal::Plaintext &p1, const seal::Plaintext &p2) noexcept
{
    return p1.to_string() >= p2.to_string();
}

bool isLessNumber(const seal::Plaintext &p1, const seal::Plaintext &p2) noexcept
{
    return std::stol(p1.to_string()) < std::stol(p2.to_string());
}

bool isLessEqualNumber(const seal::Plaintext &p1, const seal::Plaintext &p2) noexcept
{
    return std::stol(p1.to_string()) >= std::stol(p2.to_string());
}
bool isGreaterNumber(const seal::Plaintext &p1, const seal::Plaintext &p2) noexcept
{
    return std::stol(p1.to_string()) > std::stol(p2.to_string());
}
bool isGreaterEqualNumber(const seal::Plaintext &p1, const seal::Plaintext &p2) noexcept
{
    return std::stol(p1.to_string()) >= std::stol(p2.to_string());
}

enum struct Operations
{
    ADD,
    SUB,
    AVG
};

// For my vscode the coloring is very weird here
// But works correctly so it is just coloring issue
const std::unordered_map<std::string, auto (*)(const seal::Plaintext &p1, const seal::Plaintext &p2)->bool> mappingElems =
    {
        {"equal", isEqual},
        {"less", isLess},
        {"lesse", isLessEqual},
        {"greater", isGreater},
        {"greatere", isGreaterEqual},
        {"equalN", isEqual},
        {"lessN", isLessNumber},
        {"lesseN", isLessEqualNumber},
        {"greaterN", isGreaterNumber},
        {"greatereN", isGreaterEqualNumber}

};

const std::unordered_map<std::string, Operations> operationMapping = {
    {"sum", Operations::ADD},
    {"sub", Operations::SUB},
};