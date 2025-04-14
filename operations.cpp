#include "operations.hpp"

bool isEqual(const seal::Plaintext &p1, const seal::Plaintext &p2) noexcept
{
    return p1.to_string() == p2.to_string();
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