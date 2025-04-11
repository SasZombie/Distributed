#pragma once
#include <vector>
#include <optional>
#include <stdexcept>

namespace sas
{

    template <typename T>
    class Matrix
    {
    private:
        size_t rows = 1, cols = 1;
        std::vector<T> data;

        size_t getIndex(size_t i, size_t j) const noexcept
        {
            return (i * cols + j);
        }

        void checkInsideBoundry(size_t row, size_t col) const
        {
            if (row >= this->rows || col >= this->cols)
            {
                throw std::out_of_range("Tried index out of range");
            }
        }

        bool checkInsideBoundry(size_t index) const noexcept
        {
            if (data.size() > index)
                return true;
            return false;
        }

        std::optional<T> getElem(size_t row, size_t col) const noexcept
        {
            if (row >= data.size() || col >= data.size() || row >= rows || col >= cols)
                return std::nullopt;
            size_t index = getIndex(row, col);

            return data[index];
        }

    public:
        Matrix() noexcept
            : data(rows * cols)
        {
        }

        Matrix(size_t n_rows, size_t n_cols) noexcept
            : rows(n_rows), cols(n_cols), data(rows * cols)
        {
        }

        Matrix(std::initializer_list<std::initializer_list<T>> init)
            : rows(init.size()), cols(init.begin()->size())
        {
            data.resize(rows * cols);

            size_t i = 0;

            for (const auto &row : init)
            {
                if (row.size() != cols)
                {
                    throw std::invalid_argument("All rows must have the same number of cols");
                }

                size_t j = 0;

                for (const auto &elem : row)
                {
                    data[getIndex(i, j)] = elem;
                    ++j;
                }
                ++i;
            }
        }

        T &operator()(size_t row, size_t col)
        {
            checkInsideBoundry(row, col);
            return data[getIndex(row, col)];
        }

        const T &operator()(size_t row, size_t col) const
        {
            checkInsideBoundry(row, col);
            return data[getIndex(row, col)];
        }

        T &operator()(size_t index)
        {
            checkInsideBoundry(index);
            return data[index];
        }

        const T &operator()(size_t index) const
        {
            checkInsideBoundry(index);
            return data[index];
        }

        // mat.push(0, 1)
        void pushElem(size_t row, size_t col, const T &elem) noexcept
        {
            if (row >= rows)
            {
                setRows(row + 1);
            }

            if (col >= cols)
            {
                setCols(col + 1);
            }

            checkInsideBoundry(row, col);
            data[getIndex(row, col)] = elem;
        }

        void setRows(size_t n_rows) noexcept
        {
            this->data.resize(this->cols * n_rows);
            this->rows = n_rows;
        }
        void setCols(size_t n_cols) noexcept
        {

            this->data.resize(this->rows * n_cols);
            this->cols = n_cols;
        }

        size_t getRows() const noexcept
        {
            return this->rows;
        }
        size_t getCols() const noexcept
        {
            return this->cols;
        }

        T *begin()
        {
            return data.data();
        }

        T *end()
        {
            return data.data() + data.size();
        }

        const T *begin() const
        {
            return data.data();
        }

        const T *end() const
        {
            return data.data() + data.size();
        }

        Matrix &operator=(const std::initializer_list<std::initializer_list<T>> other)
        {
            size_t newRows = other.size();

            size_t newCols = 0;

            for (const auto &row : other)
            {
                if (newCols == 0)
                {
                    newCols = row.size();
                }
                else
                {
                    if (row.size() != newCols)
                    {
                        throw std::invalid_argument("All rows must have the same ammount of columns");
                    }
                }
            }

            setRows(newRows);
            setCols(newCols);

            size_t i = 0;
            for (const auto &row : other)
            {
                size_t j = 0;
                for (const auto &elem : row)
                {
                    data[getIndex(i, j)] = elem;
                    ++j;
                }
                ++i;
            }

            return *this;
        }

        // Returns tuple of Nighbours excluding oneself
        // The order is clockwise starting from North-West: NW,N,NE,E,SE,S,SW,W
        // To verify which neighbour was returned, this returns an optional
        std::array<std::optional<T>, 8> getNeighbours(size_t i, size_t j) const
        {
            checkInsideBoundry(i, j);
            std::array<std::optional<T>, 8> neighbors;

            neighbors[0] = getElem(i - 1, j - 1);
            neighbors[1] = getElem(i - 1, j);
            neighbors[2] = getElem(i - 1, j + 1);
            neighbors[3] = getElem(i, j + 1);
            neighbors[4] = getElem(i + 1, j + 1);
            neighbors[5] = getElem(i + 1, j);
            neighbors[6] = getElem(i + 1, j - 1);
            neighbors[7] = getElem(i, j - 1);

            return neighbors;
        }

        template <typename U>
        friend std::ostream &operator<<(std::ostream &os, const Matrix<U> &p);

        ~Matrix() noexcept = default;
    };


    template <typename T>
    std::ostream &operator<<(std::ostream &os, const Matrix<T> &p)
    {
        for(size_t i = 0; i < p.getRows(); ++i)
        {
            for(size_t j = 0; j < p.getCols(); ++j)
            {
                os << p(i, j) << ' ';
            }
            os << '\n';
        }
        return os;
    }

}