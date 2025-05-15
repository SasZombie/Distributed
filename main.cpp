#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <tuple>
#include <seal/seal.h>
#include "operations.hpp"
#include "Matrix.hpp"
#include <QStringList>
#include <QApplication>
#include <QMainWindow>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>
#include <QLabel>
#include <QFileDialog>
#include <QStringList>
#include <QTextEdit>
#include <QFileInfo>

// Structure of a file
struct File
{
    sas::Matrix<seal::Plaintext> publicFields;
    sas::Matrix<seal::Ciphertext> encrpiptedFields;
};

static std::vector<std::string> tokenize(std::ifstream &file)
{
    std::vector<std::string> returned;
    std::string line;
    const std::string expectedMagic = "comv";
    char buff[4];
    file.read(buff, sizeof(buff));
    if (file.gcount() < 4 || buff[0] != 'c' || buff[1] != 'o' || buff[2] != 'm' || buff[3] != 'v')
    {
        // Return empty to indicate error
        return {};
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

static sas::Matrix<std::string> getFileValues(std::ifstream &file)
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

static std::vector<size_t> indiciesToNotEncrypt(const std::vector<std::string> &tokens)
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

static bool isNumeric(const std::string &s)
{
    return !s.empty() && std::all_of(s.begin(), s.end(), ::isdigit);
}

static std::tuple<sas::Matrix<seal::Plaintext>, sas::Matrix<seal::Ciphertext>> getParameters(
    const std::vector<size_t> &publicIndicies,
    const sas::Matrix<std::string> &valuesFile,
    const seal::Encryptor &encryptor,
    const seal::BatchEncoder &encoder)
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
            if (indicies < maxPublic && publicIndicies[indicies] == j)
            {
                seal::Plaintext pt(valuesFile(i, j));
                ++indicies;
                publicFields.pushElem(rowPublic, colPublic, pt);
                ++colPublic;
            }
            else
            {
                seal::Plaintext pt;
                seal::Ciphertext cf;
                if (isNumeric(valuesFile(i, j)))
                {
                    uint64_t val = std::stoull(valuesFile(i, j));
                    std::vector<uint64_t> vec(encoder.slot_count(), 0);
                    vec[0] = val;
                    encoder.encode(vec, pt);
                }
                else
                {
                    std::hash<std::string> hasher;
                    uint64_t hashedVal = hasher(valuesFile(i, j));
                    std::vector<uint64_t> vec(encoder.slot_count(), 0);
                    vec[0] = hashedVal;
                    encoder.encode(vec, pt);
                }
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

static std::vector<seal::Ciphertext> handleCondition(
    const std::vector<File> &files,
    auto (*predicate)(const seal::Plaintext &p1, const seal::Plaintext &p2) -> bool,
    Operations op,
    size_t column,
    const seal::Evaluator &eval)
{
    seal::Ciphertext result;
    std::vector<seal::Ciphertext> results;
    size_t candidateSize = files[0].publicFields.size();
    const auto &candidates = files[0].publicFields.asVector();
    const size_t fileSize = files.size();
    std::vector<std::pair<size_t, size_t>> indicies;
    for (size_t c = 0; c < candidateSize; ++c)
    {
        const auto &candidate = candidates[c];
        bool inAll = true;
        for (size_t f = 0; f < fileSize; ++f)
        {
            const auto &matrix = files[f].publicFields;
            bool found = false;
            const size_t rowSize = matrix.getRows();
            const size_t colSize = matrix.getCols();
            for (size_t i = 0; i < rowSize; ++i)
            {
                for (size_t j = 0; j < colSize; ++j)
                {
                    if (predicate(candidate, matrix(i, j)))
                    {
                        indicies.push_back({i, column});
                        found = true;
                        break;
                    }
                }
                if (found)
                    break;
            }
            if (!found)
            {
                indicies.clear();
                inAll = false;
                break;
            }
        }
        if (inAll)
        {
            result = files[0].encrpiptedFields(indicies[0].first, indicies[0].second);
            switch (op)
            {
            case Operations::ADD:
                for (size_t finFile = 1; finFile < fileSize; ++finFile)
                {
                    const auto &[row, col] = indicies[finFile];
                    eval.add_inplace(result, files[finFile].encrpiptedFields(row, col));
                }
                break;
            default:
                break;
            }
            indicies.clear();
            results.push_back(result);
        }
    }
    return results;
}

static seal::Ciphertext handleOperation(
    const std::vector<File> &files,
    Operations op,
    const seal::Evaluator &eval,
    size_t column)
{
    seal::Ciphertext result = files[0].encrpiptedFields(column);
    for (const auto &f : files)
    {
        const size_t rowsSize = f.encrpiptedFields.getRows();
        for (size_t i = 0; i < rowsSize; ++i)
        {
            switch (op)
            {
            case Operations::ADD:
                eval.add_inplace(result, f.encrpiptedFields(i, column));
                break;
            case Operations::SUB:
                eval.sub_inplace(result, f.encrpiptedFields(i, column));
                break;
            default:
                // Unreachable
                break;
            }
        }
    }
    if (op == Operations::ADD)
    {
        eval.sub_inplace(result, files[0].encrpiptedFields(column));
        return result;
    }
    eval.add_inplace(result, files[0].encrpiptedFields(column));
    return result;
}

static std::vector<std::vector<seal::Ciphertext>> performOperations(
    const std::vector<std::string> &tokens,
    const std::vector<File> files,
    const seal::Evaluator &eval)
{
    size_t size = tokens.size();
    std::vector<std::vector<seal::Ciphertext>> results;
    for (size_t i = 0; i < size; ++i)
    {
        if (tokens[i] == "if")
        {
            results.emplace_back(handleCondition(files, mappingElems.at(tokens[i + 2]), operationMapping.at(tokens[i + 3]), std::stoul(tokens[i + 4]) - 2, eval));
            i = i + 4;
        }
        else
        {
            std::vector<seal::Ciphertext> vecTrick;
            vecTrick.emplace_back(handleOperation(files, operationMapping.at(tokens[i]), eval, std::stoul(tokens[i + 1]) - 1));
            results.emplace_back(vecTrick);
            i = i + 1;
        }
    }
    return results;
}

std::string run_main_logic(const QStringList& files)
{
    std::ostringstream output;

    if (files.size() < 2)
    {
        output << "Not enough files provided.\nUsage: File1, File2, ..., File N, algorithm.common";
        return output.str();
    }

    // SEAL
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

    // Open the algorithm/common file (last file)
    std::ifstream commonFile(files.back().toStdString());
    if (!commonFile.is_open())
    {
        output << "Cannot open algorithm/common file: " << files.back().toStdString();
        return output.str();
    }
    const auto &elems = tokenize(commonFile);
    if (elems.empty())
    {
        output << "Algorithm/common file format error.";
        return output.str();
    }

    std::vector<File> fileObjs;
    for (int i = 0; i < files.size() - 1; ++i)
    {
        std::ifstream file(files[i].toStdString());
        if (!file.is_open())
        {
            output << "Cannot open file: " << files[i].toStdString() << "\n";
            return output.str();
        }
        const auto &publicFields = indiciesToNotEncrypt(elems);
        const auto &valuesFile = getFileValues(file);
        const auto &[publicFile, encFile] = getParameters(publicFields, valuesFile, encryptor, encoder);
        File f{publicFile, encFile};
        fileObjs.push_back(f);
    }

    const auto &results = performOperations(elems, fileObjs, evaluator);

    for (const auto &resultVec : results)
    {
        output << "Current operation results:\n";
        for (const auto &result : resultVec)
        {
            seal::Plaintext pt;
            decryptor.decrypt(result, pt);
            std::vector<uint64_t> decoded;
            encoder.decode(pt, decoded);
            output << "\tResult = " << decoded[0] << "\n";
        }
    }

    return output.str();
}


class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow() {
        auto *central = new QWidget(this);
        auto *layout = new QVBoxLayout(central);

        auto *label = new QLabel("Distributed Project", this);
        layout->addWidget(label);

        auto *selectCsvButton = new QPushButton("Select CSV Files", this);
        layout->addWidget(selectCsvButton);

        auto *selectAlgoButton = new QPushButton("Select algorithm.common", this);
        layout->addWidget(selectAlgoButton);

        auto *runButton = new QPushButton("Run!", this);
        layout->addWidget(runButton);

        output = new QTextEdit(this);
        output->setReadOnly(true);
        layout->addWidget(output);

        setCentralWidget(central);

        connect(selectCsvButton, &QPushButton::clicked, this, [this, label]() {
            csvFiles = QFileDialog::getOpenFileNames(this, "Select CSV Files", QString(), "CSV Files (*.csv);;All Files (*)");
            if (!csvFiles.isEmpty()){
                QStringList fileNames;
                for (const QString& path : csvFiles)
                fileNames << QFileInfo(path).fileName();
                label->setText("CSV files selected: " + fileNames.join(", "));
            }
            else
                label->setText("No CSV files selected.");
        });

        connect(selectAlgoButton, &QPushButton::clicked, this, [this, label]() {
            QString file = QFileDialog::getOpenFileName(this, "Select algorithm.common", QString(), "Common Files (*.common);;All Files (*)");
            if (!file.isEmpty()) {
                algoFile = file;
                label->setText(label->text() + "\nAlgorithm file selected: " + QFileInfo(algoFile).fileName());
            } else {
                label->setText(label->text() + "\nNo algorithm file selected.");
            }
        });

        connect(runButton, &QPushButton::clicked, this, [this]() {
            if (csvFiles.isEmpty() || algoFile.isEmpty()) {
                output->setText("Please select both CSV files and the algorithm.common file first.");
                return;
            }
            // Combine files for logic: CSVs + algorithm file as last
            QStringList allFiles = csvFiles;
            allFiles << algoFile;
            std::string result = run_main_logic(allFiles);
            output->setText(QString::fromStdString(result));
        });
    }

private:
    QStringList csvFiles;
    QString algoFile;
    QTextEdit* output;
};

#include "main.moc"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    MainWindow window;
    window.setWindowTitle("Distributed App");
    window.resize(800, 600);
    window.show();

    return app.exec();
}
