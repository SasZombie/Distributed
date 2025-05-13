## Requirements:
- CMake
- C++ compiler
- This project is made with Microsoft SEAL: https://github.com/Microsoft/SEAL.git

## Usage:
- `mkdir build`    
- `cd build`
- `cmake ..`
- `./main file1.csv file2.csv file3.csv algorithm.common`

## Description
The project is a secure multi-party computation program where csv files are provided.
This can be done on a web server such that no one has acceess to the files.
The project contains a very small and simplistic scripting language in the form of a .common file
For the moment it only supports adding, subtracting and checking for different kind of relationships between them.
For example: `if $F1 equal sum $F2`, this will check which rows have the same first column equal and then sum the
third column respectivly. 

So if the input are 2 files of form: <br>
```
F1 = {
    ID, price
    ID001,12
    ID002,14
}
```
And respectivly:
```
F2 = {
    ID, price
    ID002,11
    ID003,12
}
```
Then the output would be `25 -> 14 + 11`. <br>
The scripting language also supports direct opperations such as: `sum $F2` where the output will be: `49 -> 12 + 14 + 11 + 12` (No checking)<br>

## Steps of the program:
1) Checks for argument lists
2) Set up seal parameters with the Polynomial number. Here 8192
3) Opens all files, checks what indicies cannot be encrypted(Cannot check if 2 files are equal and returning if they are encrypted)
4) Parses the csv
5) Encypts and Encode all elements from csv
6) Performs operations according to the common file
7) Displays the results

## Note
The scripting language is very limited. We didnt put much accent on the development of it. It should be well formated and can lead to crashes if not used properlly. The scripting allows infinite simple operations like summations:

```
sum $F1
sum $F2
.
.
.
sum $Fn
```
However it is limited in the checking of the files. For example if I have the construction: `if $F1 equal sum $F2`
then F1 cannot be encoded. Such that it is in a different "data frame" than F2.

If on the next line we would write something like:`if $F2 equal sum $F1` then F1 cannot be checked due to already being encoded.
At the same time, suppose we have a third field F3. If the script contains both `if $F1 equal sum $F2` and `sum $F3` it will not work! Since the indexes are offset.

However, this works:
```
if $F1 equal sum $F2
if $F1 equal sum $F3
.
.
.
if $F1 equal sum $Fn
```