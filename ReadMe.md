Requirements:
    CMake
    C++ compiler

Usage: <br>
    mkdir build<br>    
    cd build/<br>
    cmake ..<br>

    ./main file1.csv file2.csv file3.csv algorithm.common

The project is a secure multi-party computation program where csv files are provided.
This can be done on a web server such that no one has acceess to the files.
The project contains a very small and simplistic scripting language in the form of a .common file
For the moment it only supports adding, subtracting and checking for different kind of relationships between them.
For example: "if $F1 equal sum $F2", this will check which rows have the same first column equal and then sum the
third column respectivly. So if the input are 2 files of form: <br>
F1 = {<br>
    ID, price<br>
    ID001,12<br>
    ID002,14<br>
} <br>
And respectivly:<br>
<br>
F2 = {<br>
    ID, price<br>
    ID002,11<br>
    ID003,12<br>
}<br>

Then the output would be 25 -> 14 + 11. <br>
The scripting language also supports direct opperations such as: sum $F2 where the output will be: 49 -> 12 + 14 + 11 + 12 (No checking)<br>

This project is made with Microsoft SEAL: https://github.com/Microsoft/SEAL.git<br>

Steps of the program:<br>
    1) Checks for argument lists<br>
    2) Set up seal parameters with the Polynomial number. Here 8192<br>
    3) Opens all files, checks what indicies cannot be encrypted(Cannot check if 2 files are equal and returning if they are encrypted)<br>
    4) Parses the csv<br>
    5) Encypts and Encode all elements from csv<br>
    6) Performs operations according to the common file<br>
    7) Displays the results<br>

Note that the scripting language is very limited. We didnt put much accent on the development of it. It should be well formated
and can lead to crashes if not used properlly. The scripting allows infinite simple operations like summations:

sum $F1<br>
sum $F2<br>
.<br>
.<br>
.<br>
sum $Fn<br>

However it is limited in the checking of the files. For example if I have the construction:<br>

if $F1 equal sum $F2<br>

then F1 cannot be encoded. Such that it is in a different "data frame" than F2.
If on the next line we would write something like:<br>

if $F2 equal sum $F1<br>

then F1 cannot be checked due to already being encoded.
At the same time, suppose we have a third field F3. If the script contains:<br>
<br>
if $F1 equal sum $F2<br>
sum $F3<br>

This will not work! Since the indexsies are offseted.<br>
However this works:<br>
if $F1 equal sum $F2<br>
if $F1 equal sum $F3<br>
.<br>
.<br>
.<br>
if $F1 equal sum $Fn
