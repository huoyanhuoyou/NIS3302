#!/bin/bash
 
LibDir=$PWD
Target=$1
 
lib_array=($(ldd $Target | grep -o "/.*" | grep -o "/.*/[^[:space:]]*"))
 
for Variable in ${lib_array[@]}
do
    cp "$Variable" $LibDir
done
