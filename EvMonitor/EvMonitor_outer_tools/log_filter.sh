#!/bin/bash

dir=$1
files=`ls $dir`
exp=$2
outfile=em_extract_`date +%s`
current=`pwd`

for file in $files
do
    cat ./$dir/$file | grep -E "$exp" >> outfile
done