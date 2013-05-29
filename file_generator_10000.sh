#!/bin/sh

if [ $# -ne 1 ]; then
    echo "$0 mount_dir"
    exit 0
fi

BASE_DIR=$1
dir_name=""
file_name=""

date 

suffix=`date +%s`

#for((i=1; i<=10000; i++))
for((i=1; i<=1000; i++))
do
    dir_name=${BASE_DIR}"/container-"${i}"-"${suffix}
    file_name="file-"${i}"-"${suffix}
    mkdir -p ${dir_name}
    if [ "$?" -eq "0" ]; then
        cp /home/rpy/seed_small_file ${dir_name}/${file_name}
    else
        echo "Error mkdir -p ${dir_name}"
        exit 1 
    fi
done

date

exit 0


