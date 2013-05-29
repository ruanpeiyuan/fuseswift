#!/bin/sh

if [ $# -ne 1 ]; then
    echo "$0 mount_dir"
    exit 0
fi

BASE_DIR=$1
dir_name=""
file_name=""

date 

for((i=1; i<=10; i++))
do
    dir_name=${BASE_DIR}"/dir-"${i}
    file_name="file-"${i}
    mkdir -p ${dir_name}
    if [ "$?" -eq "0" ]; then
        cp /home/rpy/seedfile ${dir_name}/${file_name}
    else
        echo "Error mkdir -p ${dir_name}"
        exit 1 
    fi

    for((j=1; j<=10; j++))
    do
        dir_name=${BASE_DIR}"/dir-"${i}"/dir-"${i}"-"${j}
        file_name="file-"${i}"-"${j}
        mkdir -p ${dir_name}
        if [ "$?" -eq "0" ]; then
            cp /home/rpy/seedfile ${dir_name}/${file_name}
        else
            echo "Error mkdir -p ${dir_name}"
            exit 1 
        fi

        for((k=1; k<=10; k++))
        do
            dir_name=${BASE_DIR}"/dir-"${i}"/dir-"${i}"-"${j}"/dir-"${i}"-"${j}"-"${k}
            file_name="file-"${i}"-"${j}"-"${k}
            mkdir -p ${dir_name}
            if [ "$?" -eq "0" ]; then
                cp /home/rpy/seedfile ${dir_name}/${file_name}
            else
                echo "Error mkdir -p ${dir_name}"
                exit 1 
            fi

            for((l=1; l<=5; l++))
            do
                dir_name=${BASE_DIR}"/dir-"${i}"/dir-"${i}"-"${j}"/dir-"${i}"-"${j}"-"${k}"/dir-"${i}"-"${j}"-"${k}"-"${l}
                file_name="file-"${i}"-"${j}"-"${k}"-"${l}
                mkdir -p ${dir_name}
                if [ "$?" -eq "0" ]; then
                    cp /home/rpy/seedfile ${dir_name}/${file_name}
                else
                    echo "Error mkdir -p ${dir_name}"
                    exit 1 
                fi
            done

        done
    done
done

date

exit 0


