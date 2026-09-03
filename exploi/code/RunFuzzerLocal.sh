for i in `cat list`
do
python FuzzerLocal.py $i A
done
