#/bin/bash

if [[ $# > 1 ]]; then
    comment=$1
else
    comment=`date +%D_%H`
fi
git add .
git commit -m $comment
git push