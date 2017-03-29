#!/bin/sh
SCRIPT=$(readlink -f $0)
SCRIPTPATH=`dirname $SCRIPT`

. ./build-docker.sh

mkdir -p $SCRIPTPATH/site

docker run -ti --rm \
    -v $SCRIPTPATH/blog:/blog \
    -v $SCRIPTPATH/site:/site \
    jekyll \
    jekyll build -s /blog -d /site

gsutil -m rsync -dr site gs://blog.ebfe.dk
gsutil -m acl ch -R -u AllUsers:R gs://blog.ebfe.dk
gsutil web set -m index.html -e 404.html gs://blog.ebfe.dk
