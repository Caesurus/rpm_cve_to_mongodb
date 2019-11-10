# rpm_cve_to_mongodb

## Requirements
1) Download latest rpm_cve list from 'https://www.redhat.com/security/data/metrics/rpm-to-cve.xml'
2) Process the list and insert into mongodb instance of your choice
3) Information should be upserted so that data in mongo is updated when run an no duplicates occur

## Run
`./rpm_cve_to_mongo.py -s "mongodb://localhost" -u username -p password`

## Mongo DB
Given the right permissions, the script will create a `RPMINFO` DB, with a `rpm2cve` collection.

At the time of writing
```
use RPMINFO
db.getCollection('rpm2cve').find({}).count()
```
returns `30467` documents


## Installing

```
git clone git@github.com:Caesurus/rpm_cve_to_mongodb.git
mkvirtualenv --python=`which python3` rpm_cve
workon rpm_cve
pip install -r requirements.txt
./rpm_cve_to_mongo.py -s "mongodb://localhost" -u username -p password
```