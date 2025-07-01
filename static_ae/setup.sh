wget https://zenodo.org/records/15784901/files/target_APK.tar.gz
tar xvf target_APK.tar.gz 
wget https://zenodo.org/records/15784901/files/zenodo.tar
tar xvf zenodo.tar
cp ../Dockerfile_static_ae ./Dockerfile
cp ../run_rq1.sh ./run_rq1.sh
