# create a virtual enviroment
> python -m venv env
# active venv
# on linux :
> source env/bin/activate
#on windows : 
> env/script/activate
# install requirements
> pip install -r requirements.txt
# create database
> python manage.py migrate
#run grpcserver on port 50051
> python manage.py grpcrunserver 127.0.0.1:50051
