"""
A simple app to create a JWT token.
"""
import os
import logging
import datetime
import functools
import jwt

# pylint: disable=import-error
from flask import Flask, jsonify, request, abort


JWT_SECRET = os.environ.get('JWT_SECRET', 'abc123abc1234')
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')


def _logger():
    '''
    Setup logger format, level, and handler.

    RETURNS: log object
    '''
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    log = logging.getLogger(__name__)
    log.setLevel(LOG_LEVEL)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    log.addHandler(stream_handler)
    return log


LOG = _logger()
LOG.debug("Starting with log level: %s" % LOG_LEVEL )
APP = Flask(__name__)

def require_jwt(function):
    """
    Decorator to check valid jwt is present.
    """
    @functools.wraps(function)
    def decorated_function(*args, **kws):
        if not 'Authorization' in request.headers:
            abort(401)
        data = request.headers['Authorization']
        token = str.replace(str(data), 'Bearer ', '')
        try:
            jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        except: # pylint: disable=bare-except
            abort(401)

        return function(*args, **kws)
    return decorated_function


@APP.route('/', methods=['POST', 'GET'])
def health():
    return jsonify("Healthy")


@APP.route('/auth', methods=['POST'])
def auth():
    """
    Create JWT token based on email.
    """
    request_data = request.get_json()
    email = request_data.get('email')
    password = request_data.get('password')
    if not email:
        LOG.error("No email provided")
        return jsonify({"message": "Missing parameter: email"}, 400)
    if not password:
        LOG.error("No password provided")
        return jsonify({"message": "Missing parameter: password"}, 400)
    body = {'email': email, 'password': password}

    user_data = body

    return jsonify(token=_get_jwt(user_data).decode('utf-8'))


@APP.route('/contents', methods=['GET'])
def decode_jwt():
    """
    Check user token and return non-secret data
    """
    if not 'Authorization' in request.headers:
        abort(401)
    data = request.headers['Authorization']
    token = str.replace(str(data), 'Bearer ', '')
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except: # pylint: disable=bare-except
        abort(401)


    response = {'email': data['email'],
                'exp': data['exp'],
                'nbf': data['nbf'] }
    return jsonify(**response)


def _get_jwt(user_data):
    exp_time = datetime.datetime.utcnow() + datetime.timedelta(weeks=2)
    payload = {'exp': exp_time,
               'nbf': datetime.datetime.utcnow(),
               'email': user_data['email']}
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

if __name__ == '__main__':
    APP.run(host='127.0.0.1', port=8080, debug=True)

# Run flask app in Git!!!!!!!!!!!!!!!!!!!!!!!
# export JWT_SECRET='myjwtsecret'
# export LOG_LEVEL=DEBUG
# python main.py
# export TOKEN=`curl -d '{"email":"philipp.steinert@rwth-aachen.de","password":"password"}' -H "Content-Type: application/json" -X POST localhost:8080/auth  | jq -r '.token'`
# echo $TOKEN
# curl --request GET 'http://127.0.0.1:8080/contents' -H "Authorization: Bearer ${TOKEN}" | jq .

# conda create --name flask_kubernetes_env --file requirements.txt
# conda create -n flask_kubernetes_env
# pip install -r requirements.txt
# choco install eksctl --version 0.21.0 --allow-downgrade
# python main.py
# Set up env_file!!!!!!!!!!!!!!!!!!!!!!!
# JWT_SECRET='myjwtsecret'
# LOG_LEVEL=DEBUG
# Build and run docker!!!!!!!!!!!!!!!!!!!!!!!
# docker build --tag jwt-api-test .
# docker run --env-file env_file -p 8080:8080 <image_id>
# docker container ls
# docker stop <container_id>
# docker image rm -f <image_name>
# Check out /auth endpoint in Git!!!!!!!!!!!!!!!!!!!!!!!
# export TOKEN=`curl -d '{"email":"philipp.steinert@rwth-aachen.de","password":"password"}' -H "Content-Type: application/json" -X POST localhost:8080/auth  | jq -r '.token'`
# curl --request GET 'http://127.0.0.1:8080/contents' -H "Authorization: Bearer ${TOKEN}" | jq .
# Create EKS cluster and IAM role in Git!!!!!!!!!!!!!!!!!!!!!!!
# 1) eksctl create cluster --name simple-jwt-api
# 2) kubectl get nodes
# 3) aws sts get-caller-identity --query Account --output text
# 4) TRUST="{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"AWS\": \"arn:aws:iam::474082499116:root\" }, \"Action\": \"sts:AssumeRole\" } ] }"
# 5) aws iam create-role --role-name UdacityFlaskDeployCBKubectlRole --assume-role-policy-document file://trust.json --output text --query 'Role.Arn'
# 6) aws iam put-role-policy --role-name UdacityFlaskDeployCBKubectlRole --policy-name eks-describe --policy-document file://iam-role-policy.json
# 
# aws ssm put-parameter --name JWT_SECRET --value "myjwtsecret" --type SecureString
# https://EBF72A37A0D9DBB8B9458A94414F2238.gr7.us-west-2.eks.amazonaws.com
# export TOKEN=`curl -d '{"email":"<EMAIL>","password":"<PASSWORD>"}' -H "Content-Type: application/json" -X POST https://EBF72A37A0D9DBB8B9458A94414F2238.gr7.us-west-2.eks.amazonaws.com/auth  | jq -r '.token'`
# curl --request GET 'https://oidc.eks.us-west-2.amazonaws.com/id/EBF72A37A0D9DBB8B9458A94414F2238/contents' -H "Authorization: Bearer ${TOKEN}" | jq 
# code . --new-window.


# 3) ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
# 4) TRUST="{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\",  \"Principal\": { \"AWS\": \"arn:aws:iam::${ACCOUNT_ID}:root\" }, \"Action\":  \"sts:AssumeRole\" } ] }"
# 5) aws iam create-role --role-name UdacityFlaskDeployCBKubectlRole --assume-role-policy-document "$TRUST" --output text --query 'Role.Arn'
# 6) echo '{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Action": [ "eks:Describe*", "ssm:GetParameters" ], "Resource": "*" } ] }' > ./iam-role-policy
# aws iam put-role-policy --role-name UdacityFlaskDeployCBKubectlRole --policy-name eks-describe --policy-document file://./iam-role-policy
# kubectl get -n kube-system configmap/aws-auth -o yaml > ./aws-auth-patch.yml


# curl -o aws-auth-cm.yaml https://amazon-eks.s3.us-west-2.amazonaws.com/cloudformation/2020-03-23/aws-auth-cm.yaml
# kubectl patch configmap/aws-auth -n kube-system --patch "$(cat ./aws-auth-patch.yml)"
# kubectl apply -f ./aws-auth-patch.yml
# cat ./aws-auth-patch.yml
# kubectl patch configmap/aws-auth -n kube-system --patch "$(cat ./aws-auth-patch.yml)"
# kubectl patch configmap/aws-auth -n kube-system --patch "$(type ./aws-auth-patch.yml)"
# kubectl patch configmap/aws-auth -n kube-system --patch "$(cat ./aws-auth-patch.yml)"
# aws configure list
# kubectl config get-clusters
# kubectl get nodes
# eksctl utils write-kubeconfig --cluster=simple-jwt-api
# eksctl delete cluster simple-jwt-api

# Get AWS account ID!!!!!!!!!!!!!!!!!!!!!!!
# aws sts get-caller-identity

# git clone https://github.com/PhilippSteinert/FSND-Deploy-Flask-App-to-Kubernetes-Using-EKS

# Latest attempt:
# docker run --env-file=.env_file -p 80:8080 jwt-api-test
# eksctl create cluster --name simple-jwt-api
# kubectl get nodes
# aws sts get-caller-identity --query Account --output text
# 474082499116
# ...
# Grant the role access to the cluster:
# kubectl get -n kube-system configmap/aws-auth -o yaml > ./aws-auth-patch.yml
# In Git Bash!:
# kubectl patch configmap/aws-auth -n kube-system --patch "$(cat ./aws-auth-patch.yml)"
# Token for CodePipeline:
# 9da404239dd499bbca7bce36b9122c9e3764083e
# aws ssm put-parameter --name JWT_SECRET --value "myjwtsecret" --type SecureString
# aws ssm get-parameter --name JWT_SECRET
# aws ssm delete-parameter --name JWT_SECRET
# git add .
# git commit -m "initial commit"
# git push heroku master
